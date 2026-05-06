// fuzz_chunk_decoder.cpp
//
// libFuzzer harness for EncryptionEngine::decryptChunk (v3 per-chunk AEAD).
//
// decryptChunk is a private static method, so we cannot call it directly.
// Instead we drive it through the public decryptFile → cryptOperationV3Decrypt
// → decryptChunk stack with a carefully constructed v3-shaped file blob.
// This exercises the full decode path including chunk-framing (chunk_size,
// chunk_count), per-chunk GCM tag verification, and buildChunkNonce.
//
// Fuzzing strategy: the fuzz input is split as:
//   byte[0]  — control byte (trailer mode + chunk count)
//   byte[1..] — chunk payload bytes (fuzz-controlled ciphertext + tag)
//
// Invariant: never crash; always return empty QByteArray for bad tag/key.

#include "encryptionengine.h"
#include <QBuffer>
#include <QCoreApplication>
#include <QFile>
#include <QDataStream>
#include <QTemporaryDir>
#include <sodium.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int          g_argc    = 0;
static char**       g_argv    = nullptr;
static QCoreApplication* g_app = nullptr;
static EncryptionEngine* g_eng = nullptr;
static QString       g_tmpPath;

// Minimal OCUI v3 file constants (must match encryptionengine.h values).
static constexpr quint32 OCUI_MAGIC         = 0x4F435549u; // "OCUI"
static constexpr quint8  OCUI_FMT_V3        = 3;
static constexpr quint8  ALG_ID_AES256_GCM  = 0x01;
static constexpr quint8  KDF_ID_PBKDF2      = 0x01;
static constexpr quint32 MIN_PBKDF2_ITERS   = 600000u;

// Construct a minimal v3-shaped byte blob that wraps the fuzz-supplied chunk
// payload.  Uses QBuffer for serialisation to avoid QDataStream/QByteArray
// open-mode confusion (WriteOnly seeks to 0; Append seeks to end).
//
// Layout:
//   [magic(4)][ver(1)][algId(1)][kdfId(1)][rsv(1)][iters(4)]  = 12 bytes (header)
//   [salt(32)][base_iv(12)]                                    = 44 bytes
//   [chunk_size(4)][chunk_count(4)]                            = 8 bytes
//   [chunk payload (fuzz-controlled)]
//   [optional SIG_ stub trailer(12)]
//
// Two trailer modes:
//   mode 0: no trailer — engine rejects at "no Ed25519 signature" check.
//   mode 1: stub SIG_ trailer with sigLen=0, CRC32(empty)=0x00000000.
//           Exercises the trailer magic/length/CRC parse path in
//           verifySignature before the Ed25519 body check.
static QByteArray buildV3File(const uint8_t* chunkData, size_t chunkSize,
                               quint32 chunkCount, int mode)
{
    QByteArray blob;
    blob.reserve(12 + 44 + 8 + static_cast<int>(chunkSize) + 12);

    QBuffer buf(&blob);
    buf.open(QIODevice::WriteOnly);
    QDataStream ds(&buf);
    ds.setByteOrder(QDataStream::BigEndian);

    // 12-byte OCUI header
    ds << OCUI_MAGIC;
    ds << OCUI_FMT_V3;
    ds << ALG_ID_AES256_GCM;
    ds << KDF_ID_PBKDF2;
    ds << quint8(0); // reserved
    ds << MIN_PBKDF2_ITERS;

    // 32-byte salt + 12-byte base_iv (all zeros — key derivation will still
    // run with a deterministic result, which is fine for fuzzing purposes)
    for (int i = 0; i < 44; ++i) ds << quint8(0);

    // Chunk framing: chunk_size = 1 MiB, chunk_count = caller-supplied
    ds << quint32(1u << 20); // chunk_size
    ds << chunkCount;

    // Chunk payload bytes (fuzz-controlled)
    buf.write(reinterpret_cast<const char*>(chunkData), static_cast<qint64>(chunkSize));

    if (mode == 1) {
        // Stub "SIG_" trailer: [magic=0x5349475F][sigLen=0][CRC32(empty)=0]
        // CRC32 of an empty buffer: initial crc = 0xFFFFFFFF, no loop iterations,
        // return ~0xFFFFFFFF = 0x00000000.
        ds << quint32(0x5349475Fu); // "SIG_"
        ds << quint32(0u);          // sigLen = 0
        ds << quint32(0x00000000u); // CRC32(empty) = 0
    }

    buf.close();
    return blob;
}

static void ensureInit()
{
    if (g_app) return;

    if (sodium_init() < 0) {
        fprintf(stderr, "[fuzz_chunk_decoder] sodium_init() failed\n");
        abort();
    }

    static char progName[] = "FuzzChunkDecoder";
    static char* fakeArgv[] = { progName, nullptr };
    g_argc = 1;
    g_argv = fakeArgv;
    g_app  = new QCoreApplication(g_argc, g_argv);
    g_eng  = new EncryptionEngine();

    static QTemporaryDir* s_tmpDir = new QTemporaryDir();
    if (!s_tmpDir->isValid()) {
        fprintf(stderr, "[fuzz_chunk_decoder] cannot create temp dir\n");
        abort();
    }
    g_tmpPath = s_tmpDir->filePath("fuzz_chunk.enc");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ensureInit();

    // Need at least one byte to produce a non-trivial test.
    if (size == 0) return 0;

    // Extract a 1-byte control header so the fuzzer can control:
    //   bit 0: trailer mode (0 = none, 1 = stub SIG_)
    //   bits 1-2: chunkCount hint (0..3 → 1..4 chunks; we clamp to avoid huge loops)
    const uint8_t ctrl       = data[0];
    const int     trailerMode = (ctrl & 0x01);
    const quint32 chunkCount  = static_cast<quint32>((ctrl >> 1 & 0x03) + 1);

    const uint8_t* chunkData = data + 1;
    const size_t   chunkSize = size - 1;

    // Build the fake v3 blob and drive decryptFile.
    QByteArray blob = buildV3File(chunkData, chunkSize, chunkCount, trailerMode);

    {
        QFile f(g_tmpPath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return 0;
        f.write(blob);
    }

    // Use AES-256-GCM (v3 AEAD requirement).  decryptFile will:
    //   1. Parse the OCUI header (magic, version, alg/kdf cross-check).
    //   2. Read salt + base_iv.
    //   3. Derive keys (PBKDF2 with MIN_PBKDF2_ITERS — slow but correct).
    //   4. Call cryptOperationV3Decrypt, which:
    //      a. Opens a second fd and looks for the SIG_ trailer.
    //      b. Reads chunk_size and chunk_count from the framing header.
    //      c. For each chunk, calls decryptChunk with the derived key + nonce.
    //   Expected result: false (wrong key, bad tag, bad/missing sig).
    (void) g_eng->decryptFile(
        g_tmpPath,
        "fuzzer-password",
        "AES-256-GCM",
        "PBKDF2",
        static_cast<int>(MIN_PBKDF2_ITERS),
        /*useHMAC=*/false,
        /*customHeader=*/QString());

    return 0;
}
