// fuzz_signature_verifier.cpp
//
// libFuzzer harness for EncryptionEngine::verifySignature (private method,
// reached via the full decryptFile path).
//
// Strategy: prepend a syntactically valid OCUI v2 header + salt + IV to the
// fuzz input, so the header parse always succeeds and execution reaches the
// signature-verification code path.  The fuzz engine controls the bytes that
// follow the IV — i.e. the ciphertext region and the signature trailer.
//
// The signature trailer layout (from encryptionengine_tamperevidence.cpp):
//   [sig N bytes][magic "SIG_" 4][sigLen 4][CRC32 4]
//
// The verifier reads the 12-byte fixed trailer first, then seeks backward to
// read sig bytes, then re-derives the Ed25519 keypair from the fixed signing
// seed, then SHA-512-hashes everything before the trailer, then calls
// crypto_sign_verify_detached.
//
// The harness also exercises the CRC32 check path, the length-overflow guard
// (signatureLength > 10*1024 check), and the public-key mismatch path.
//
// Temp-file strategy: single reused path per process.

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

// ---------------------------------------------------------------------------
// Fixed OCUI v2 header constants (must match encryptionengine.h values).
// We use v2 (non-AEAD) so the decryption path goes through the bulk
// ciphertext + signature verifier code, not the v3 chunk path.
// ---------------------------------------------------------------------------
static constexpr quint32 OCUI_MAGIC         = 0x4F435549u; // "OCUI"
static constexpr quint8  OCUI_FMT_V2        = 2;
// AES-256-CBC (id=0x04) — non-AEAD, so v2 path is always taken.
static constexpr quint8  ALG_ID_AES256_CBC  = 0x04;
static constexpr quint8  KDF_ID_PBKDF2      = 0x01;
static constexpr quint32 MIN_PBKDF2_ITERS   = 600000u;

// AES-256-CBC uses a 16-byte IV.
static constexpr int SALT_SIZE = 32;
static constexpr int IV_SIZE   = 16;

// Total fixed prefix written before the fuzz payload:
//   header(12) + salt(32) + iv(16) = 60 bytes
static constexpr int PREFIX_SIZE = 12 + SALT_SIZE + IV_SIZE;

static int           g_argc  = 0;
static char**        g_argv  = nullptr;
static QCoreApplication* g_app = nullptr;
static EncryptionEngine* g_eng = nullptr;
static QString        g_tmpPath;

static void ensureInit()
{
    if (g_app) return;

    if (sodium_init() < 0) {
        fprintf(stderr, "[fuzz_signature_verifier] sodium_init() failed\n");
        abort();
    }

    static char progName[] = "FuzzSignatureVerifier";
    static char* fakeArgv[] = { progName, nullptr };
    g_argc = 1;
    g_argv = fakeArgv;
    g_app  = new QCoreApplication(g_argc, g_argv);
    g_eng  = new EncryptionEngine();

    static QTemporaryDir* s_tmpDir = new QTemporaryDir();
    if (!s_tmpDir->isValid()) {
        fprintf(stderr, "[fuzz_signature_verifier] cannot create temp dir\n");
        abort();
    }
    // Must end in ".enc" for decryptFile to strip the extension.
    g_tmpPath = s_tmpDir->filePath("fuzz_sig.enc");
}

// Build a v2-shaped file: fixed header prefix + fuzz-controlled suffix.
// The suffix is the region that contains the ciphertext and the trailer,
// and is entirely controlled by the fuzzer.
//
// Uses QBuffer so all serialisation happens through one sequential write
// cursor; avoids the WriteOnly/Append open-mode ambiguity that affects
// QDataStream constructed directly on a QByteArray.
static QByteArray buildV2File(const uint8_t* suffix, size_t suffixSize)
{
    QByteArray blob;
    blob.reserve(PREFIX_SIZE + static_cast<int>(suffixSize));

    QBuffer buf(&blob);
    buf.open(QIODevice::WriteOnly);
    QDataStream ds(&buf);
    ds.setByteOrder(QDataStream::BigEndian);

    // 12-byte OCUI v2 header
    ds << OCUI_MAGIC;
    ds << OCUI_FMT_V2;
    ds << ALG_ID_AES256_CBC;
    ds << KDF_ID_PBKDF2;
    ds << quint8(0); // reserved
    ds << MIN_PBKDF2_ITERS;

    // 32-byte salt + 16-byte IV (all zeros).
    // All-zero salt means key derivation is deterministic across iterations,
    // which is fine here — we're stressing the signature verifier path, not
    // KDF correctness.
    for (int i = 0; i < SALT_SIZE + IV_SIZE; ++i) ds << quint8(0);

    // Fuzz-controlled suffix: ciphertext + trailer
    buf.write(reinterpret_cast<const char*>(suffix), static_cast<qint64>(suffixSize));

    buf.close();
    return blob;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ensureInit();

    // Build the file: fixed valid header + fuzz-controlled body/trailer.
    QByteArray blob = buildV2File(data, size);

    {
        QFile f(g_tmpPath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return 0;
        f.write(blob);
    }

    // Call decryptFile with AES-256-CBC.  Execution flow:
    //   1. cryptOperation reads and validates the OCUI v2 header.
    //      → magic OK, version OK, alg OK, kdf OK, iters at floor → proceed
    //   2. Reads salt + IV from the fixed prefix.
    //   3. Derives masterKey via PBKDF2 from "fuzzer-password" + zero-salt.
    //   4. Calls deriveSubkeys to produce encKey + sigKey.
    //   5. Checks enforceIntegrity → opens sigCheckFile for the trailer.
    //      → reads last 12 bytes for magic/sigLen/CRC (fuzz-controlled).
    //      → if magic == "SIG_": validates sigLen bounds, reads sig bytes,
    //        calls verifySignature with the fuzz-controlled body.
    //   6. verifySignature:
    //      a. Reads 12-byte trailer (magic, sigLen, CRC).
    //      b. Reads sigLen bytes of signature.
    //      c. CRC32 check (fuzz-controlled).
    //      d. Splits sig into Ed25519-sig + public key.
    //      e. Re-derives expected public key from sigKey seed.
    //      f. Constant-time public-key comparison.
    //      g. SHA-512 hashes the file body.
    //      h. crypto_sign_verify_detached.
    //   Expected: false (wrong sig or missing trailer).
    (void) g_eng->decryptFile(
        g_tmpPath,
        "fuzzer-password",
        "AES-256-CBC",
        "PBKDF2",
        static_cast<int>(MIN_PBKDF2_ITERS),
        /*useHMAC=*/false,
        /*customHeader=*/QString());

    return 0;
}
