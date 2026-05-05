// fuzz_ocui_header.cpp
//
// libFuzzer harness for the OCUI v2/v3 header parser and full decryptFile path.
//
// Strategy: treat the entire fuzz input as the content of an encrypted file
// (ending in ".enc"), write it to a persistent temp path, and call
// EncryptionEngine::decryptFile.  We pass a fixed algorithm/KDF/password so
// the early-exit code paths in cryptOperation are reachable; the OCUI magic
// check, version check, algorithm-id and KDF-id cross-validation, iteration
// floor, salt/IV read, and signature verifier will all be exercised on every
// mutation the fuzzer generates.
//
// Invariant: decryptFile MUST NOT crash regardless of input.  Return value
// (true/false) is not checked — garbage input is expected to fail; what we
// forbid is a crash, assertion, or sanitizer finding.
//
// Temp-file strategy: reuse a single path per process to avoid creating and
// unlinking 100k+ files per second, which would dominate wall-clock time.

#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <sodium.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// ---------------------------------------------------------------------------
// Global state — initialised once, reused across all LLVMFuzzerTestOneInput
// invocations within the same process (fuzzer runs many iterations in one
// process lifetime).
// ---------------------------------------------------------------------------

static int          g_argc      = 0;
static char**       g_argv      = nullptr;
static QCoreApplication* g_app  = nullptr;
static EncryptionEngine* g_eng  = nullptr;
static QString       g_tmpPath;   // persistent .enc file path

// The harness tries each combination of (algorithm, kdf) so the parser for
// every supported algorithm ID and KDF ID is reachable.  We keep KDF
// iterations at minimum to avoid spending time in real KDF computation when
// the header is rejected before key derivation even starts.  When the fuzz
// input presents a plausible header, key derivation will run; we use 600000
// (the PBKDF2 floor) to stay valid while keeping PBKDF2 fast relative to
// Argon2.
struct AlgoKdf { const char* algo; const char* kdf; int iters; };
static const AlgoKdf g_combos[] = {
    { "AES-256-GCM",         "PBKDF2",  600000 },
    { "AES-256-CBC",         "PBKDF2",  600000 },
    { "ChaCha20-Poly1305",   "PBKDF2",  600000 },
    { "AES-128-GCM",         "PBKDF2",  600000 },
};
static constexpr int g_nCombos = static_cast<int>(sizeof(g_combos) / sizeof(g_combos[0]));

static void ensureInit()
{
    if (g_app) return; // already done

    // libsodium must be initialised before any sodium_* call.
    if (sodium_init() < 0) {
        fprintf(stderr, "[fuzz_ocui_header] sodium_init() failed\n");
        abort();
    }

    // QCoreApplication is needed by QFile, QDir, and the engine internals.
    // Build a fake argc/argv to satisfy the constructor.
    static char progName[] = "FuzzOCUIHeader";
    static char* fakeArgv[] = { progName, nullptr };
    g_argc = 1;
    g_argv = fakeArgv;
    g_app  = new QCoreApplication(g_argc, g_argv);

    g_eng = new EncryptionEngine();

    // Create a temporary directory that lives for the entire process lifetime,
    // then derive a fixed file path within it.  We never remove the directory
    // on purpose; the OS cleans up temp dirs on process exit.
    // We write to a static location so we avoid open/close/unlink churn.
    static QTemporaryDir* s_tmpDir = new QTemporaryDir();
    if (!s_tmpDir->isValid()) {
        fprintf(stderr, "[fuzz_ocui_header] cannot create temp dir\n");
        abort();
    }
    g_tmpPath = s_tmpDir->filePath("fuzz_input.enc");
}

// ---------------------------------------------------------------------------
// LLVMFuzzerTestOneInput — called by the fuzzer for every generated input.
// ---------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ensureInit();

    // Write the fuzz bytes verbatim to the temp file.  The engine treats the
    // file content as a potential OCUI-encrypted blob.
    {
        QFile f(g_tmpPath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return 0;
        f.write(reinterpret_cast<const char*>(data), static_cast<qint64>(size));
        // f closes on scope exit
    }

    // Drive each (algorithm, kdf) combination.  Most calls will exit in the
    // header-validation fast path (wrong magic, wrong version, wrong alg/kdf
    // id), which is exactly the parser surface we want to stress.  Calls that
    // accidentally match the stored header bytes will proceed to key derivation
    // and signature verification, stressing deeper paths.
    for (int i = 0; i < g_nCombos; ++i) {
        const AlgoKdf& c = g_combos[i];
        // decryptFile returns false for malformed input — that is expected and
        // not an error.  What we must not see is a crash or sanitizer finding.
        (void) g_eng->decryptFile(
            g_tmpPath,
            "fuzzer-password",
            QString::fromLatin1(c.algo),
            QString::fromLatin1(c.kdf),
            c.iters,
            /*useHMAC=*/false,
            /*customHeader=*/QString());
    }

    return 0;
}
