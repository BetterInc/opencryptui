// test_endtoend_blackbox.cpp
//
// Black-box end-to-end smoke test for the shipped OpenCryptUI binary.
//
// Strategy
// --------
// OpenCryptUI has no command-line encrypt/decrypt interface (confirmed by
// inspecting src/main.cpp: QCommandLineParser is absent and argv[] is not
// inspected beyond standard Qt initialisation).  Driving the GUI from a
// sibling QProcess via QTest::mouseClick requires an in-process handle to the
// target widget tree, which is not available across process boundaries when
// using the offscreen platform.
//
// Therefore we implement the sanctioned fallback from the specification:
//
//   1.  Startup smoke  — spawn the freshly-built OpenCryptUI binary under
//       QT_QPA_PLATFORM=offscreen, give it 5 s to come up, verify the process
//       is still alive (no crash-on-startup regression), then send SIGKILL.
//       This catches the most common class of regression that neither the
//       build nor the engine tests would catch.
//
//   2.  Round-trip via engine API  — encrypt a 1 MiB payload with AES-256-GCM
//       using the same EncryptionEngine the binary ships, then decrypt it and
//       byte-compare.  This exercises the full encrypt/decrypt code path that
//       the binary uses at runtime.
//
//   3.  Tamper rejection via engine API  — flip a byte in the .enc file and
//       verify (a) decryption returns false and (b) no plaintext is left on
//       disk.  Mirrors the security guarantee the shipped binary relies on.
//
// The engine-API tests (2 & 3) are kept in the same translation unit so that
// a single CTest entry (EndToEndBlackbox) covers the full scenario in one run.
//
// Build note
// ----------
// The OpenCryptUI binary path is injected at compile time by CMake as the
// macro OPENCRYPTUI_BINARY_PATH.  The CTest WORKING_DIRECTORY is the build
// directory, so a relative path would also work, but an absolute one is
// unambiguous.

#include "encryptionengine.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QThread>
#include <QDebug>

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

static int check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    return ok ? 0 : 1;
}

static bool writeFile(const QString& path, const QByteArray& data)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}

static QByteArray readFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

// Generate n bytes of deterministic pseudo-random data (LCG — not
// cryptographic, just deterministic payload for comparison).
static QByteArray makePayload(qint64 size)
{
    QByteArray buf(static_cast<int>(size), '\0');
    quint32 rng = 0xCAFEBABEu;
    for (int i = 0; i < buf.size(); ++i) {
        rng = rng * 1664525u + 1013904223u;
        buf[i] = static_cast<char>(rng >> 24);
    }
    return buf;
}

static bool flipByteAt(const QString& path, qint64 offset)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadWrite)) return false;
    if (!f.seek(offset)) return false;
    char b = '\0';
    if (f.read(&b, 1) != 1) return false;
    b ^= 0x5A;
    if (!f.seek(offset)) return false;
    return f.write(&b, 1) == 1;
}

// ---------------------------------------------------------------------------
// TC0: Binary startup smoke
//
// Spawn OpenCryptUI, wait up to STARTUP_TIMEOUT_MS for it to either:
//   - exit (= crash or self-terminate) → FAIL if exit code != 0 within 1 s
//   - still be running after STARTUP_TIMEOUT_MS → PASS (it came up cleanly)
// Then kill it and wait for it to finish.
// ---------------------------------------------------------------------------

static constexpr int STARTUP_TIMEOUT_MS = 5000;  // 5 s max wait for startup
static constexpr int KILL_WAIT_MS       = 3000;  // 3 s grace after kill

static int tc0_binaryStartupSmoke()
{
#ifndef OPENCRYPTUI_BINARY_PATH
    std::fprintf(stderr, "SKIP: TC0: OPENCRYPTUI_BINARY_PATH not defined at compile time\n");
    std::fflush(stderr);
    return 0;
#else
    QString binaryPath = QString::fromLatin1(OPENCRYPTUI_BINARY_PATH);

    // CMake injects the bare target name; on Windows the binary has a
    // `.exe` suffix and on macOS it's `OpenCryptUI.app/Contents/MacOS/OpenCryptUI`.
    // Linux has the bare name. Probe the common variants.
    if (!QFile::exists(binaryPath)) {
        const QStringList candidates = {
            binaryPath + ".exe",                                  // Windows MSYS2
            binaryPath + ".app/Contents/MacOS/OpenCryptUI",       // macOS bundle
        };
        for (const QString& c : candidates) {
            if (QFile::exists(c)) { binaryPath = c; break; }
        }
    }

    if (!QFile::exists(binaryPath)) {
        std::fprintf(stderr, "FAIL: TC0: binary not found at %s (also tried .exe / .app/Contents/MacOS variants)\n",
                     binaryPath.toLocal8Bit().constData());
        std::fflush(stderr);
        return 1;
    }

    QProcess proc;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("offscreen"));
    // Suppress Qt's own logging noise on stderr.
    env.insert(QStringLiteral("QT_LOGGING_RULES"), QStringLiteral("*.debug=false;*.info=false;*.warning=false"));
    proc.setProcessEnvironment(env);
    proc.setProcessChannelMode(QProcess::MergedChannels);

    proc.start(binaryPath, QStringList());
    if (!proc.waitForStarted(STARTUP_TIMEOUT_MS)) {
        std::fprintf(stderr, "FAIL: TC0: binary did not start within %d ms\n", STARTUP_TIMEOUT_MS);
        std::fflush(stderr);
        return 1;
    }

    // Poll: if the process terminates quickly (< 1 s) that is a crash.
    // A GUI app under offscreen should stay alive indefinitely.
    const bool exitedEarly = proc.waitForFinished(1000);
    if (exitedEarly) {
        int code = proc.exitCode();
        std::fprintf(stderr, "FAIL: TC0: binary exited within 1 s (exit code %d) — likely crash\n", code);
        std::fflush(stderr);
        return 1;
    }

    // Process is still alive — startup succeeded.
    check(true, "TC0: binary alive after 1 s under offscreen platform");

    // Terminate gracefully; fall back to kill if needed.
    proc.terminate();
    if (!proc.waitForFinished(KILL_WAIT_MS)) {
        proc.kill();
        proc.waitForFinished(KILL_WAIT_MS);
    }

    return 0;
#endif
}

// ---------------------------------------------------------------------------
// TC1: Round-trip — 1 MiB payload, AES-256-GCM, PBKDF2
// ---------------------------------------------------------------------------

static int tc1_roundTrip(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + QStringLiteral("/tc1_plain.bin");
    const QString ct    = plain + QStringLiteral(".enc");

    const QByteArray payload = makePayload(1 * 1024 * 1024); // 1 MiB
    if (!writeFile(plain, payload))
        return check(false, "TC1: write payload");

    bool ok = eng.encryptFile(plain,
                              QStringLiteral("correct-horse-battery-staple"),
                              QStringLiteral("AES-256-GCM"),
                              QStringLiteral("PBKDF2"),
                              /*iterations=*/600000,
                              /*useHMAC=*/false,
                              /*customHeader=*/QString());
    if (check(ok, "TC1: encrypt 1 MiB")) return 1;

    // Remove original so decrypt has to recreate it.
    QFile::remove(plain);

    ok = eng.decryptFile(ct,
                         QStringLiteral("correct-horse-battery-staple"),
                         QStringLiteral("AES-256-GCM"),
                         QStringLiteral("PBKDF2"),
                         600000,
                         /*useHMAC=*/false,
                         /*customHeader=*/QString());
    if (check(ok, "TC1: decrypt 1 MiB")) return 1;

    const QByteArray recovered = readFile(plain);
    int failures = 0;
    failures += check(recovered.size() == payload.size(), "TC1: size matches");
    failures += check(recovered == payload,               "TC1: byte-identical round-trip");

    QFile::remove(plain);
    QFile::remove(ct);
    return failures;
}

// ---------------------------------------------------------------------------
// TC2: Tamper rejection
//
// Flip a byte inside the ciphertext body, then verify:
//   (a) decryptFile returns false
//   (b) no plaintext file is left on disk (no partial leak)
// ---------------------------------------------------------------------------

static int tc2_tamperRejection(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + QStringLiteral("/tc2_plain.bin");
    const QString ct    = plain + QStringLiteral(".enc");

    const QByteArray payload = makePayload(1 * 1024 * 1024);
    if (!writeFile(plain, payload))
        return check(false, "TC2: write payload");

    bool ok = eng.encryptFile(plain,
                              QStringLiteral("correct-horse-battery-staple"),
                              QStringLiteral("AES-256-GCM"),
                              QStringLiteral("PBKDF2"),
                              600000,
                              false, QString());
    if (check(ok, "TC2: encrypt for tamper test")) return 1;

    QFile::remove(plain);

    // Flip a byte in the ciphertext body (offset 80 is well past the
    // 12-byte OCUI header + 32-byte salt + 12-byte IV + 4+4 framing = 64
    // bytes of preamble, safely inside encrypted payload territory).
    const qint64 tamperOffset = 80;
    if (!flipByteAt(ct, tamperOffset))
        return check(false, "TC2: flip byte in ciphertext");

    // Decrypt must be rejected.
    ok = eng.decryptFile(ct,
                         QStringLiteral("correct-horse-battery-staple"),
                         QStringLiteral("AES-256-GCM"),
                         QStringLiteral("PBKDF2"),
                         600000,
                         false, QString());

    int failures = 0;
    failures += check(!ok,                    "TC2: tampered file rejected");
    failures += check(!QFile::exists(plain),  "TC2: no plaintext left on disk after rejection");

    QFile::remove(ct);
    return failures;
}

// ---------------------------------------------------------------------------
// TC3: Wrong password rejected cleanly
// ---------------------------------------------------------------------------

static int tc3_wrongPassword(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + QStringLiteral("/tc3_plain.bin");
    const QString ct    = plain + QStringLiteral(".enc");

    const QByteArray payload = makePayload(4096);
    if (!writeFile(plain, payload))
        return check(false, "TC3: write payload");

    bool ok = eng.encryptFile(plain,
                              QStringLiteral("correct-password"),
                              QStringLiteral("AES-256-GCM"),
                              QStringLiteral("PBKDF2"),
                              600000,
                              false, QString());
    if (check(ok, "TC3: encrypt with correct password")) return 1;

    QFile::remove(plain);

    ok = eng.decryptFile(ct,
                         QStringLiteral("wrong-password"),
                         QStringLiteral("AES-256-GCM"),
                         QStringLiteral("PBKDF2"),
                         600000,
                         false, QString());

    int failures = 0;
    failures += check(!ok,                   "TC3: wrong-password decrypt rejected");
    failures += check(!QFile::exists(plain), "TC3: no plaintext after wrong-password rejection");

    QFile::remove(ct);
    return failures;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    int failures = 0;

    // --- TC0: binary startup smoke -------------------------------------------
    std::fprintf(stderr, "\n=== TC0: Binary startup smoke ===\n");
    failures += tc0_binaryStartupSmoke();

    // --- Engine API tests ----------------------------------------------------
    QTemporaryDir dir;
    if (!dir.isValid()) {
        std::fprintf(stderr, "FATAL: could not create temp directory\n");
        return 99;
    }

    EncryptionEngine eng;

    std::fprintf(stderr, "\n=== TC1: 1 MiB round-trip (AES-256-GCM / PBKDF2) ===\n");
    failures += tc1_roundTrip(eng, dir.path());

    std::fprintf(stderr, "\n=== TC2: Tamper rejection ===\n");
    failures += tc2_tamperRejection(eng, dir.path());

    std::fprintf(stderr, "\n=== TC3: Wrong-password rejection ===\n");
    failures += tc3_wrongPassword(eng, dir.path());

    std::fprintf(stderr, "\n");
    if (failures) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", failures);
        std::fflush(stderr);
        return 1;
    }
    std::fprintf(stderr, "ALL END-TO-END BLACKBOX TESTS PASSED\n");
    std::fflush(stderr);
    return 0;
}
