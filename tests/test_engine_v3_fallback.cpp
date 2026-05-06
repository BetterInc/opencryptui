// Cross-version round-trip test.
//
// The production encrypt path defaults to v4 (deniable) for AEAD ciphers,
// but old encrypted files in the wild are still v3 (chunked AEAD with a
// plaintext OCUI header). The decrypt path tries v4 first and falls back
// to v3 → v2 if outer AEAD fails. We need to assert the fallback works.
//
// To produce a v3 file, we use the TEST-ONLY env var OCUI_TEST_FORCE_V3=1
// recognised by the encrypt path. The variable is cleared before decrypt
// so the engine takes the normal v4-first path and falls back to v3.
//
// This test catches the kind of regression where someone "simplifies" the
// decrypt dispatch and accidentally drops the v3 case — silently bricking
// every researcher's existing encrypted archive.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QByteArray>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int s_failures = 0;
static int check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
    return ok ? 0 : 1;
}

static QByteArray makePayload(qint64 size)
{
    QByteArray b(size, 0);
    quint32 rng = 0xBADCAFEu;
    for (qint64 i = 0; i < size; ++i) {
        rng = rng * 1664525u + 1013904223u;
        b[int(i)] = char(rng >> 24);
    }
    return b;
}

static bool writeFile(const QString& p, const QByteArray& d)
{
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(d) == d.size();
}

static QByteArray readAll(const QString& p)
{
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    const QByteArray payload = makePayload(2 * 1024 * 1024); // 2 MiB → multiple chunks
    const QString plain = dir.filePath("p.bin");
    const QString ct    = plain + ".enc";
    const QString pwd   = "cross-version-test-pwd";

    writeFile(plain, payload);

    // ---- Step 1: produce a v3 file via the test-only env-var hook ----
    qputenv("OCUI_TEST_FORCE_V3", "1");
    bool ok = eng.encryptFile(plain, pwd, "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    qunsetenv("OCUI_TEST_FORCE_V3");
    check(ok, "v3 encrypt (forced via OCUI_TEST_FORCE_V3)");

    // ---- Step 2: confirm we actually got a v3 file (plaintext OCUI magic) ----
    {
        QByteArray head = readAll(ct).left(4);
        bool isV3 = head.size() == 4 && std::memcmp(head.constData(), "OCUI", 4) == 0;
        check(isV3,
              "v3 file has plaintext 'OCUI' magic at offset 0 (this confirms the env-var hook works)");
    }

    // ---- Step 3: decrypt with the production path (v4-first, falls back) ----
    QFile::remove(plain);
    ok = eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    check(ok,
          "production decrypt (v4-first → falls back to v3) succeeds on the v3 file");

    QByteArray got = readAll(plain);
    check(got == payload, "v3 fallback round-trip is byte-identical");

    // ---- Step 4: tampered v3 file is rejected (not silently accepted) ----
    {
        QFile::remove(plain);
        QFile f(ct);
        if (f.open(QIODevice::ReadWrite)) {
            qint64 mid = f.size() / 2;
            f.seek(mid);
            char b; f.read(&b, 1); b ^= 0x80;
            f.seek(mid); f.write(&b, 1);
            f.close();
        }
        bool tamperOk = eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                                        false, QString());
        check(!tamperOk, "tampered v3 file rejected (no silent accept on fallback path)");
        check(!QFile::exists(plain),
              "no plaintext on disk after tampered-v3 rejection");
    }

    // ---- Step 5: confirm the env-var hook leaves no residue ----
    // Re-encrypt the original payload WITHOUT the env var; result must be v4.
    {
        const QString p2 = dir.filePath("p2.bin");
        const QString c2 = p2 + ".enc";
        writeFile(p2, payload);
        ok = eng.encryptFile(p2, pwd, "AES-256-GCM", "PBKDF2", 600000,
                             false, QString());
        check(ok, "default encrypt (no env var) succeeds");

        QByteArray h2 = readAll(c2).left(4);
        bool notV3 = h2.size() == 4 &&
                     std::memcmp(h2.constData(), "OCUI", 4) != 0;
        check(notV3,
              "default encrypt produces v4 (no plaintext OCUI) — env var did not leak");
    }

    if (s_failures) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures);
        return 1;
    }
    std::fprintf(stderr, "ALL V3 FALLBACK TESTS PASSED\n");
    return 0;
}
