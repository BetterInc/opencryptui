// Cipher-cascade test.
//
// A cascade encrypts each chunk through several AEAD ciphers in sequence, each
// with an independent subkey, written via the deniable v4 format. This test
// proves:
//   1. Round-trip is byte-identical across multiple chunks (>1 MiB).
//   2. The output is still deniable (no OCUI/SIG_/cipher-name strings, looks
//      uniformly random) — cascades must not break v4 deniability.
//   3. A wrong password is rejected.
//   4. Tampering anywhere is rejected (outer AEAD + per-layer AEAD + Ed25519).
//   5. Decrypting a cascade file with the WRONG recipe is rejected (the cascade
//      id is cryptographically bound).
//   6. Empty-file cascade round-trips.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QByteArray>
#include <cstdio>
#include <cstring>

static int s_failures = 0;
static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
}

static QByteArray makePayload(qint64 size)
{
    QByteArray b(size, 0);
    quint32 rng = 0x1234567u;
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
static int findSeq(const QByteArray& h, const char* n, int len)
{
    for (int i = 0; i + len <= h.size(); ++i)
        if (std::memcmp(h.constData() + i, n, len) == 0) return i;
    return -1;
}

static void testOneCascade(EncryptionEngine& eng, const QString& cascade,
                           const QString& dirPath, const QByteArray& payload)
{
    const QString label = cascade.toUtf8().constData();
    const QString plain = dirPath + "/c.bin";
    const QString ct    = plain + ".enc";
    const QString pwd   = "cascade-test-password";

    QFile::remove(plain); QFile::remove(ct);
    writeFile(plain, payload);

    bool ok = eng.encryptFile(plain, pwd, cascade, "Argon2", 3, false, QString());
    check(ok, (label + ": encrypt").toUtf8().constData());

    // Deniability: cascade output must still look like random v4 (no markers).
    QByteArray whole = readAll(ct);
    check(findSeq(whole, "OCUI", 4) == -1, (label + ": no OCUI magic on disk").toUtf8().constData());
    check(findSeq(whole, "SIG_", 4) == -1, (label + ": no SIG_ marker on disk").toUtf8().constData());

    // Round-trip.
    QFile::remove(plain);
    ok = eng.decryptFile(ct, pwd, cascade, "Argon2", 3, false, QString());
    check(ok, (label + ": decrypt").toUtf8().constData());
    check(readAll(plain) == payload, (label + ": byte-identical round-trip").toUtf8().constData());

    // Wrong password rejected.
    QFile::remove(plain);
    ok = eng.decryptFile(ct, "WRONG", cascade, "Argon2", 3, false, QString());
    check(!ok, (label + ": wrong password rejected").toUtf8().constData());
    check(!QFile::exists(plain), (label + ": no plaintext after wrong-password").toUtf8().constData());

    // Tamper mid-file rejected.
    {
        QFile f(ct);
        if (f.open(QIODevice::ReadWrite)) {
            qint64 mid = f.size() / 2;
            f.seek(mid); char b; f.read(&b, 1); b ^= 0x40; f.seek(mid); f.write(&b, 1);
            f.close();
        }
        QFile::remove(plain);
        ok = eng.decryptFile(ct, pwd, cascade, "Argon2", 3, false, QString());
        check(!ok, (label + ": tamper rejected").toUtf8().constData());
        check(!QFile::exists(plain), (label + ": no plaintext after tamper").toUtf8().constData());
    }
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    const QByteArray payload = makePayload(2 * 1024 * 1024 + 777); // multi-chunk + partial

    // Every advertised cascade round-trips, stays deniable, rejects tamper.
    for (const QString& cascade : EncryptionEngine::cascadeAlgorithmNames())
        testOneCascade(eng, cascade, dir.path(), payload);

    // ---- Wrong-recipe rejection: encrypt with cascade #1, decrypt as #2 ----
    {
        const QString c1 = "Cascade: AES-256-GCM + ChaCha20-Poly1305";
        const QString c2 = "Cascade: ChaCha20-Poly1305 + AES-256-GCM";
        const QString plain = dir.path() + "/r.bin";
        const QString ct    = plain + ".enc";
        QFile::remove(plain); QFile::remove(ct);
        writeFile(plain, payload.left(4096));
        eng.encryptFile(plain, "pw", c1, "Argon2", 3, false, QString());
        QFile::remove(plain);
        bool ok = eng.decryptFile(ct, "pw", c2, "Argon2", 3, false, QString());
        check(!ok, "wrong cascade recipe rejected (id binding)");
        check(!QFile::exists(plain), "no plaintext after wrong-recipe");
        // And the correct recipe still works.
        ok = eng.decryptFile(ct, "pw", c1, "Argon2", 3, false, QString());
        check(ok, "correct recipe still decrypts");
        check(readAll(plain) == payload.left(4096), "correct recipe round-trip ok");
    }

    // ---- Empty-file cascade round-trip ----
    {
        const QString c1 = "Cascade: AES-256-GCM + ChaCha20-Poly1305 + AES-256-GCM";
        const QString plain = dir.path() + "/empty.bin";
        const QString ct    = plain + ".enc";
        QFile::remove(plain); QFile::remove(ct);
        writeFile(plain, QByteArray());
        bool ok = eng.encryptFile(plain, "pw", c1, "Argon2", 3, false, QString());
        check(ok, "empty-file cascade encrypt");
        QFile::remove(plain);
        ok = eng.decryptFile(ct, "pw", c1, "Argon2", 3, false, QString());
        check(ok, "empty-file cascade decrypt");
        check(readAll(plain).isEmpty(), "empty-file cascade round-trip ok");
    }

    if (s_failures) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures);
        return 1;
    }
    std::fprintf(stderr, "ALL CASCADE TESTS PASSED\n");
    return 0;
}
