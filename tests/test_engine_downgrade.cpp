// Engine-level downgrade test: OCUI v2 header binds algorithm + KDF.
// Verify decrypt rejects when caller claims a cipher/KDF different
// from what was written at encrypt time.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QDebug>

static bool write(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(data);
    return true;
}

static int expectRejection(EncryptionEngine& eng, const QString& ctPath,
                           const QString& plainPath, const char* label,
                           const QString& algo, const QString& kdf, int iters)
{
    QFile::remove(plainPath);
    const bool ok = eng.decryptFile(ctPath, "password123", algo, kdf, iters,
                                    /*useHMAC=*/false, QString());
    if (ok) {
        qCritical() << "[" << label << "] decrypt should have been REJECTED — downgrade invariant broken";
        return 1;
    }
    if (QFile::exists(plainPath)) {
        qCritical() << "[" << label << "] rejected but left plaintext on disk";
        return 2;
    }
    qInfo() << "[" << label << "] rejected as expected — OK";
    return 0;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { qCritical("no tempdir"); return 99; }

    EncryptionEngine eng;
    int failures = 0;
    const QString plain = dir.filePath("plain.txt");
    const QString ct    = plain + ".enc";

    // Baseline: encrypt with AES-256-GCM + PBKDF2 + 600k.
    if (!write(plain, "downgrade test payload")) { qCritical("write plain failed"); return 99; }
    if (!eng.encryptFile(plain, "password123", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString())) {
        qCritical("encrypt baseline failed");
        return 99;
    }

    // 1. Algorithm downgrade: claim CBC instead of GCM.
    failures += expectRejection(eng, ct, plain, "algo downgrade GCM→CBC",
                                "AES-256-CBC", "PBKDF2", 600000);

    // 2. KDF swap: same alg, claim Argon2 instead of PBKDF2.
    //    (Note: header stores numeric KDF id; should mismatch.)
    //    Use Argon2's floor (3) — the engine refuses sub-floor iter counts
    //    BEFORE the KDF-mismatch check now (calculateSecureIterations gates
    //    earlier). Passing floor-conformant 3 lets the KDF-mismatch path
    //    actually run, which is what this case is meant to exercise.
    failures += expectRejection(eng, ct, plain, "KDF swap PBKDF2→Argon2",
                                "AES-256-GCM", "Argon2", 3);

    // 3. Iteration lie: caller claims 1; file has 600000.
    //    Previously the engine silently clamped sub-floor counts up to the
    //    OWASP floor — so caller's "1" became 600000 internally and the
    //    decrypt succeeded, masking the fact that the v4 outer master is
    //    derived from CALLER's iter count (not the file's). That silent
    //    clamp is gone. Now the engine refuses the sub-floor count outright,
    //    which is the correct security behavior: if a caller can't supply a
    //    valid iter count, they shouldn't be able to derive a key.
    failures += expectRejection(eng, ct, plain, "iteration lie 1<<600000",
                                "AES-256-GCM", "PBKDF2", 1);

    // 4. Honest decrypt — make sure nothing else broke.
    {
        QFile::remove(plain);
        const bool ok = eng.decryptFile(ct, "password123",
                                        "AES-256-GCM", "PBKDF2", 600000,
                                        false, QString());
        if (!ok) {
            qCritical("honest round-trip failed");
            failures++;
        } else {
            qInfo("[honest round-trip] OK");
        }
    }

    if (failures) { qCritical() << "FAILURES:" << failures; return 1; }
    qInfo("ALL DOWNGRADE CASES OK");
    return 0;
}
