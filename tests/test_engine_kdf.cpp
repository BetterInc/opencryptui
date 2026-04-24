// Engine-level KDF behaviour test.
//   - deriveKeyWithoutKeyfile is deterministic: same inputs → same key.
//   - Different salts produce different keys.
//   - Different passwords produce different keys.
//   - PBKDF2 below the 600k floor is rejected on decrypt.
//   - Non-empty key is returned for each advertised KDF.
// No UI, no filesystem roundtrip — this is focused on the key-derivation
// primitive itself.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QByteArray>
#include <QFile>
#include <QTemporaryDir>
#include <QDebug>
#include <QtEndian>

static int check(bool ok, const char* label) {
    if (!ok) { qCritical() << "FAIL:" << label; return 1; }
    qInfo() << "OK  :" << label;
    return 0;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    EncryptionEngine eng;
    int failures = 0;

    const QString pwd  = "correct-horse-battery-staple";
    const QString pwd2 = "different-password-entirely";
    const QString saltA = "0123456789abcdef0123456789abcdef"; // 32 chars
    const QString saltB = "fedcba9876543210fedcba9876543210";
    const int keySize = 32;

    // --- 1. Determinism: same inputs → same key (PBKDF2) -----------------
    {
        QByteArray k1 = eng.deriveKeyWithoutKeyfile(pwd, saltA, "PBKDF2", 600000, keySize);
        QByteArray k2 = eng.deriveKeyWithoutKeyfile(pwd, saltA, "PBKDF2", 600000, keySize);
        failures += check(!k1.isEmpty() && !k2.isEmpty(), "PBKDF2 non-empty");
        failures += check(k1 == k2, "PBKDF2 deterministic");
    }

    // --- 2. Different salt → different key -------------------------------
    {
        QByteArray kA = eng.deriveKeyWithoutKeyfile(pwd, saltA, "PBKDF2", 600000, keySize);
        QByteArray kB = eng.deriveKeyWithoutKeyfile(pwd, saltB, "PBKDF2", 600000, keySize);
        failures += check(kA != kB, "different salt → different key");
    }

    // --- 3. Different password → different key ---------------------------
    {
        QByteArray kA = eng.deriveKeyWithoutKeyfile(pwd,  saltA, "PBKDF2", 600000, keySize);
        QByteArray kB = eng.deriveKeyWithoutKeyfile(pwd2, saltA, "PBKDF2", 600000, keySize);
        failures += check(kA != kB, "different password → different key");
    }

    // --- 4. Argon2 returns non-empty, advertised KDFs work ---------------
    {
        QByteArray kArgon = eng.deriveKeyWithoutKeyfile(pwd, saltA, "Argon2", 1, keySize);
        failures += check(!kArgon.isEmpty(), "Argon2 non-empty (iter=1)");

        QByteArray kPbk = eng.deriveKeyWithoutKeyfile(pwd, saltA, "PBKDF2", 600000, keySize);
        failures += check(!kPbk.isEmpty(), "PBKDF2 non-empty (600k)");

        failures += check(kArgon != kPbk, "Argon2 and PBKDF2 diverge for same input");
    }

    // --- 5. PBKDF2 floor on decrypt --------------------------------------
    // Encrypt a real file with PBKDF2 600k, then splice the OCUI header so
    // the stored iteration count reads as 1000 (below the 600k floor) and
    // assert decrypt rejects.
    //
    // OCUI v2 header layout:
    //   [magic "OCUI" 4][ver 1][algId 1][kdfId 1][reserved 1][iters 4 BE]
    //   → total 12 bytes, iters at offset 8..11.
    {
        QTemporaryDir dir;
        if (!dir.isValid()) { qCritical("no tempdir"); return 99; }
        const QString plain = dir.filePath("p.txt");
        const QString ct    = plain + ".enc";
        {
            QFile f(plain);
            if (!f.open(QIODevice::WriteOnly) || f.write("hi") != 2) {
                qCritical("write plain"); return 99;
            }
        }
        if (!eng.encryptFile(plain, pwd, "AES-256-GCM", "PBKDF2", 600000,
                             false, QString())) {
            qCritical("floor-test: encrypt failed");
            failures++;
        } else {
            // Splice stored iteration count down to 1000.
            QFile f(ct);
            if (!f.open(QIODevice::ReadWrite)) { qCritical("open ct"); return 99; }
            if (!f.seek(8)) { qCritical("seek hdr"); return 99; }
            const quint32 newIters = qToBigEndian<quint32>(1000);
            if (f.write(reinterpret_cast<const char*>(&newIters), 4) != 4) {
                qCritical("write iters"); return 99;
            }
            f.close();

            QFile::remove(plain);
            const bool ok = eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                                            false, QString());
            failures += check(!ok, "PBKDF2 floor rejects stored iters=1000");
            failures += check(!QFile::exists(plain), "floor-rejected decrypt leaves no plaintext");
        }
    }

    if (failures) { qCritical() << "FAILURES:" << failures; return 1; }
    qInfo("ALL KDF CASES OK");
    return 0;
}
