// Engine-level tamper test: flip bytes in the ciphertext / header / IV /
// salt and verify decryption rejects the file AND leaves no plaintext
// output on disk. No UI — direct EncryptionEngine API.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QDebug>

static bool write(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(data);
    return true;
}

static bool flipByteAt(const QString& path, qint64 offset) {
    QFile f(path);
    if (!f.open(QIODevice::ReadWrite)) return false;
    if (!f.seek(offset)) return false;
    char b;
    if (f.read(&b, 1) != 1) return false;
    b ^= 0x01;
    if (!f.seek(offset)) return false;
    if (f.write(&b, 1) != 1) return false;
    return true;
}

// Encrypts payload → returns ciphertext path. Caller responsible for removing.
static bool encryptFixture(EncryptionEngine& eng, const QString& dir,
                           QString* outCtPath, QString* outPlainPath)
{
    *outPlainPath = dir + "/plain.txt";
    *outCtPath    = *outPlainPath + ".enc";
    if (!write(*outPlainPath, "sensitive data for tamper test")) return false;
    return eng.encryptFile(*outPlainPath, "correct-horse-battery-staple",
                           "AES-256-GCM", "PBKDF2", 600000,
                           /*useHMAC=*/false, /*customHeader=*/QString());
}

static int expectRejection(EncryptionEngine& eng, const QString& ctPath,
                           const QString& plainPath, const char* label,
                           const QString& algo = "AES-256-GCM",
                           const QString& kdf = "PBKDF2", int iters = 600000)
{
    // Remove any leftover plaintext so we can assert it doesn't reappear.
    QFile::remove(plainPath);
    const bool ok = eng.decryptFile(ctPath, "correct-horse-battery-staple",
                                    algo, kdf, iters,
                                    /*useHMAC=*/false, /*customHeader=*/QString());
    if (ok) {
        qCritical() << "[" << label << "] decrypt unexpectedly SUCCEEDED on tampered file";
        return 1;
    }
    if (QFile::exists(plainPath)) {
        qCritical() << "[" << label << "] tampered decrypt left plaintext on disk — SECURITY BUG";
        return 2;
    }
    qInfo() << "[" << label << "] rejected as expected, no output file — OK";
    return 0;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { qCritical("no tempdir"); return 99; }

    EncryptionEngine eng;
    int failures = 0;

    struct Case { const char* label; qint64 offset; };
    const Case cases[] = {
        {"OCUI magic",          0   },   // magic "OCUI" at offset 0
        {"format version",      4   },   // fmtVer byte
        {"algorithm id",        5   },   // algId byte
        {"KDF id",              6   },   // kdfId byte
        {"iterations field",    8   },   // iters big-endian u32 at offset 8
        {"salt",                16  },   // first salt byte after 12-byte header
        {"IV",                  48  },   // first IV byte after salt (32-byte salt)
        {"ciphertext body",     62  },   // after 12 hdr + 32 salt + 12 iv (AES-GCM)
    };

    for (const auto& c : cases) {
        QString ct, plain;
        if (!encryptFixture(eng, dir.path(), &ct, &plain)) {
            qCritical() << "[" << c.label << "] encrypt fixture failed";
            failures++;
            continue;
        }
        if (!flipByteAt(ct, c.offset)) {
            qCritical() << "[" << c.label << "] flipByteAt failed";
            failures++;
            continue;
        }
        if (int rc = expectRejection(eng, ct, plain, c.label)) failures += rc;
        QFile::remove(ct);
        QFile::remove(plain);
    }

    // Negative control — untampered file MUST still decrypt.
    {
        QString ct, plain;
        if (!encryptFixture(eng, dir.path(), &ct, &plain)) {
            qCritical("control: encrypt fixture failed");
            failures++;
        } else {
            QFile::remove(plain);
            if (!eng.decryptFile(ct, "correct-horse-battery-staple",
                                 "AES-256-GCM", "PBKDF2", 600000,
                                 false, QString())) {
                qCritical("control: untampered file FAILED to decrypt");
                failures++;
            } else {
                qInfo("[control] untampered round-trip OK");
            }
        }
    }

    if (failures) { qCritical() << "FAILURES:" << failures; return 1; }
    qInfo("ALL TAMPER CASES OK");
    return 0;
}
