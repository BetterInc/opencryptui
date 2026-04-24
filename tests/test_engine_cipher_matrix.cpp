// Engine-level cipher-matrix test: every supported cipher must round-trip
// (encrypt → decrypt → byte-identical plaintext). No UI.
//
// Replaces the UI-driven testAllCiphersAndKDFs for the security-relevant
// part (the actual crypto). Only PBKDF2 is exercised here to keep runtime
// low; Argon2 and Scrypt get their own targeted tests in test_engine_kdf.
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

static QByteArray read(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { qCritical("no tempdir"); return 99; }

    EncryptionEngine eng;
    const QStringList ciphers = eng.supportedCiphers();
    if (ciphers.isEmpty()) { qCritical("no supported ciphers"); return 99; }

    const QByteArray payload = "cipher matrix round-trip payload with enough bytes to span a block";
    const QString pwd = "correct-horse-battery-staple";
    const QString kdf = "PBKDF2";
    const int iters = 600000; // above the hardened floor

    int failures = 0;
    for (const QString& algo : ciphers) {
        const QString plain = dir.filePath("plain_" + QString(algo).replace('-', '_') + ".txt");
        const QString ct    = plain + ".enc";

        if (!write(plain, payload)) {
            qCritical() << "[" << algo << "] write plain failed";
            failures++;
            continue;
        }

        if (!eng.encryptFile(plain, pwd, algo, kdf, iters,
                             /*useHMAC=*/false, QString())) {
            qCritical() << "[" << algo << "] encryptFile failed";
            failures++;
            QFile::remove(plain);
            QFile::remove(ct);
            continue;
        }

        QFile::remove(plain); // force fresh plaintext file

        if (!eng.decryptFile(ct, pwd, algo, kdf, iters,
                             /*useHMAC=*/false, QString())) {
            qCritical() << "[" << algo << "] decryptFile failed";
            failures++;
            QFile::remove(ct);
            continue;
        }

        const QByteArray got = read(plain);
        if (got != payload) {
            qCritical() << "[" << algo << "] plaintext MISMATCH. expected size:"
                        << payload.size() << "got size:" << got.size();
            failures++;
        } else {
            qInfo() << "[" << algo << "] OK";
        }

        QFile::remove(plain);
        QFile::remove(ct);
    }

    if (failures) {
        qCritical() << "FAILURES:" << failures << "of" << ciphers.size() << "ciphers";
        return 1;
    }
    qInfo() << "ALL" << ciphers.size() << "CIPHERS ROUND-TRIP OK";
    return 0;
}
