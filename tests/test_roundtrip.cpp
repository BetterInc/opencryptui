// Quick standalone round-trip test: encrypt -> decrypt a small file with the
// real EncryptionEngine API, no UI. Iterate on this until it passes.
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QDebug>
#include <cstdio>

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

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    SecureLogger::getInstance().setLogLevel(SecureLogger::LogLevel::DEBUG);

    QTemporaryDir dir;
    if (!dir.isValid()) { qCritical("no tempdir"); return 1; }

    const QString plain = dir.filePath("plain.txt");
    const QString ct    = plain + ".enc";

    const QByteArray payload = "Hello, round-trip! This is a test.";
    if (!write(plain, payload)) { qCritical("write plain"); return 1; }

    EncryptionEngine eng;

    const QString algo = QString::fromLatin1(argc > 1 ? argv[1] : "AES-256-GCM");
    const QString kdf  = "PBKDF2";
    const QString pwd  = "correct-horse-battery-staple";

    qInfo() << "=== ENCRYPT" << algo << "===";
    bool ok = eng.encryptFile(plain, pwd, algo, kdf, 10000, /*useHMAC=*/false,
                              /*customHeader=*/QString());
    qInfo() << "encryptFile returned:" << ok << " ct size:" << QFileInfo(ct).size();
    if (!ok) return 2;

    QFile::remove(plain); // force decrypt to produce a fresh file

    qInfo() << "=== DECRYPT ===";
    ok = eng.decryptFile(ct, pwd, algo, kdf, 10000, /*useHMAC=*/false,
                         /*customHeader=*/QString());
    qInfo() << "decryptFile returned:" << ok << " back size:"
            << (QFile::exists(plain) ? QFileInfo(plain).size() : -1);
    if (!ok) return 3;

    QByteArray got = read(plain);
    if (got != payload) {
        qCritical() << "MISMATCH. expected size:" << payload.size()
                    << "got size:" << got.size()
                    << "\n  expected:" << payload
                    << "\n  got:     " << got;
        return 4;
    }

    qInfo() << "ROUND-TRIP OK, algo=" << algo;
    return 0;
}
