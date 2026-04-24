// Engine-level keyfile test — no UI. Encrypt with password + keyfile,
// verify same keyfile round-trips, wrong keyfile rejects, no keyfile
// rejects.
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
    int failures = 0;

    const QString plain    = dir.filePath("plain.txt");
    const QString ct       = plain + ".enc";
    const QString keyfileA = dir.filePath("keyfile_a.bin");
    const QString keyfileB = dir.filePath("keyfile_b.bin");
    const QByteArray payload = "payload needing keyfile";

    if (!write(plain, payload))             { qCritical("write plain");    return 99; }
    if (!write(keyfileA, "keyfile-A-bytes")) { qCritical("write kfA");      return 99; }
    if (!write(keyfileB, "keyfile-B-bytes")) { qCritical("write kfB");      return 99; }

    const QString pwd = "correct-horse-battery-staple";

    // Case 1: same password + same keyfile → round-trip.
    if (!eng.encryptFile(plain, pwd, "AES-256-GCM", "PBKDF2", 600000,
                         false, QString(), QStringList{keyfileA})) {
        qCritical("encrypt with keyfile A failed");
        return 1;
    }
    QFile::remove(plain);
    if (!eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                         false, QString(), QStringList{keyfileA})) {
        qCritical("decrypt with keyfile A failed — round-trip broken");
        failures++;
    } else if (read(plain) != payload) {
        qCritical("decrypt succeeded but plaintext mismatch");
        failures++;
    } else {
        qInfo("[round-trip, keyfile A] OK");
    }

    // Case 2: wrong keyfile → must fail, no output.
    QFile::remove(plain);
    {
        const bool ok = eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                                        false, QString(), QStringList{keyfileB});
        if (ok) {
            qCritical("decrypt with WRONG keyfile succeeded — SECURITY BUG");
            failures++;
        } else if (QFile::exists(plain)) {
            qCritical("wrong-keyfile rejected but left plaintext on disk");
            failures++;
        } else {
            qInfo("[wrong keyfile] rejected, no output — OK");
        }
    }

    // Case 3: no keyfile when one was used → must fail.
    QFile::remove(plain);
    {
        const bool ok = eng.decryptFile(ct, pwd, "AES-256-GCM", "PBKDF2", 600000,
                                        false, QString(), QStringList{});
        if (ok) {
            qCritical("decrypt WITHOUT the keyfile succeeded — SECURITY BUG");
            failures++;
        } else if (QFile::exists(plain)) {
            qCritical("no-keyfile rejected but left plaintext on disk");
            failures++;
        } else {
            qInfo("[missing keyfile] rejected, no output — OK");
        }
    }

    if (failures) { qCritical() << "FAILURES:" << failures; return 1; }
    qInfo("ALL KEYFILE CASES OK");
    return 0;
}
