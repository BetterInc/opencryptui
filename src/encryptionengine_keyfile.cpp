// Keyfile I/O — extracted from encryptionengine_keyderivation.cpp so
// that file can focus on the KDF primitives themselves. The HMAC-based
// combining of keyfile material into the master password lives in
// deriveKey() next door; this file is just the disk read.
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>

QByteArray EncryptionEngine::readKeyfile(const QString& keyfilePath)
{
    if (keyfilePath.isEmpty()) {
        return QByteArray();
    }

    QFile keyfile(keyfilePath);
    if (!keyfile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            QString("Failed to open keyfile at path: %1").arg(keyfilePath));
        return QByteArray();
    }

    QByteArray keyfileData = keyfile.readAll();
    keyfile.close();

    if (keyfileData.isEmpty()) {
        SECURE_LOG(WARNING, "EncryptionEngine",
            QString("Keyfile is empty or could not be read: %1").arg(keyfilePath));
    }

    return keyfileData;
}
