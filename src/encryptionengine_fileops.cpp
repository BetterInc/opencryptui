#include "encryptionengine.h"
#include "secure_string.h"
#include <QFile>
#include <QProcess>
#include <openssl/rand.h>
#include "logging/secure_logger.h"

bool EncryptionEngine::encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return encryptFile(filePath, sp, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::encryptFile(const QString& filePath, const SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Starting file encryption for file: %1").arg(filePath));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Using algorithm: %1, KDF: %2, iterations: %3, HMAC: %4")
                       .arg(algorithm).arg(kdf).arg(iterations).arg(useHMAC ? "Yes" : "No"));

    // Validate input file
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Input file validation failed: %1 (exists: %2, isFile: %3, isReadable: %4)")
                             .arg(filePath)
                             .arg(fileInfo.exists())
                             .arg(fileInfo.isFile())
                             .arg(fileInfo.isReadable()));
        return false;
    }

    QString outputPath = filePath + ".enc";
    bool success = cryptOperation(filePath, outputPath, password, algorithm, true, kdf, iterations, useHMAC, customHeader, keyfilePaths);

    if (success) {
        SECURE_LOG(INFO, "EncryptionEngine", QString("File encryption completed successfully: %1").arg(outputPath));
    } else {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("File encryption failed: %1").arg(filePath));
    }

    return success;
}

bool EncryptionEngine::decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return decryptFile(filePath, sp, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::decryptFile(const QString& filePath, const SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Starting file decryption for file: %1").arg(filePath));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Using algorithm: %1, KDF: %2, iterations: %3, HMAC: %4")
                      .arg(algorithm).arg(kdf).arg(iterations).arg(useHMAC ? "Yes" : "No"));

    // Validate input file
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Input file validation failed: %1 (exists: %2, isFile: %3, isReadable: %4)")
                            .arg(filePath)
                            .arg(fileInfo.exists())
                            .arg(fileInfo.isFile())
                            .arg(fileInfo.isReadable()));
        return false;
    }

    // Verify file extension
    if (!filePath.endsWith(".enc")) {
        SECURE_LOG(WARNING, "EncryptionEngine", QString("File does not have .enc extension: %1").arg(filePath));
    }

    QString outputPath = filePath;
    outputPath.chop(4); // Remove ".enc"

    bool success = cryptOperation(filePath, outputPath, password, algorithm, false, kdf, iterations, useHMAC, customHeader, keyfilePaths);

    if (success) {
        SECURE_LOG(INFO, "EncryptionEngine", QString("File decryption completed successfully: %1").arg(outputPath));
    } else {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("File decryption failed: %1").arg(filePath));
    }

    return success;
}
