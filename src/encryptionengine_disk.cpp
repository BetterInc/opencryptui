#include "encryptionengine.h"
#include "encryptionengine_diskops.h"
#include "secure_string.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <sodium.h>

// Disk encryption implementation for EncryptionEngine class
//
// SECURITY NOTE: every site that derives a `key` here must zero it via
// sodium_memzero (NOT memset). Plain memset can be elided by the compiler
// with LTO + dead-store elimination, leaving raw key bytes in the heap
// after the QByteArray is destroyed. sodium_memzero is documented as
// non-elidable.  Additionally, several early-return paths previously
// leaked the key — all such paths now wipe before returning.

bool EncryptionEngine::encryptDisk(const QString& diskPath, const QString& password, const QString& algorithm,
                                  const QString& kdf, int iterations, bool useHMAC,
                                  const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return encryptDisk(diskPath, sp, algorithm, kdf, iterations, useHMAC, keyfilePaths);
}

bool EncryptionEngine::encryptDisk(const QString& diskPath, const SecureString& password, const QString& algorithm,
                                  const QString& kdf, int iterations, bool useHMAC,
                                  const QStringList& keyfilePaths) {
    if (!m_currentProvider) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "No crypto provider selected");
        return false;
    }

    // Validate the disk path
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Invalid disk path: %1").arg(diskPath));
        return false;
    }

    SECURE_LOG(INFO, "EncryptionEngine", QString("Encrypting disk: %1").arg(diskPath));

    // Generate a secure salt for key derivation
    QByteArray salt = generateSecureSalt();

    // Generate secure IV for encryption
    QByteArray iv = generateSecureIV();
    // Removed lastIv storage for security reasons // Store for later use

    // Derive the encryption key from the password (SecureString) + keyfiles
    QByteArray key = deriveKey(password, salt, keyfilePaths, kdf, iterations);
    
    // Create the encryption header file
    bool headerCreated = DiskOperations::createEncryptionHeader(diskPath, algorithm, kdf, iterations, useHMAC, salt, iv);
    if (!headerCreated) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create encryption header for disk");
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Open the disk for encryption
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open disk for encryption: %1").arg(diskPath));
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Skip the header (4KB)
    diskFile.seek(DISK_HEADER_SIZE);

    // Create a temporary file for the encrypted data
    QTemporaryFile tempFile;
    if (!tempFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for encryption");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Encrypt the disk contents
    bool encryptionSuccess = m_currentProvider->encrypt(diskFile, tempFile, key, iv, algorithm, useHMAC);

    // Securely wipe the key from memory (sodium_memzero is non-elidable;
    // plain memset can be removed by the optimiser).
    if (!key.isEmpty()) sodium_memzero(key.data(), key.size());

    if (!encryptionSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to encrypt disk contents");
        diskFile.close();
        return false;
    }
    
    // Write the encrypted data back to the disk
    tempFile.reset(); // Seek to beginning
    diskFile.seek(DISK_HEADER_SIZE);
    
    QByteArray buffer;
    buffer.resize(1024 * 1024); // 1MB buffer for copying
    qint64 bytesRead;
    
    while ((bytesRead = tempFile.read(buffer.data(), buffer.size())) > 0) {
        if (diskFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write encrypted data back to disk");
            diskFile.close();
            return false;
        }
    }
    
    diskFile.close();
    SECURE_LOG(INFO, "EncryptionEngine", "Disk encryption completed successfully");
    
    return true;
}

bool EncryptionEngine::decryptDisk(const QString& diskPath, const QString& password, const QString& algorithm,
                                  const QString& kdf, int iterations, bool useHMAC,
                                  const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return decryptDisk(diskPath, sp, algorithm, kdf, iterations, useHMAC, keyfilePaths);
}

bool EncryptionEngine::decryptDisk(const QString& diskPath, const SecureString& password, const QString& algorithm,
                                  const QString& kdf, int iterations, bool useHMAC,
                                  const QStringList& keyfilePaths) {
    if (!m_currentProvider) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "No crypto provider selected");
        return false;
    }
    
    // Validate the disk path
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Invalid disk path: %1").arg(diskPath));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", QString("Decrypting disk: %1").arg(diskPath));
    
    // Read the encryption header to get the parameters
    QString headerAlgorithm;
    QString headerKdf;
    int headerIterations;
    bool headerUseHMAC;
    QByteArray headerSalt;
    QByteArray headerIv;
    bool hasHidden;
    
    bool headerRead = DiskOperations::readEncryptionHeader(diskPath, headerAlgorithm, headerKdf, 
                                                          headerIterations, headerUseHMAC, 
                                                          headerSalt, headerIv, hasHidden);
    
    if (!headerRead) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read encryption header from disk");
        return false;
    }
    
    // Use the parameters from the header, overriding any provided parameters
    QString algOverride = headerAlgorithm;
    QString kdfOverride = headerKdf;
    int iterOverride = headerIterations;
    bool hmacOverride = headerUseHMAC;
    // Removed lastIv storage for security reasons
    
    // Derive the encryption key from the password and keyfiles
    QByteArray key = deriveKey(password, headerSalt, keyfilePaths, kdfOverride, iterOverride);

    // Open the disk for decryption
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open disk for decryption: %1").arg(diskPath));
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Skip the header (4KB)
    diskFile.seek(DISK_HEADER_SIZE);

    // Create a temporary file for the decrypted data
    QTemporaryFile tempFile;
    if (!tempFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for decryption");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Decrypt the disk contents
    bool decryptionSuccess = m_currentProvider->decrypt(diskFile, tempFile, key, headerIv, algOverride, hmacOverride);

    // Securely wipe the key from memory (sodium_memzero is non-elidable).
    if (!key.isEmpty()) sodium_memzero(key.data(), key.size());

    if (!decryptionSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to decrypt disk contents");
        diskFile.close();
        return false;
    }
    
    // Write the decrypted data back to the disk
    tempFile.reset(); // Seek to beginning
    diskFile.seek(DISK_HEADER_SIZE);
    
    QByteArray buffer;
    buffer.resize(1024 * 1024); // 1MB buffer for copying
    qint64 bytesRead;
    
    while ((bytesRead = tempFile.read(buffer.data(), buffer.size())) > 0) {
        if (diskFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write decrypted data back to disk");
            diskFile.close();
            return false;
        }
    }
    
    diskFile.close();
    SECURE_LOG(INFO, "EncryptionEngine", "Disk decryption completed successfully");
    
    return true;
}

bool EncryptionEngine::encryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, 
                                        const QString& kdf, int iterations, bool useHMAC, 
                                        const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize) {
    if (!m_currentProvider) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "No crypto provider selected");
        return false;
    }
    
    // Validate the disk path
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Invalid disk path: %1").arg(diskPath));
        return false;
    }
    
    // Validate section parameters
    if (startOffset < DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Start offset cannot be within the header area");
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", QString("Encrypting disk section: %1 (offset: %2, size: %3)")
                                         .arg(diskPath).arg(startOffset).arg(sectionSize));
    
    // Generate a secure salt for key derivation
    QByteArray salt = generateSecureSalt();
    
    // Generate secure IV for encryption
    QByteArray iv = generateSecureIV();
    // Removed lastIv storage for security reasons // Store for later use
    
    // Derive the encryption key from the password and keyfiles
    QByteArray key = deriveKey(password, salt, keyfilePaths, kdf, iterations);

    // Open the disk for encryption
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open disk for section encryption: %1").arg(diskPath));
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Seek to the section start offset
    if (!diskFile.seek(startOffset)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to seek to section offset: %1").arg(startOffset));
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Create a temporary file for the section data
    QTemporaryFile sectionFile;
    if (!sectionFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for section data");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Read the section data to the temporary file
    QByteArray buffer;
    buffer.resize(1024 * 1024); // 1MB buffer
    qint64 totalRead = 0;
    qint64 bytesRead;

    while (totalRead < sectionSize && (bytesRead = diskFile.read(buffer.data(), qMin(qint64(buffer.size()), sectionSize - totalRead))) > 0) {
        if (sectionFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write section data to temporary file");
            diskFile.close();
            if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
            return false;
        }
        totalRead += bytesRead;
    }
    
    // Store section metadata in the disk header (for hidden volumes)
    HiddenVolumeInfo hiddenInfo;
    hiddenInfo.offset = startOffset;
    hiddenInfo.size = sectionSize;
    hiddenInfo.algorithm = algorithm;
    hiddenInfo.kdf = kdf;
    hiddenInfo.iterations = iterations;
    hiddenInfo.useHMAC = useHMAC;
    hiddenInfo.salt = salt;
    hiddenInfo.iv = iv;
    
    // Update the main header to indicate that it has a hidden volume
    bool mainHeaderUpdated = DiskOperations::createEncryptionHeader(
        diskPath, algorithm, kdf, iterations, useHMAC, salt, iv, true);

    if (!mainHeaderUpdated) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to update main disk header for hidden volume");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Write the hidden volume information
    bool headerUpdated = DiskOperations::createHiddenVolume(
        diskPath, sectionSize, algorithm, kdf, iterations, useHMAC, salt, iv);
    if (!headerUpdated) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to update disk header with hidden volume information");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Reset the section file and prepare for encryption
    sectionFile.reset();

    // Create a temporary file for the encrypted data
    QTemporaryFile encryptedFile;
    if (!encryptedFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for encrypted section");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Encrypt the section data
    bool encryptionSuccess = m_currentProvider->encrypt(sectionFile, encryptedFile, key, iv, algorithm, useHMAC);

    // Securely wipe the key from memory (sodium_memzero is non-elidable).
    if (!key.isEmpty()) sodium_memzero(key.data(), key.size());

    if (!encryptionSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to encrypt section data");
        diskFile.close();
        return false;
    }
    
    // Write the encrypted data back to the disk
    encryptedFile.reset(); // Seek to beginning
    diskFile.seek(startOffset);
    
    buffer.resize(1024 * 1024); // 1MB buffer for copying
    totalRead = 0;
    
    while ((bytesRead = encryptedFile.read(buffer.data(), buffer.size())) > 0) {
        if (diskFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write encrypted data back to disk section");
            diskFile.close();
            return false;
        }
        totalRead += bytesRead;
    }
    
    diskFile.close();
    SECURE_LOG(INFO, "EncryptionEngine", QString("Disk section encryption completed successfully (bytes: %1)").arg(totalRead));
    
    return true;
}

bool EncryptionEngine::decryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, 
                                        const QString& kdf, int iterations, bool useHMAC, 
                                        const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize) {
    if (!m_currentProvider) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "No crypto provider selected");
        return false;
    }
    
    // Validate the disk path
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Invalid disk path: %1").arg(diskPath));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", QString("Decrypting disk section: %1 (offset: %2, size: %3)")
                                         .arg(diskPath).arg(startOffset).arg(sectionSize));
    
    // First, check if we're decrypting a hidden volume
    HiddenVolumeInfo hiddenInfo;
    bool hasHidden = DiskOperations::readHiddenVolumeHeader(diskPath, hiddenInfo);
    
    // If hidden volume exists and the offset matches, use its parameters
    QByteArray salt;
    QByteArray iv;
    QString algOverride = algorithm;
    QString kdfOverride = kdf;
    int iterOverride = iterations;
    bool hmacOverride = useHMAC;
    
    if (hasHidden && hiddenInfo.offset == startOffset) {
        SECURE_LOG(INFO, "EncryptionEngine", "Detected hidden volume, using stored parameters");
        salt = hiddenInfo.salt;
        iv = hiddenInfo.iv;
        algOverride = hiddenInfo.algorithm;
        kdfOverride = hiddenInfo.kdf;
        iterOverride = hiddenInfo.iterations;
        hmacOverride = hiddenInfo.useHMAC;
        sectionSize = hiddenInfo.size; // Use the stored size for accuracy
        // Removed lastIv storage for security reasons
    } else {
        // If not a hidden volume or not found, use provided parameters
        // but still need salt and IV from somewhere
        SECURE_LOG(WARNING, "EncryptionEngine", "No hidden volume detected, using provided parameters");
        
        // Try to read them from the main volume header as fallback
        QString headerAlgorithm;
        QString headerKdf;
        int headerIterations;
        bool headerUseHMAC;
        QByteArray headerSalt;
        QByteArray headerIv;
        bool hasHiddenVol;
        
        bool headerRead = DiskOperations::readEncryptionHeader(diskPath, headerAlgorithm, headerKdf, 
                                                              headerIterations, headerUseHMAC, 
                                                              headerSalt, headerIv, hasHiddenVol);
        
        if (headerRead) {
            salt = headerSalt;
            iv = headerIv;
            // Removed lastIv storage for security reasons
        } else {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read any encryption parameters");
            return false;
        }
    }
    
    // Derive the encryption key from the password and keyfiles
    QByteArray key = deriveKey(password, salt, keyfilePaths, kdfOverride, iterOverride);

    // Open the disk for decryption
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open disk for section decryption: %1").arg(diskPath));
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Seek to the section start offset
    if (!diskFile.seek(startOffset)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to seek to section offset: %1").arg(startOffset));
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Create a temporary file for the encrypted section data
    QTemporaryFile encryptedFile;
    if (!encryptedFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for encrypted section");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Read the encrypted section data to the temporary file
    QByteArray buffer;
    buffer.resize(1024 * 1024); // 1MB buffer
    qint64 totalRead = 0;
    qint64 bytesRead;

    while (totalRead < sectionSize && (bytesRead = diskFile.read(buffer.data(), qMin(qint64(buffer.size()), sectionSize - totalRead))) > 0) {
        if (encryptedFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write encrypted section data to temporary file");
            diskFile.close();
            if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
            return false;
        }
        totalRead += bytesRead;
    }

    // Reset the encrypted file and prepare for decryption
    encryptedFile.reset();

    // Create a temporary file for the decrypted data
    QTemporaryFile decryptedFile;
    if (!decryptedFile.open()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for decrypted section");
        diskFile.close();
        if (!key.isEmpty()) sodium_memzero(key.data(), key.size());
        return false;
    }

    // Decrypt the section data
    bool decryptionSuccess = m_currentProvider->decrypt(encryptedFile, decryptedFile, key, iv, algOverride, hmacOverride);

    // Securely wipe the key from memory (sodium_memzero is non-elidable).
    if (!key.isEmpty()) sodium_memzero(key.data(), key.size());

    if (!decryptionSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to decrypt section data");
        diskFile.close();
        return false;
    }
    
    // Write the decrypted data back to the disk
    decryptedFile.reset(); // Seek to beginning
    diskFile.seek(startOffset);
    
    buffer.resize(1024 * 1024); // 1MB buffer for copying
    totalRead = 0;
    
    while ((bytesRead = decryptedFile.read(buffer.data(), buffer.size())) > 0) {
        if (diskFile.write(buffer.data(), bytesRead) != bytesRead) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to write decrypted data back to disk section");
            diskFile.close();
            return false;
        }
        totalRead += bytesRead;
    }
    
    diskFile.close();
    SECURE_LOG(INFO, "EncryptionEngine", QString("Disk section decryption completed successfully (bytes: %1)").arg(totalRead));
    
    return true;
}