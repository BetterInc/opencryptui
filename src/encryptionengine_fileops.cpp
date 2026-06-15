#include "encryptionengine.h"
#include "secure_string.h"
#include <QFile>
#include <QProcess>
#include <openssl/rand.h>
#include "logging/secure_logger.h"

bool EncryptionEngine::compressFolder(const QString& folderPath, const QString& outputFilePath) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Compressing folder: %1 to %2").arg(folderPath).arg(outputFilePath));
    
    // Make sure the folder exists and is readable
    QFileInfo folderInfo(folderPath);
    if (!folderInfo.exists() || !folderInfo.isDir() || !folderInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Folder validation failed: %1 (exists: %2, isDir: %3, isReadable: %4)")
            .arg(folderPath)
            .arg(folderInfo.exists())
            .arg(folderInfo.isDir())
            .arg(folderInfo.isReadable()));
        return false;
    }
    
    // Make sure the parent directory of the output file exists
    QFileInfo outputInfo(outputFilePath);
    QDir outputDir = outputInfo.dir();
    if (!outputDir.exists()) {
        if (!outputDir.mkpath(".")) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to create parent directory for output file: %1").arg(outputDir.path()));
            return false;
        }
    }
    
    // Remove any existing output file
    if (QFile::exists(outputFilePath)) {
        if (!QFile::remove(outputFilePath)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to remove existing output file: %1").arg(outputFilePath));
            return false;
        }
    }
    
    QProcess process;
    
    // Use absolute paths to avoid issues with working directory
    QString absFolder = QFileInfo(folderPath).absoluteFilePath();
    QString absOutput = QFileInfo(outputFilePath).absoluteFilePath();
    
    // Change directory to the parent of the folder being compressed
    QDir parentDir = QFileInfo(absFolder).dir();
    QString folderName = QFileInfo(absFolder).fileName();
    
    process.setWorkingDirectory(parentDir.path());
    
    // Construct the tar command carefully
    QStringList args;
    args << "-czf" << absOutput << folderName;
    
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Running tar from directory %1 with args: %2")
        .arg(parentDir.path()).arg(args.join(" ")));
    
    process.start("tar", args);
    process.waitForFinished(-1);
    
    bool success = process.exitCode() == 0;
    if (!success) {
        QString errorOutput = process.readAllStandardError();
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Folder compression failed with exit code: %1, Error: %2")
            .arg(process.exitCode())
            .arg(errorOutput));
    } else {
        SECURE_LOG(INFO, "EncryptionEngine", "Folder compression completed successfully");
    }
    
    return success;
}

bool EncryptionEngine::decompressFolder(const QString& filePath, const QString& outputFolderPath) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Decompressing file: %1 to %2").arg(filePath).arg(outputFolderPath));
    
    // Make sure the compressed file exists and is readable
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("File validation failed: %1 (exists: %2, isFile: %3, isReadable: %4)")
            .arg(filePath)
            .arg(fileInfo.exists())
            .arg(fileInfo.isFile())
            .arg(fileInfo.isReadable()));
        return false;
    }
    
    // Make sure the output directory exists
    QDir outputDir(outputFolderPath);
    if (!outputDir.exists()) {
        if (!outputDir.mkpath(".")) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to create output directory: %1").arg(outputFolderPath));
            return false;
        }
    }
    
    QProcess process;
    
    // Use absolute paths to avoid issues with working directory
    QString absFile = QFileInfo(filePath).absoluteFilePath();
    QString absOutput = QFileInfo(outputFolderPath).absoluteFilePath();
    
    // Construct the tar command carefully
    QStringList args;
    args << "-xzf" << absFile << "-C" << absOutput;
    
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Running tar with args: %1").arg(args.join(" ")));
    
    process.start("tar", args);
    process.waitForFinished(-1);
    
    bool success = process.exitCode() == 0;
    if (!success) {
        QString errorOutput = process.readAllStandardError();
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Folder decompression failed with exit code: %1, Error: %2")
            .arg(process.exitCode())
            .arg(errorOutput));
    } else {
        SECURE_LOG(INFO, "EncryptionEngine", "Folder decompression completed successfully");
    }
    
    return success;
}

// QString convenience wrapper - converts to mlocked SecureString and
// delegates. Used by tests, the benchmark path, and any non-UI caller.
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

bool EncryptionEngine::encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return encryptFolder(folderPath, sp, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::encryptFolder(const QString& folderPath, const SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Starting folder encryption: %1").arg(folderPath));
    
    // Validate folder
    QFileInfo folderInfo(folderPath);
    if (!folderInfo.exists() || !folderInfo.isDir() || !folderInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Folder validation failed: %1 (exists: %2, isDir: %3, isReadable: %4)")
                             .arg(folderPath)
                             .arg(folderInfo.exists())
                             .arg(folderInfo.isDir())
                             .arg(folderInfo.isReadable()));
        return false;
    }
    
    QString compressedFilePath = folderPath + ".tar.gz";
    if (!compressFolder(folderPath, compressedFilePath)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Folder compression failed, aborting encryption: %1").arg(folderPath));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", "Folder compressed, proceeding with encryption");
    bool success = encryptFile(compressedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
    
    if (success) {
        SECURE_LOG(INFO, "EncryptionEngine", QString("Folder encryption completed successfully: %1").arg(folderPath));
        
        // Clean up the compressed file
        if (QFile::exists(compressedFilePath)) {
            SECURE_LOG(DEBUG, "EncryptionEngine", "Removing temporary compressed file");
            if (!QFile::remove(compressedFilePath)) {
                SECURE_LOG(WARNING, "EncryptionEngine", QString("Failed to remove temporary compressed file: %1").arg(compressedFilePath));
            }
        }
    } else {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Folder encryption failed: %1").arg(folderPath));
    }
    
    return success;
}

bool EncryptionEngine::decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SecureString sp = SecureString::from_qstring(password);
    return decryptFolder(folderPath, sp, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::decryptFolder(const QString& folderPath, const SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    SECURE_LOG(INFO, "EncryptionEngine", QString("Starting folder decryption: %1").arg(folderPath));
    
    // Check multiple possible encrypted file paths
    QString encryptedFilePath;
    QStringList possibleExtensions = {".enc", ".encrypted"};
    
    for (const QString& ext : possibleExtensions) {
        QString testPath = folderPath + ext;
        if (QFile::exists(testPath)) {
            encryptedFilePath = testPath;
            SECURE_LOG(DEBUG, "EncryptionEngine", QString("Found encrypted file at: %1").arg(encryptedFilePath));
            break;
        }
    }
    
    // If not found with folder path, try with parent directory file matching folder name
    if (encryptedFilePath.isEmpty()) {
        QFileInfo folderInfo(folderPath);
        QString folderName = folderInfo.fileName();
        QString parentDir = folderInfo.dir().path();
        
        for (const QString& ext : possibleExtensions) {
            QString testPath = parentDir + "/" + folderName + ext;
            if (QFile::exists(testPath)) {
                encryptedFilePath = testPath;
                SECURE_LOG(DEBUG, "EncryptionEngine", QString("Found encrypted file in parent directory: %1").arg(encryptedFilePath));
                break;
            }
        }
    }
    
    if (encryptedFilePath.isEmpty()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Could not find encrypted file for: %1").arg(folderPath));
        return false;
    }
    
    // Define temporary files
    QString compressedFilePath = folderPath + ".tar.gz";
    
    // Validate encrypted file
    QFileInfo fileInfo(encryptedFilePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Encrypted file validation failed: %1 (exists: %2, isFile: %3, isReadable: %4)")
            .arg(encryptedFilePath)
            .arg(fileInfo.exists())
            .arg(fileInfo.isFile())
            .arg(fileInfo.isReadable()));
        return false;
    }
    
    // Ensure target folder exists or can be created
    QDir targetDir(folderPath);
    if (!targetDir.exists()) {
        SECURE_LOG(INFO, "EncryptionEngine", QString("Creating target folder: %1").arg(folderPath));
        if (!targetDir.mkpath(".")) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to create target folder: %1").arg(folderPath));
            return false;
        }
    }
    
    // First decrypt the file
    if (!decryptFile(encryptedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to decrypt folder archive: %1").arg(encryptedFilePath));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", "Archive decrypted, proceeding with decompression");
    
    // Check if the decrypted compressed file exists
    if (!QFile::exists(compressedFilePath)) {
        // Try to find the compressed file without extension
        QString basePath = encryptedFilePath;
        if (basePath.endsWith(".enc")) {
            basePath.chop(4);
        } else if (basePath.endsWith(".encrypted")) {
            basePath.chop(10);
        }
        
        if (QFile::exists(basePath)) {
            compressedFilePath = basePath;
            SECURE_LOG(DEBUG, "EncryptionEngine", 
                QString("Found decompressed file at alternate location: %1").arg(compressedFilePath));
        } else {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Could not find decompressed archive at expected path: %1").arg(compressedFilePath));
            return false;
        }
    }
    
    // Now decompress it
    bool success = decompressFolder(compressedFilePath, folderPath);
    
    if (success) {
        SECURE_LOG(INFO, "EncryptionEngine", QString("Folder decryption and decompression completed successfully: %1").arg(folderPath));
        
        // Clean up the compressed file
        if (QFile::exists(compressedFilePath)) {
            SECURE_LOG(DEBUG, "EncryptionEngine", "Removing temporary compressed file");
            if (!QFile::remove(compressedFilePath)) {
                SECURE_LOG(WARNING, "EncryptionEngine", 
                    QString("Failed to remove temporary compressed file: %1").arg(compressedFilePath));
            }
        }
    } else {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Folder decompression failed: %1").arg(compressedFilePath));
    }
    
    return success;
}