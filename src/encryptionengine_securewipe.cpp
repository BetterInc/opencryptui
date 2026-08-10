#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QProcess>
#include <QStorageInfo>
#include <QThreadPool>
#include <algorithm> // For std::min
#include <array>   // For std::array

// Secure file deletion with multiple passes
bool EncryptionEngine::secureDeleteFile(const QString& filePath, int passes)
{
    if (passes < 1) passes = 3; // Default to 3 passes for good security
    
    QFile file(filePath);
    QFileInfo fileInfo(filePath);
    
    // Check if file exists and is writable
    if (!fileInfo.exists() || !fileInfo.isWritable()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Cannot securely delete file: %1 - File does not exist or is not writable").arg(filePath));
        return false;
    }
    
    // Get file size for overwriting
    qint64 fileSize = fileInfo.size();
    if (fileSize <= 0) {
        // Empty file, just delete it
        return QFile::remove(filePath);
    }
    
    // Open file for writing
    if (!file.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Cannot open file for secure deletion: %1").arg(filePath));
        return false;
    }
    
    // Create data buffers of different patterns
    QByteArray randomBuffer(std::min(fileSize, static_cast<qint64>(1024 * 1024)), 0); // Max 1MB buffer
    QByteArray zeroBuffer(randomBuffer.size(), 0);
    QByteArray oneBuffer(randomBuffer.size(), 0xFF);
    
    try {
        // Multiple secure overwrite passes
        for (int pass = 0; pass < passes; pass++) {
            // Reset to beginning of file
            if (!file.seek(0)) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                    QString("Failed to seek to beginning of file for pass %1: %2").arg(pass).arg(filePath));
                file.close();
                return false;
            }
            
            // Pattern selection based on pass number
            QByteArray* currentBuffer = nullptr;
            QByteArray randomData; // Declare outside switch for scope reasons
            
            switch (pass % 3) {
                case 0:
                    // Random data pass
                    randomData = generateSecureRandomBytes(randomBuffer.size(), false);
                    randomBuffer = randomData;
                    currentBuffer = &randomBuffer;
                    break;
                case 1:
                    // All zeros pass
                    currentBuffer = &zeroBuffer;
                    break;
                case 2:
                    // All ones pass
                    currentBuffer = &oneBuffer;
                    break;
            }
            
            // Write in chunks
            qint64 remaining = fileSize;
            while (remaining > 0) {
                QByteArray writeBuffer;
                if (remaining >= currentBuffer->size()) {
                    writeBuffer = *currentBuffer;
                } else {
                    writeBuffer = currentBuffer->left(remaining);
                }
                
                // Write the pattern
                qint64 bytesWritten = file.write(writeBuffer);
                if (bytesWritten <= 0) {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                        QString("Failed to write during secure deletion pass %1: %2").arg(pass).arg(filePath));
                    file.close();
                    return false;
                }
                
                // Update remaining bytes
                remaining -= bytesWritten;
                
                // Explicitly flush to ensure data is written
                file.flush();
            }
        }
        
        // Flush all data to disk
        file.flush();
        
        // Close file before rename/deletion
        file.close();
        
        // Rename the file to hide its original name
        QString tempName = filePath + ".tmp" + QString::number(QDateTime::currentMSecsSinceEpoch());
        QString fileToDelete = filePath;
        
        if (!QFile::rename(filePath, tempName)) {
            SECURE_LOG(WARNING, "EncryptionEngine", 
                QString("Failed to rename file during secure deletion: %1").arg(filePath));
            // Continue with deletion attempt anyway
        } else {
            // Use the new temp name for final deletion
            fileToDelete = tempName;
        }
        
        // Finally delete the file
        if (!QFile::remove(fileToDelete)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to delete file after secure overwrite: %1").arg(fileToDelete));
            return false;
        }
        
        SECURE_LOG(INFO, "EncryptionEngine", 
            QString("Securely deleted file with %1 passes: %2").arg(passes).arg(fileInfo.fileName()));
        
        return true;
    }
    catch (const std::exception& e) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Exception during secure file deletion: %1").arg(e.what()));
        
        // Make sure file is closed
        if (file.isOpen()) {
            file.close();
        }
        
        return false;
    }
}

// Securely delete plaintext after encryption
bool EncryptionEngine::secureDeletePlaintext(const QString& plaintextFilePath)
{
    return secureDeleteFile(plaintextFilePath, 3);
}

// Implement inode scrubbing to completely remove file traces
bool EncryptionEngine::scrubFileInode(const QString& filePath)
{
    // This is a Linux-specific implementation using the shred command
    // It tries to hide all traces of file existence
    
#ifdef Q_OS_UNIX
    // Create a QProcess to run the external command
    QProcess process;
    QStringList args;
    
    // Configure shred for thorough deletion (-u removes the file, -z adds a final zero pass, -n 3 is 3 passes)
    args << "-u" << "-z" << "-n" << "3" << filePath;
    
    // Execute shred command
    process.start("shred", args);
    
    // Wait for the process to finish with a timeout
    if (!process.waitForFinished(30000)) { // 30 second timeout
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Timeout while running shred on file: %1").arg(filePath));
        process.kill();
        return false;
    }
    
    // Check the exit code
    if (process.exitCode() != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Shred command failed with exit code %1: %2")
            .arg(process.exitCode())
            .arg(QString(process.readAllStandardError())));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Successfully scrubbed file inode: %1").arg(filePath));
    return true;
    
#else
    // For non-Unix systems, fall back to regular secure delete
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Inode scrubbing not supported on this platform, using secure delete for: %1").arg(filePath));
    return secureDeleteFile(filePath, 7); // Use more passes as compensation
#endif
}

// Helper function to write a specific wipe pattern to a disk
bool EncryptionEngine::writeWipePattern(QFile& diskFile, WipePattern pattern, qint64 size, int passNumber, int totalPasses)
{
    // First seek to the beginning of the file/device
    if (!diskFile.seek(0)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Failed to seek to start of disk: %1").arg(diskFile.fileName()));
        return false;
    }
    
    // Determine the appropriate pattern based on input
    QByteArray writePattern;
    
    // Create buffer for writing - use a reasonable size to balance speed and memory usage
    const qint64 bufferSize = 1024 * 1024; // 1MB buffer
    
    switch (pattern) {
        case WipePattern::ZEROS:
            writePattern = QByteArray(bufferSize, 0x00);
            break;
            
        case WipePattern::ONES:
            writePattern = QByteArray(bufferSize, 0xFF);
            break;
            
        case WipePattern::RANDOM:
            writePattern = generateSecureRandomBytes(bufferSize, false);
            break;
            
        case WipePattern::DOD_SHORT: {
            // DoD Short method uses specific patterns depending on the pass number
            if (passNumber % 3 == 0) {
                writePattern = QByteArray(bufferSize, 0x00); // Zeros
            } else if (passNumber % 3 == 1) {
                writePattern = QByteArray(bufferSize, 0xFF); // Ones
            } else {
                writePattern = generateSecureRandomBytes(bufferSize, false); // Random
            }
            break;
        }
            
        case WipePattern::DOD_FULL:
        case WipePattern::GUTMANN: {
            // These use multiple complex patterns with specific bit sequences
            // For simplicity in this implementation, we'll use a pattern based on the pass number
            int patternSeed = passNumber % 7;
            
            switch (patternSeed) {
                case 0: writePattern = QByteArray(bufferSize, 0x00); break; // All zeros
                case 1: writePattern = QByteArray(bufferSize, 0xFF); break; // All ones
                case 2: writePattern = QByteArray(bufferSize, 0x55); break; // Alternating 01
                case 3: writePattern = QByteArray(bufferSize, 0xAA); break; // Alternating 10
                case 4: writePattern = QByteArray(bufferSize, 0x92); break; // 10010010
                case 5: writePattern = QByteArray(bufferSize, 0x49); break; // 01001001
                default: writePattern = generateSecureRandomBytes(bufferSize, false); break;
            }
            break;
        }
    }
    
    // Write the pattern to the entire disk in chunks
    qint64 bytesRemaining = size;
    qint64 totalWritten = 0;
    
    while (bytesRemaining > 0) {
        // Determine how much to write in this iteration
        qint64 chunkSize = std::min(bytesRemaining, (qint64)writePattern.size());
        
        // Write the chunk
        qint64 bytesWritten = diskFile.write(writePattern.data(), chunkSize);
        
        if (bytesWritten <= 0) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to write wipe data to disk: %1")
                .arg(diskFile.fileName()));
            return false;
        }
        
        bytesRemaining -= bytesWritten;
        totalWritten += bytesWritten;
        
        // Force data to disk periodically
        if (totalWritten % (10 * bufferSize) == 0) {
            diskFile.flush();
        }
    }
    
    // Final flush to ensure all data is written
    diskFile.flush();
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Successfully wrote wipe pattern to disk (Pass %1/%2): %3 bytes")
        .arg(passNumber + 1)
        .arg(totalPasses)
        .arg(totalWritten));
    
    return true;
}

// Helper function to verify a specific wipe pattern on a disk
bool EncryptionEngine::verifyWipePattern(QFile& diskFile, WipePattern pattern, qint64 size)
{
    // Only verify certain patterns (zeros, ones, and simple patterns)
    // Random patterns can't be verified
    if (pattern == WipePattern::RANDOM) {
        return true; // Skip verification for random patterns
    }
    
    if (!diskFile.seek(0)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Failed to seek to start of disk for verification: %1").arg(diskFile.fileName()));
        return false;
    }
    
    // Determine the expected pattern
    unsigned char expectedByte = 0x00;
    
    switch (pattern) {
        case WipePattern::ZEROS:
            expectedByte = 0x00;
            break;
        case WipePattern::ONES:
            expectedByte = 0xFF;
            break;
        default:
            SECURE_LOG(WARNING, "EncryptionEngine", 
                QString("Only verifying simple patterns (zeros/ones) for disk: %1").arg(diskFile.fileName()));
            return true; // Skip verification for complex patterns
    }
    
    // Read in chunks and verify each byte
    const qint64 bufferSize = 1024 * 1024; // 1MB read buffer
    QByteArray readBuffer(bufferSize, 0);
    
    qint64 bytesRemaining = size;
    qint64 totalRead = 0;
    qint64 invalidBytes = 0;
    
    while (bytesRemaining > 0) {
        qint64 chunkSize = std::min(bytesRemaining, (qint64)readBuffer.size());
        
        // Read a chunk
        qint64 bytesRead = diskFile.read(readBuffer.data(), chunkSize);
        
        if (bytesRead <= 0) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Failed to read data from disk during verification: %1").arg(diskFile.fileName()));
            return false;
        }
        
        // Verify each byte in the chunk
        for (qint64 i = 0; i < bytesRead; i++) {
            if (readBuffer.at(static_cast<int>(i)) != expectedByte) {
                invalidBytes++;
                
                // If too many invalid bytes, abort verification
                if (invalidBytes > 1000) {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                        QString("Too many invalid bytes during verification (%1 errors)").arg(invalidBytes));
                    return false;
                }
            }
        }
        
        bytesRemaining -= bytesRead;
        totalRead += bytesRead;
    }
    
    // Allow a small number of invalid bytes (due to bad sectors, etc.)
    if (invalidBytes > 0) {
        SECURE_LOG(WARNING, "EncryptionEngine", 
            QString("Found %1 invalid bytes during verification of %2 total bytes")
            .arg(invalidBytes).arg(totalRead));
        
        // Fail if more than 0.01% of bytes are invalid
        if (invalidBytes > totalRead / 10000) {
            return false;
        }
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Successfully verified disk wipe pattern: %1").arg(diskFile.fileName()));
    
    return true;
}

// Public method to securely wipe a disk
bool EncryptionEngine::secureWipeDisk(const QString& diskPath, int passes, bool verifyWipe)
{
    // Validate input parameters
    if (passes < 1) passes = 3; // Default to 3 passes
    if (passes > 35) passes = 35; // Cap at 35 passes (Gutmann method)
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Starting secure disk wipe for %1 with %2 passes")
        .arg(diskPath).arg(passes));
    
    // Verify disk path exists and is writable
    QFileInfo diskInfo(diskPath);
    if (!diskInfo.exists()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Disk path does not exist: %1").arg(diskPath));
        return false;
    }
    
    // For safety, refuse to wipe anything that is currently mounted.
#ifdef Q_OS_UNIX
    // Parse the mount table and match THIS disk against each entry's device and
    // mount point. A blanket substring search for "/" or "/boot" would match the
    // root/boot lines present on every system and so refuse every wipe - which is
    // why a plain regular file could never be wiped before.
    QProcess process;
    process.start("mount", QStringList());
    process.waitForFinished();
    const QString mountOutput = QString::fromUtf8(process.readAllStandardOutput());
    const QString canonicalPath = QFileInfo(diskPath).canonicalFilePath();

    const QStringList mountLines = mountOutput.split('\n', Qt::SkipEmptyParts);
    for (const QString& line : mountLines) {
        // Each line looks like: "DEVICE on MOUNTPOINT type FSTYPE (opts)".
        const int onIdx = line.indexOf(" on ");
        if (onIdx < 0) continue;
        const int typeIdx = line.indexOf(" type ", onIdx + 4);
        if (typeIdx < 0) continue;
        const QString device = line.left(onIdx).trimmed();
        const QString mountPoint = line.mid(onIdx + 4, typeIdx - (onIdx + 4)).trimmed();

        // Match the target by exact path, by its canonical path, or - for a
        // whole-disk target like /dev/sda whose partition /dev/sda1 is mounted -
        // by device prefix.
        const bool matchesDevice =
            device == diskPath ||
            (!canonicalPath.isEmpty() && device == canonicalPath) ||
            (diskPath.startsWith("/dev/") && device.startsWith(diskPath));
        const bool matchesMount =
            mountPoint == diskPath ||
            (!canonicalPath.isEmpty() && mountPoint == canonicalPath);

        if (matchesDevice || matchesMount) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("Refusing to wipe mounted disk or partition: %1 (mounted at %2)")
                    .arg(diskPath).arg(mountPoint));
            return false;
        }
    }
#elif defined(Q_OS_WIN)
    // On Windows, refuse to wipe C: drive and system partitions
    if (diskPath.startsWith("C:", Qt::CaseInsensitive) || 
        diskPath.contains("\\windows\\", Qt::CaseInsensitive)) {
        
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Refusing to wipe system disk: %1").arg(diskPath));
        return false;
    }
#endif
    
    // Open the disk for writing
    QFile diskFile(diskPath);
    QIODevice::OpenMode openMode = QIODevice::WriteOnly;
    
    // Also open for reading if verification is enabled
    if (verifyWipe) {
        openMode |= QIODevice::ReadOnly;
    }
    
    if (!diskFile.open(openMode)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Failed to open disk for wiping: %1 (Error: %2)")
            .arg(diskPath).arg(diskFile.errorString()));
        return false;
    }
    
    // Get the disk size
    qint64 diskSize = diskFile.size();
    
    // If we can't determine size, try to get it another way
    if (diskSize <= 0) {
        QStorageInfo storageInfo(diskPath);
        if (storageInfo.isValid()) {
            diskSize = storageInfo.bytesTotal();
        }
    }
    
    // If we still don't have a valid size, default to a reasonable value for testing
    if (diskSize <= 0) {
        SECURE_LOG(WARNING, "EncryptionEngine", 
            QString("Could not determine disk size for %1, using default size").arg(diskPath));
        diskSize = 4ULL * 1024 * 1024 * 1024; // Assume 4GB
    }
    
    // Determine the wipe pattern based on the number of passes
    WipePattern pattern;
    
    if (passes >= 35) {
        pattern = WipePattern::GUTMANN; // Gutmann 35-pass method
    } else if (passes >= 7) {
        pattern = WipePattern::DOD_FULL; // DoD 7-pass method
    } else if (passes >= 3) {
        pattern = WipePattern::DOD_SHORT; // DoD 3-pass method
    } else {
        pattern = WipePattern::ZEROS; // Single pass of zeros
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Wiping disk %1 (%2 bytes) with %3 passes")
        .arg(diskPath).arg(diskSize).arg(passes));
    
    try {
        // Execute multiple passes of writing
        for (int pass = 0; pass < passes; pass++) {
            SECURE_LOG(INFO, "EncryptionEngine", 
                QString("Starting wipe pass %1/%2 for %3").arg(pass + 1).arg(passes).arg(diskPath));
            
            // For each pass, determine the specific pattern
            WipePattern currentPattern;
            
            if (pattern == WipePattern::DOD_SHORT) {
                // DoD short method: Zeros, Ones, Random
                currentPattern = static_cast<WipePattern>(pass % 3);
            } else if (pattern == WipePattern::DOD_FULL) {
                // DoD full method: More complex pattern sequence
                if (pass == 0 || pass == 6) {
                    currentPattern = WipePattern::RANDOM;
                } else if (pass % 2 == 0) {
                    currentPattern = WipePattern::ZEROS;
                } else {
                    currentPattern = WipePattern::ONES;
                }
            } else if (pattern == WipePattern::GUTMANN) {
                // Gutmann method: Complex 35-pass pattern
                if (pass < 4 || pass >= 31) {
                    currentPattern = WipePattern::RANDOM;
                } else {
                    // Alternate between various patterns
                    currentPattern = static_cast<WipePattern>(pass % 3);
                }
            } else {
                // Simple pattern: Zeros, Ones, or Random
                currentPattern = pattern;
            }
            
            // Execute the current pass
            bool passSuccess = writeWipePattern(diskFile, currentPattern, diskSize, pass, passes);
            
            if (!passSuccess) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                    QString("Failed during wipe pass %1/%2 for disk: %3")
                    .arg(pass + 1).arg(passes).arg(diskPath));
                diskFile.close();
                return false;
            }
            
            // Verify the pattern for certain passes if verification is enabled
            if (verifyWipe && (pass == passes - 1 || currentPattern != WipePattern::RANDOM)) {
                SECURE_LOG(INFO, "EncryptionEngine", 
                    QString("Verifying wipe pass %1/%2 for disk: %3")
                    .arg(pass + 1).arg(passes).arg(diskPath));
                
                bool verifySuccess = verifyWipePattern(diskFile, currentPattern, diskSize);
                
                if (!verifySuccess) {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                        QString("Verification failed for wipe pass %1/%2 on disk: %3")
                        .arg(pass + 1).arg(passes).arg(diskPath));
                    diskFile.close();
                    return false;
                }
            }
        }
        
        // Final verification after all passes
        if (verifyWipe) {
            // Use a consistent pattern for final verification (zeros)
            SECURE_LOG(INFO, "EncryptionEngine", 
                QString("Performing final wipe verification for disk: %1").arg(diskPath));
            
            bool finalPass = writeWipePattern(diskFile, WipePattern::ZEROS, diskSize, 0, 1);
            
            if (!finalPass) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                    QString("Failed during final zero pass for disk: %1").arg(diskPath));
                diskFile.close();
                return false;
            }
            
            bool finalVerify = verifyWipePattern(diskFile, WipePattern::ZEROS, diskSize);
            
            if (!finalVerify) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                    QString("Final verification failed for disk: %1").arg(diskPath));
                diskFile.close();
                return false;
            }
        }
        
        diskFile.close();
        
        SECURE_LOG(INFO, "EncryptionEngine", 
            QString("Successfully completed secure wipe of disk: %1 (%2 passes)")
            .arg(diskPath).arg(passes));
        
        return true;
    }
    catch (const std::exception& e) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Exception during secure disk wipe: %1").arg(e.what()));
        
        if (diskFile.isOpen()) {
            diskFile.close();
        }
        
        return false;
    }
}

// Public method to securely wipe a partition
bool EncryptionEngine::secureWipePartition(const QString& partitionPath, int passes)
{
    // For partitions, we want to wipe with verification
    return secureWipeDisk(partitionPath, passes, true);
}