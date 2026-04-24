#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QTemporaryFile>
#include <QCoreApplication>
#include <QDataStream>
#include <QStandardPaths>
#include <QDir>
#include <QScopeGuard>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sodium.h>

bool EncryptionEngine::cryptOperation(const QString &inputPath, const QString &outputPath, const QString &password, const QString &algorithm, bool encrypt, const QString &kdf, int iterations, bool useHMAC, const QString &customHeader, const QStringList &keyfilePaths)
{
    if (!m_currentProvider)
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "No crypto provider set");
        return false;
    }

    // Always force integrity check (HMAC/AEAD) for government-grade security
    bool enforceIntegrity = true;
    
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Starting cryptOperation with provider: %1").arg(m_currentProviderName));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Encrypt mode: %1").arg(encrypt ? "Encryption" : "Decryption"));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Input file: %1").arg(inputPath));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Output file: %1").arg(outputPath));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Algorithm: %1").arg(algorithm));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("KDF: %1").arg(kdf));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Iterations: %1").arg(iterations));
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Use HMAC: %1").arg((useHMAC || enforceIntegrity) ? "Yes (Enforced)" : "No"));

    QFile inputFile(inputPath);
    QFile outputFile(outputPath);

    if (!inputFile.open(QIODevice::ReadOnly))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open input file: %1").arg(inputPath));
        return false;
    }

    if (!outputFile.open(QIODevice::WriteOnly))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open output file: %1").arg(outputPath));
        return false;
    }

    QByteArray key;
    bool success = false;
    auto cleanup = qScopeGuard([&]() {
        if (inputFile.isOpen()) inputFile.close();
        if (outputFile.isOpen()) outputFile.close();
        // Never leave partial plaintext (or partial ciphertext) on disk after a failed run.
        if (!success) {
            QFile::remove(outputPath);
        }
        if (!key.isEmpty()) {
            sodium_memzero(key.data(), key.size());
        }
    });

    // Generate salt and IV or read them from encrypted file
    QByteArray salt(32, 0);
    QByteArray iv(16, 0); // Most algorithms use 16 bytes

    if (encrypt)
    {
        // Use the provider's generateRandomBytes for consistency
        salt = m_currentProvider->generateRandomBytes(32);
        if (salt.isEmpty())
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to generate salt");
            return false;
        }

        iv = m_currentProvider->generateRandomBytes(16);
        if (iv.isEmpty())
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to generate IV");
            return false;
        }

        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Generated salt (hex): %1").arg(QString(salt.toHex())));
        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Generated IV (hex): %1").arg(QString(iv.toHex())));
    }
    else
    {
        // For decryption, read the salt and IV from the file
        int headerSize = 0;
        if (!customHeader.isEmpty())
        {
            headerSize = customHeader.size();
            // Ensure we're at the right position after the header
            if (!inputFile.seek(headerSize))
            {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to seek past header in input file");
                return false;
            }
        }
        else
        {
            // Ensure we're at the beginning of the file if no header
            if (!inputFile.seek(0))
            {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to seek to beginning of input file");
                return false;
            }
        }

        // Read salt
        if (inputFile.read(salt.data(), salt.size()) != salt.size())
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read salt from input file");
            return false;
        }

        // Read IV
        if (inputFile.read(iv.data(), iv.size()) != iv.size())
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read IV from input file");
            return false;
        }

        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Read salt (hex): %1").arg(QString(salt.toHex())));
        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Read IV (hex): %1").arg(QString(iv.toHex())));
    }

    // Removed storage of IV in class member for security reasons

    // Derive key using the password and keyfiles
    key = deriveKey(password, salt, keyfilePaths, kdf, iterations);

    if (key.isEmpty())
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Key derivation failed");
        return false;
    }

    // Special handling for AEAD ciphers (avoid double authentication and potental conflicts)
    bool isAEADCipher = algorithm.contains("GCM") || algorithm.contains("CCM") || 
                         algorithm.contains("ChaCha20-Poly1305");
    if (isAEADCipher) {
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("AEAD cipher detected (%1), enabling built-in authentication").arg(algorithm));
        enforceIntegrity = true;  // Always enable digital signatures for AEAD
        useHMAC = false;          // Disable separate HMAC for AEAD (they have built-in auth)
    }

    // If digital signatures or HMAC is required, ensure the file has tamper evidence
    bool needsTamperEvidence = enforceIntegrity || useHMAC;

    if (encrypt)
    {
        // Write header, salt, and IV for encryption
        if (!customHeader.isEmpty())
        {
            outputFile.write(customHeader.toUtf8());
        }
        outputFile.write(salt);
        outputFile.write(iv);

        // Reset input file position to beginning for encryption
        if (!inputFile.seek(0))
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to seek to beginning of input file before encryption");
            return false;
        }

        // Generate digital signature for tamper evidence
        QByteArray signature;
        if (enforceIntegrity) {
            // Create Ed25519 signature of the input data for tamper evidence
            signature = generateDigitalSignature(inputFile, key);
            // Reset file position for encryption
            inputFile.seek(0);
        }
        
        // Perform encryption
        success = m_currentProvider->encrypt(inputFile, outputFile, key, iv, algorithm, useHMAC || enforceIntegrity);
        
        // Append digital signature if enabled
        if (enforceIntegrity && success) {
            // Add signature and validation data to the end of the file
            appendSignature(outputFile, signature);
        }
    }
    else
    {
        // For decryption, we need to properly handle the signature that may exist at the end of the file
        QByteArray storedSignature;
        bool hasSignature = false;
        bool validSignature = true;
        
        // Save file position before signature verification
        qint64 decryptionStartPos = customHeader.size() + salt.size() + iv.size();
        qint64 signatureSize = 0;
        
        // Check if file has a signature
        if (enforceIntegrity) {
            // Create a copy of the file to examine without disturbing the original file position
            QFile signatureCheckFile(inputPath);
            if (signatureCheckFile.open(QIODevice::ReadOnly)) {
                // Check file size to see if it's large enough to have a signature
                hasSignature = signatureCheckFile.size() > (decryptionStartPos + 64); // Header + minimum content + signature
                
                if (hasSignature) {
                    // Look for signature marker at end of file
                    signatureCheckFile.seek(signatureCheckFile.size() - 12); // Magic + length + CRC
                    QDataStream in(&signatureCheckFile);
                    in.setByteOrder(QDataStream::BigEndian);
                    
                    quint32 magic;
                    in >> magic;
                    
                    if (magic == 0x5349475F) { // "SIG_"
                        // Read signature length
                        quint32 sigLength;
                        in >> sigLength;
                        
                        // Sanity check the signature length
                        if (sigLength > 0 && sigLength < signatureCheckFile.size() - decryptionStartPos - 12) {
                            signatureSize = sigLength + 12; // signature + magic + length + CRC
                            
                            // Save original position before verification
                            qint64 savePos = inputFile.pos();
                            
                            // Verify the signature if we have one
                            validSignature = verifySignature(inputFile, key, storedSignature);
                            
                            // Restore position after verification
                            inputFile.seek(savePos);
                            
                            if (validSignature) {
                                SECURE_LOG(DEBUG, "EncryptionEngine", "Valid signature found and verified");
                            } else {
                                SECURE_LOG(WARNING, "EncryptionEngine", "Digital signature validation failed - file may have been tampered with");
                            }
                        } else {
                            hasSignature = false;
                            SECURE_LOG(WARNING, "EncryptionEngine", "Invalid signature length: " + QString::number(sigLength));
                        }
                    } else {
                        hasSignature = false;
                        SECURE_LOG(DEBUG, "EncryptionEngine", "No signature marker found");
                    }
                }
                signatureCheckFile.close();
            }
        }

        // Abort before any plaintext can be written when integrity is enforced
        // and the signature did not verify. The cleanup guard removes the
        // (empty) output file so no partial plaintext is ever observable.
        if (hasSignature && !validSignature && enforceIntegrity) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                "Integrity check failed: digital signature did not verify - aborting decryption");
            return false;
        }

        // Make sure we're at the correct position for decryption
        inputFile.seek(decryptionStartPos);
        
        // Create a temporary buffer for content without signature if needed
        if (hasSignature && signatureSize > 0) {
            // Determine actual encrypted data size (without signature)
            qint64 encryptedSize = inputFile.size() - decryptionStartPos - signatureSize;
            
            if (encryptedSize > 0) {
                SECURE_LOG(DEBUG, "EncryptionEngine", "Extracting encrypted data without signature: " + 
                           QString::number(encryptedSize) + " bytes");
                
                // Create a temporary file with the proper header and encrypted content
                // Use a more secure location than default /tmp
                QString secureDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
                // Create directory if it doesn't exist
                QDir().mkpath(secureDir);
                // Create temporary file in our secure app-specific directory
                QTemporaryFile tempFile(secureDir + QDir::separator() + "opencryptui_XXXXXX");
                
                // Set restrictive permissions - only readable by current user
                tempFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
                
                if (tempFile.open()) {
                    // Read salt and IV from original file
                    inputFile.seek(customHeader.size());
                    QByteArray header = inputFile.read(salt.size() + iv.size());
                    
                    // Write header to temporary file
                    tempFile.write(header);
                    
                    // Now read and write the encrypted content without the signature
                    inputFile.seek(decryptionStartPos);
                    QByteArray buffer(4096, 0);
                    qint64 totalBytesRead = 0;
                    
                    while (totalBytesRead < encryptedSize) {
                        qint64 bytesToRead = qMin(encryptedSize - totalBytesRead, static_cast<qint64>(buffer.size()));
                        qint64 bytesRead = inputFile.read(buffer.data(), bytesToRead);
                        
                        if (bytesRead <= 0) {
                            break;
                        }
                        
                        tempFile.write(buffer.data(), bytesRead);
                        totalBytesRead += bytesRead;
                    }
                    
                    tempFile.flush();
                    
                    if (totalBytesRead == encryptedSize) {
                        // Seek to the beginning of encrypted data in the temp file (past salt and IV)
                        tempFile.seek(salt.size() + iv.size());
                        
                        // Decrypt from the temp file
                        success = m_currentProvider->decrypt(tempFile, outputFile, key, iv, algorithm, useHMAC || enforceIntegrity);
                        
                        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Decryption %1").arg(success ? "succeeded" : "failed"));
                    } else {
                        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read complete encrypted data: expected " + 
                                  QString::number(encryptedSize) + " bytes, got " + QString::number(totalBytesRead));
                        success = false;
                    }
                } else {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for decryption");
                    success = false;
                }
            } else {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Invalid encrypted data size: " + QString::number(encryptedSize));
                success = false;
            }
        } else {
            // No signature detected, do normal decryption
            success = m_currentProvider->decrypt(inputFile, outputFile, key, iv, algorithm, useHMAC || enforceIntegrity);
        }
    }

    // File close, partial-output removal, and key zeroization are handled by the cleanup guard above.
    return success;
}

bool EncryptionEngine::performStandardEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const QByteArray &key, const QByteArray &iv, QFile &inputFile, QFile &outputFile)
{
    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, 
        reinterpret_cast<const unsigned char *>(key.data()), 
        reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Standard Encryption Init failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outBuf(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen = 0;

    while (!inputFile.atEnd())
    {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (1 != EVP_EncryptUpdate(ctx, 
            reinterpret_cast<unsigned char *>(outBuf.data()), &outLen, 
            reinterpret_cast<const unsigned char *>(buffer.data()), inLen))
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Standard Encryption Update failed for cipher: %1")
                .arg(EVP_CIPHER_name(cipher)));
            return false;
        }
        outputFile.write(outBuf.data(), outLen);
    }

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, 
        reinterpret_cast<unsigned char *>(outBuf.data()), &outLen))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Standard Encryption Finalization failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }
    outputFile.write(outBuf.data(), outLen);

    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Standard Encryption completed successfully for cipher: %1")
        .arg(EVP_CIPHER_name(cipher)));

    return true;
}

bool EncryptionEngine::performStandardDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const QByteArray &key, const QByteArray &iv, QFile &inputFile, QFile &outputFile)
{
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Starting standard decryption process for cipher: %1")
        .arg(EVP_CIPHER_name(cipher)));

    // Initialize the decryption operation
    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, 
        reinterpret_cast<const unsigned char *>(key.data()), 
        reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Standard Decryption Init failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    while (!inputFile.atEnd())
    {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (!EVP_DecryptUpdate(ctx, 
            reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen, 
            reinterpret_cast<unsigned char *>(buffer.data()), inLen))
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Standard Decryption Update failed for cipher: %1")
                .arg(EVP_CIPHER_name(cipher)));
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx, 
        reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Standard Decryption Finalization failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Standard Decryption completed successfully for cipher: %1")
        .arg(EVP_CIPHER_name(cipher)));

    return true;
}

bool EncryptionEngine::performAuthenticatedEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const QByteArray &key, const QByteArray &iv, QFile &inputFile, QFile &outputFile)
{
    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag;
    bool isAuthenticatedMode = false;

    if (cipherMode == EVP_CIPH_GCM_MODE || cipherMode == EVP_CIPH_CCM_MODE ||
        EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305)
    {
        tag.resize(16);
        isAuthenticatedMode = true;
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Authenticated mode detected: %1")
            .arg(EVP_CIPHER_name(cipher)));
    }
    else
    {
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Non-authenticated mode detected: %1")
            .arg(EVP_CIPHER_name(cipher)));
    }

    // Initialize encryption operation
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, 
        reinterpret_cast<const unsigned char *>(key.data()), 
        reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Authenticated Encryption Init failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer;

    // Encrypt the data in chunks
    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(buffer.data(), buffer.size());
        if (bytesRead <= 0)
            break;

        outputBuffer.resize(bytesRead + EVP_CIPHER_block_size(cipher));
        int outLen;

        if (!EVP_EncryptUpdate(ctx, 
            reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen,
            reinterpret_cast<const unsigned char *>(buffer.constData()), bytesRead))
        {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Authenticated Encryption Update failed for cipher: %1")
                .arg(EVP_CIPHER_name(cipher)));
            return false;
        }

        outputFile.write(outputBuffer.constData(), outLen);
    }

    // Finalize the encryption
    outputBuffer.resize(EVP_CIPHER_block_size(cipher));
    int outLen;
    if (!EVP_EncryptFinal_ex(ctx, 
        reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Authenticated Encryption Finalization failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    if (outLen > 0)
    {
        outputFile.write(outputBuffer.constData(), outLen);
    }

    // Get the tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Failed to get authentication tag for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    // Append the tag to the end of the file
    outputFile.write(tag);

    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Authenticated Encryption completed successfully"));
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Encrypted file size: %1 bytes").arg(outputFile.size()));

    if (isAuthenticatedMode)
    {
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Authentication tag: %1").arg(QString(tag.toHex())));
    }

    return true;
}

bool EncryptionEngine::performAuthenticatedDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const QByteArray &key, const QByteArray &iv, QFile &inputFile, QFile &outputFile)
{
    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag;
    bool isAuthenticatedMode = false;

    if (cipherMode == EVP_CIPH_GCM_MODE || cipherMode == EVP_CIPH_CCM_MODE ||
        EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305)
    {
        tag.resize(16);
        isAuthenticatedMode = true;
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Authenticated mode detected: %1")
            .arg(EVP_CIPHER_name(cipher)));
    }
    else
    {
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Non-authenticated mode detected: %1")
            .arg(EVP_CIPHER_name(cipher)));
    }

    // Read the entire encrypted content
    QByteArray encryptedContent = inputFile.readAll();

    // The last 16 bytes should be the tag
    if (encryptedContent.size() < 16)
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Encrypted content is too short");
        return false;
    }

    tag = encryptedContent.right(16);
    encryptedContent.chop(16); // Remove the tag from the encrypted content

    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Tag read for decryption: %1").arg(QString(tag.toHex())));

    // Initialize decryption operation
    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, 
        reinterpret_cast<const unsigned char *>(key.data()), 
        reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Authenticated Decryption Init failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    QByteArray outputBuffer(encryptedContent.size() + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    // Decrypt the data
    if (!EVP_DecryptUpdate(ctx, 
        reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen,
        reinterpret_cast<const unsigned char *>(encryptedContent.constData()), 
        encryptedContent.size()))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Authenticated Decryption Update failed for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    // Set the expected tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Failed to set authentication tag for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    int tmpLen;
    // Finalize the decryption and check the tag
    if (!EVP_DecryptFinal_ex(ctx, 
        reinterpret_cast<unsigned char *>(outputBuffer.data()) + outLen, &tmpLen))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Authenticated Decryption Finalization failed - authentication error for cipher: %1")
            .arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    outLen += tmpLen;
    outputFile.write(outputBuffer.constData(), outLen);

    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Authenticated Decryption completed successfully for cipher: %1")
        .arg(EVP_CIPHER_name(cipher)));

    return true;
}

const EVP_CIPHER *EncryptionEngine::getCipher(const QString &algorithm)
{
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Retrieving cipher for algorithm: %1").arg(algorithm));

    if (algorithm == "AES-256-GCM")
        return EVP_aes_256_gcm();
    if (algorithm == "ChaCha20-Poly1305")
        return EVP_chacha20_poly1305();
    if (algorithm == "AES-256-CTR")
        return EVP_aes_256_ctr();
    if (algorithm == "AES-256-CBC")
        return EVP_aes_256_cbc();
    if (algorithm == "AES-128-GCM")
        return EVP_aes_128_gcm();
    if (algorithm == "AES-128-CTR")
        return EVP_aes_128_ctr();
    if (algorithm == "AES-192-GCM")
        return EVP_aes_192_gcm();
    if (algorithm == "AES-192-CTR")
        return EVP_aes_192_ctr();
    if (algorithm == "AES-128-CBC")
        return EVP_aes_128_cbc();
    if (algorithm == "AES-192-CBC")
        return EVP_aes_192_cbc();
    if (algorithm == "Camellia-256-CBC")
        return EVP_camellia_256_cbc();
    if (algorithm == "Camellia-128-CBC")
        return EVP_camellia_128_cbc();

    SECURE_LOG(WARNING, "EncryptionEngine", 
        QString("Unsupported cipher algorithm: %1").arg(algorithm));

    return nullptr; // Ensure this correctly returns nullptr for unsupported ciphers
}
