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

// IV size helper + algorithm/KDF ID <-> name tables moved to
// encryptionengine_tables.cpp so this file can focus on cryptOperation
// and the provider orchestration.

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
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Algorithm: %1, KDF: %2, iterations: %3").arg(algorithm).arg(kdf).arg(iterations));

    // Fix #2: validate that algorithm and KDF are known before touching any file.
    quint8 algId = algorithmId(algorithm);
    quint8 kId   = kdfId(kdf);
    if (algId == ALG_ID_UNKNOWN) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Unknown algorithm: %1").arg(algorithm));
        return false;
    }
    if (kId == KDF_ID_UNKNOWN) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Unknown KDF: %1").arg(kdf));
        return false;
    }

    QFile inputFile(inputPath);
    QFile outputFile(outputPath);

    if (!inputFile.open(QIODevice::ReadOnly))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open input file: %1").arg(inputPath));
        return false;
    }

    // ReadWrite (not WriteOnly) so the encrypt path can re-read the ciphertext
    // it just wrote in order to sign it before appending the trailer.
    if (!outputFile.open(QIODevice::ReadWrite | QIODevice::Truncate))
    {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Failed to open output file: %1").arg(outputPath));
        return false;
    }

    // masterKey holds the raw KDF output (up to 64 bytes for Argon2/Scrypt with
    // EVP_MAX_KEY_LENGTH = 64).  We split it into encKey (32 B) + sigKey (32 B)
    // via HKDF-like key separation in deriveSubkeys (Fix #3).
    QByteArray masterKey;
    QByteArray encKey;
    QByteArray sigKey;

    bool success = false;
    auto cleanup = qScopeGuard([&]() {
        if (inputFile.isOpen())  inputFile.close();
        if (outputFile.isOpen()) outputFile.close();
        // Never leave partial plaintext (or partial ciphertext) on disk.
        if (!success) {
            QFile::remove(outputPath);
        }
        if (!masterKey.isEmpty()) sodium_memzero(masterKey.data(), masterKey.size());
        if (!encKey.isEmpty())    sodium_memzero(encKey.data(),    encKey.size());
        if (!sigKey.isEmpty())    sodium_memzero(sigKey.data(),    sigKey.size());
    });

    // Fix #7: derive proper IV size for this algorithm.
    const int ivSize = ivSizeForAlgorithm(algorithm);

    // Salt is always 32 bytes; IV size is algorithm-dependent.
    QByteArray salt(32, 0);
    QByteArray iv(ivSize, 0);

    // -----------------------------------------------------------------------
    // Fix #4: INVARIANT — salt, IV, and the OCUI header bytes are part of the
    // signed region.  generateDigitalSignature seeks to offset 0 and reads the
    // entire file before the trailer is appended, so every byte written to the
    // output before appendSignature() is called is covered by the Ed25519
    // signature.  Do NOT append additional bytes after appendSignature() or
    // move salt/IV writes to after the ciphertext — either change would silently
    // break integrity.  This comment is the explicit invariant documentation
    // requested in Fix #4.
    // -----------------------------------------------------------------------

    if (encrypt)
    {
        // -----------------------------------------------------------------
        // ENCRYPT PATH
        // -----------------------------------------------------------------
        salt = m_currentProvider->generateRandomBytes(32);
        if (salt.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to generate salt");
            return false;
        }

        iv = m_currentProvider->generateRandomBytes(ivSize);
        if (iv.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to generate IV");
            return false;
        }

        // SECURITY: do NOT log salt or IV bytes — even at DEBUG level. While
        // they aren't secret per se, logging them aids forensic reconstruction
        // and the SecureLogger redactor only catches keywords, not values.
        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Generated salt (%1 bytes) and IV (%2 bytes)").arg(salt.size()).arg(iv.size()));

        // Derive master key, then split into enc + sig sub-keys (Fix #3).
        masterKey = deriveKey(password, salt, keyfilePaths, kdf, iterations);
        if (masterKey.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Key derivation failed");
            return false;
        }
        if (!deriveSubkeys(masterKey, encKey, sigKey)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Sub-key derivation failed");
            return false;
        }
        // masterKey is zeroed inside deriveSubkeys.

        // Determine format version: AEAD ciphers use v3 (per-chunk), others use v2.
        const bool isAEADCipher = isAeadAlgorithm(algorithm);
        const quint8 fmtVer = isAEADCipher ? OCUI_FORMAT_VER_V3 : OCUI_FORMAT_VER;

        // Write OCUI header BEFORE salt/IV so it is authenticated by the signature.
        {
            QDataStream hdrOut(&outputFile);
            hdrOut.setByteOrder(QDataStream::BigEndian);
            hdrOut << quint32(OCUI_MAGIC);
            hdrOut << quint8(fmtVer);
            hdrOut << quint8(algId);
            hdrOut << quint8(kId);
            hdrOut << quint8(0); // reserved
            hdrOut << quint32(static_cast<quint32>(iterations));
        }

        if (isAEADCipher) {
            // v3 path: per-chunk AEAD framing.
            // cryptOperationV3Encrypt writes salt, base_iv, chunk framing, all chunks,
            // and the signature trailer.
            success = cryptOperationV3Encrypt(inputFile, outputFile,
                                              encKey, sigKey, salt, iv,
                                              algId, kId, iterations,
                                              algorithm, outputPath);
        } else {
            // v2 path: bulk encrypt (no per-chunk auth).
            outputFile.write(salt);
            outputFile.write(iv);

            if (!inputFile.seek(0)) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to seek input file");
                return false;
            }

            success = m_currentProvider->encrypt(inputFile, outputFile, encKey, iv, algorithm,
                                                  useHMAC || enforceIntegrity);

            if (enforceIntegrity && success) {
                outputFile.flush();
                QByteArray signature = generateDigitalSignature(outputFile, sigKey);
                if (signature.isEmpty()) {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                        "Failed to generate tamper-evidence signature");
                    success = false;
                } else {
                    appendSignature(outputFile, signature);
                }
            }
        }
    }
    else
    {
        // -----------------------------------------------------------------
        // DECRYPT PATH
        // -----------------------------------------------------------------

        // Read and validate the OCUI header (supports v2 and v3).
        quint8 fileFmtVer = 0;
        {
            quint32 magic = 0;
            quint8  fileAlgId = 0, fileKdfId = 0, reserved = 0;
            quint32 fileIterations = 0;

            QDataStream hdrIn(&inputFile);
            hdrIn.setByteOrder(QDataStream::BigEndian);
            hdrIn >> magic;
            if (magic != OCUI_MAGIC) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    "File does not have OCUI header. Old-format files must be "
                    "re-encrypted — rejecting for security.");
                return false;
            }
            hdrIn >> fileFmtVer >> fileAlgId >> fileKdfId >> reserved >> fileIterations;

            // Accept v2 and v3; reject everything else.
            if (fileFmtVer != OCUI_FORMAT_VER && fileFmtVer != OCUI_FORMAT_VER_V3) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("Unsupported OCUI format version: %1").arg(fileFmtVer));
                return false;
            }

            // v3 files must use an AEAD cipher; reject non-AEAD for v3.
            if (fileFmtVer == OCUI_FORMAT_VER_V3 && !isAeadAlgorithm(algorithm)) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    "OCUI v3 file requires an AEAD cipher (GCM or ChaCha20-Poly1305)");
                return false;
            }

            // Reject if the stored algorithm doesn't match the caller's request.
            if (fileAlgId != algId) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("Algorithm mismatch: file says %1 (%2), caller wants %3 (%4)")
                    .arg(fileAlgId).arg(algorithmFromId(fileAlgId))
                    .arg(algId).arg(algorithm));
                return false;
            }

            // Reject if the stored KDF doesn't match the caller's request.
            if (fileKdfId != kId) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("KDF mismatch: file says %1 (%2), caller wants %3 (%4)")
                    .arg(fileKdfId).arg(kdfFromId(fileKdfId))
                    .arg(kId).arg(kdf));
                return false;
            }

            // Use the iteration count stored in the file, not the caller's value,
            // so an attacker cannot request fewer iterations.
            iterations = static_cast<int>(fileIterations);

            // Enforce the floor independently of calculateSecureIterations so
            // we never silently accept a file encrypted with a weak KDF.
            if (kId == KDF_ID_PBKDF2 && iterations < 600000) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("PBKDF2 iteration count in file (%1) is below the 600 000 "
                            "floor — rejecting.").arg(iterations));
                return false;
            }

            SECURE_LOG(DEBUG, "EncryptionEngine",
                QString("OCUI v%1 header OK: alg=%2 kdf=%3 iters=%4")
                .arg(fileFmtVer).arg(algorithm).arg(kdf).arg(iterations));
        }

        // Read salt and IV from the file (after the OCUI header).
        if (inputFile.read(salt.data(), salt.size()) != salt.size()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read salt");
            return false;
        }
        if (inputFile.read(iv.data(), iv.size()) != iv.size()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to read IV");
            return false;
        }

        // SECURITY: redacted — see comment at the encrypt-side logging above.
        SECURE_LOG(DEBUG, "EncryptionEngine", QString("Read salt (%1 bytes) and IV (%2 bytes)").arg(salt.size()).arg(iv.size()));

        // Derive master key, then split into enc + sig sub-keys (Fix #3).
        masterKey = deriveKey(password, salt, keyfilePaths, kdf, iterations);
        if (masterKey.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Key derivation failed");
            return false;
        }
        if (!deriveSubkeys(masterKey, encKey, sigKey)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Sub-key derivation failed");
            return false;
        }

        if (fileFmtVer == OCUI_FORMAT_VER_V3) {
            // v3 path: signature-first, then per-chunk AEAD.
            // inputFile is positioned just after base_iv (i.e. at chunk_size field).
            success = cryptOperationV3Decrypt(inputFile, outputFile,
                                              encKey, sigKey, salt, iv,
                                              algorithm, inputPath);
        } else {
            // v2 path: bulk decrypt (original logic).
            qint64 decryptionStartPos = static_cast<qint64>(OCUI_HEADER_SIZE) + salt.size() + iv.size();
            qint64 signatureSize = 0;
            bool hasSignature = false;
            bool validSignature = true;
            QByteArray storedSignature;

            if (enforceIntegrity) {
                QFile sigCheckFile(inputPath);
                if (sigCheckFile.open(QIODevice::ReadOnly)) {
                    hasSignature = sigCheckFile.size() > (decryptionStartPos + 64);
                    if (hasSignature) {
                        sigCheckFile.seek(sigCheckFile.size() - 12);
                        QDataStream in(&sigCheckFile);
                        in.setByteOrder(QDataStream::BigEndian);
                        quint32 magic; in >> magic;
                        if (magic == 0x5349475F) { // "SIG_"
                            quint32 sigLength; in >> sigLength;
                            if (sigLength > 0 && sigLength < static_cast<quint32>(sigCheckFile.size() - decryptionStartPos - 12)) {
                                signatureSize = static_cast<qint64>(sigLength) + 12;
                                qint64 savePos = inputFile.pos();
                                validSignature = verifySignature(inputFile, sigKey, storedSignature);
                                inputFile.seek(savePos);
                                if (validSignature) {
                                    SECURE_LOG(DEBUG, "EncryptionEngine", "Valid signature found and verified");
                                } else {
                                    SECURE_LOG(WARNING, "EncryptionEngine", "Digital signature validation failed");
                                }
                            } else {
                                hasSignature = false;
                                SECURE_LOG(WARNING, "EncryptionEngine", "Invalid signature length");
                            }
                        } else {
                            hasSignature = false;
                            SECURE_LOG(DEBUG, "EncryptionEngine", "No SIG_ marker found");
                        }
                    }
                    sigCheckFile.close();
                }
            }

            if (hasSignature && !validSignature && enforceIntegrity) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    "Integrity check failed: digital signature did not verify — aborting decryption");
                return false;
            }

            // Seek to the start of ciphertext.
            inputFile.seek(decryptionStartPos);

            // v2 AEAD ciphers have no HMAC (built-in auth).
            bool isAEADCipher = isAeadAlgorithm(algorithm);
            if (isAEADCipher) {
                useHMAC = false;
            }

            if (hasSignature && signatureSize > 0) {
                qint64 encryptedSize = inputFile.size() - decryptionStartPos - signatureSize;
                if (encryptedSize > 0) {
                    SECURE_LOG(DEBUG, "EncryptionEngine",
                        "Extracting encrypted data without signature: " + QString::number(encryptedSize) + " bytes");

                    QString secureDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
                    QDir().mkpath(secureDir);
                    QTemporaryFile tempFile(secureDir + QDir::separator() + "opencryptui_XXXXXX");
                    tempFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);

                    if (tempFile.open()) {
                        inputFile.seek(decryptionStartPos);
                        QByteArray buffer(4096, 0);
                        qint64 totalBytesRead = 0;
                        while (totalBytesRead < encryptedSize) {
                            qint64 bytesToRead = qMin(encryptedSize - totalBytesRead, static_cast<qint64>(buffer.size()));
                            qint64 bytesRead = inputFile.read(buffer.data(), bytesToRead);
                            if (bytesRead <= 0) break;
                            tempFile.write(buffer.data(), bytesRead);
                            totalBytesRead += bytesRead;
                        }
                        tempFile.flush();

                        if (totalBytesRead == encryptedSize) {
                            tempFile.seek(0);
                            success = m_currentProvider->decrypt(tempFile, outputFile, encKey, iv, algorithm, useHMAC || enforceIntegrity);
                            SECURE_LOG(DEBUG, "EncryptionEngine", QString("Decryption %1").arg(success ? "succeeded" : "failed"));
                        } else {
                            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                                "Failed to read complete encrypted data: expected " +
                                QString::number(encryptedSize) + " bytes, got " + QString::number(totalBytesRead));
                            success = false;
                        }
                    } else {
                        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to create temporary file for decryption");
                        success = false;
                    }
                } else {
                    SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                        "Invalid encrypted data size: " + QString::number(encryptedSize));
                    success = false;
                }
            } else {
                success = m_currentProvider->decrypt(inputFile, outputFile, encKey, iv, algorithm, useHMAC || enforceIntegrity);
            }
        }
    }

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
        // SECURITY: do not log the AEAD tag value — it's an intermediate
        // crypto artifact and aids forensic reconstruction.
        SECURE_LOG(DEBUG, "EncryptionEngine",
            QString("Authentication tag computed (%1 bytes)").arg(tag.size()));
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

    // SECURITY: do not log the AEAD tag value (intermediate crypto artifact).
    SECURE_LOG(DEBUG, "EncryptionEngine",
        QString("AEAD tag read (%1 bytes)").arg(tag.size()));

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
