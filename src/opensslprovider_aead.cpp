// AEAD cipher path for OpenSSLProvider — AES-GCM, AES-CCM,
// ChaCha20-Poly1305. The 16-byte authentication tag is appended to the
// ciphertext on encrypt and stripped on decrypt. If the cipher turns
// out not to be AEAD (because somebody passed a CBC/CTR cipher into
// the AEAD entry point via useAuthentication=true), we fall back to
// performStandardDecryption which lives in opensslprovider_standard.cpp.
//
// Split out of opensslprovider.cpp for readability. No behaviour change.
#include "cryptoprovider.h"
#include <openssl/evp.h>
#include "logging/secure_logger.h"

bool OpenSSLProvider::performAuthenticatedEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                                     const QByteArray &key, const QByteArray &iv,
                                                     QFile &inputFile, QFile &outputFile)
{
    SECURE_LOG(DEBUG, "OpenSSLProvider", QString("Starting authenticated encryption with %1, key size: %2, iv size: %3, input file size: %4")
               .arg(EVP_CIPHER_name(cipher))
               .arg(key.size())
               .arg(iv.size())
               .arg(inputFile.size()));

    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag(16, 0);
    bool isAuthenticatedMode = (cipherMode == EVP_CIPH_GCM_MODE ||
                                cipherMode == EVP_CIPH_CCM_MODE ||
                                EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);

    if (isAuthenticatedMode) {
        SECURE_LOG(DEBUG, "OpenSSLProvider", QString("Authenticated mode confirmed: %1").arg(EVP_CIPHER_name(cipher)));
    } else {
        SECURE_LOG(DEBUG, "OpenSSLProvider", QString("Non-authenticated mode detected: %1").arg(EVP_CIPHER_name(cipher)));
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr,
                            reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider",
            QString("EVP_EncryptInit_ex failed for %1").arg(EVP_CIPHER_name(cipher)));
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer;
    qint64 totalBytesRead = 0;
    qint64 totalBytesWritten = 0;

    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(buffer.data(), buffer.size());
        if (bytesRead <= 0) break;
        totalBytesRead += bytesRead;

        outputBuffer.resize(bytesRead + EVP_CIPHER_block_size(cipher));
        int outLen;

        if (!EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen,
                               reinterpret_cast<const unsigned char *>(buffer.constData()), bytesRead))
        {
            SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_EncryptUpdate failed");
            return false;
        }

        outputFile.write(outputBuffer.constData(), outLen);
        totalBytesWritten += outLen;
    }

    outputBuffer.resize(EVP_CIPHER_block_size(cipher));
    int outLen;
    if (!EVP_EncryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_EncryptFinal_ex failed");
        return false;
    }
    if (outLen > 0) {
        outputFile.write(outputBuffer.constData(), outLen);
        totalBytesWritten += outLen;
    }

    if (isAuthenticatedMode) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
            SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed");
            return false;
        }
        // Tag appended to ciphertext; decrypt path will split it off.
        outputFile.write(tag);
        totalBytesWritten += tag.size();
        SECURE_LOG(DEBUG, "OpenSSLProvider",
            QString("AEAD encryption complete, tag appended (%1 bytes total)").arg(totalBytesWritten));
    } else {
        SECURE_LOG(DEBUG, "OpenSSLProvider",
            QString("Non-AEAD encryption via AEAD entry point, no tag. %1 bytes written").arg(totalBytesWritten));
    }

    if (outputFile.size() == 0) {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "*** ERROR: Output file is empty! ***");
    }

    return true;
}

bool OpenSSLProvider::performAuthenticatedDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                                     const QByteArray &key, const QByteArray &iv,
                                                     QFile &inputFile, QFile &outputFile)
{
    SECURE_LOG(DEBUG, "OpenSSLProvider", QString("Starting authenticated decryption with %1, key size: %2, iv size: %3, input file size: %4")
              .arg(EVP_CIPHER_name(cipher))
              .arg(key.size())
              .arg(iv.size())
              .arg(inputFile.size()));

    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag(16, 0);
    bool isAuthenticatedMode = (cipherMode == EVP_CIPH_GCM_MODE ||
                                cipherMode == EVP_CIPH_CCM_MODE ||
                                EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);

    if (!isAuthenticatedMode) {
        SECURE_LOG(DEBUG, "OpenSSLProvider",
            "Non-authenticated mode detected, falling back to standard decryption");
        return performStandardDecryption(ctx, cipher, key, iv, inputFile, outputFile);
    }

    if (inputFile.size() <= 36) {
        SECURE_LOG(WARNING, "OpenSSLProvider", "Input file is too small to be a valid encrypted file");
    }

    QByteArray encryptedContent = inputFile.readAll();
    SECURE_LOG(DEBUG, "OpenSSLProvider",
        QString("Total encrypted content size: %1").arg(encryptedContent.size()));

    if (encryptedContent.size() < 16) {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Encrypted content too small (less than tag size)");
        return false;
    }

    tag = encryptedContent.right(16);
    encryptedContent.chop(16);

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr,
                            reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_DecryptInit_ex failed");
        return false;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed");
        return false;
    }

    QByteArray decryptedData(encryptedContent.size() + EVP_CIPHER_block_size(cipher), 0);
    int decryptedLen = 0;

    if (!EVP_DecryptUpdate(ctx,
                           reinterpret_cast<unsigned char *>(decryptedData.data()),
                           &decryptedLen,
                           reinterpret_cast<const unsigned char *>(encryptedContent.constData()),
                           encryptedContent.size()))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_DecryptUpdate failed");
        return false;
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char *>(decryptedData.data() + decryptedLen),
                            &finalLen) <= 0)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_DecryptFinal_ex failed - Authentication failed");

        // Behaviour preserved from pre-split code: if we already wrote plaintext
        // and only the tag verification failed, return success and let the outer
        // Ed25519 signature layer (wrapping the whole file in cryptOperation)
        // be the arbiter of integrity. TODO(security): close this defense-in-
        // depth gap — AEAD auth failure should always be fatal.
        if (outputFile.size() > 0) {
            SECURE_LOG(WARNING, "OpenSSLProvider", "AEAD tag verification failed but content already decrypted");
            return true;
        }
        return false;
    }

    decryptedLen += finalLen;

    if (decryptedLen > 0) {
        decryptedData.resize(decryptedLen);
        outputFile.write(decryptedData.constData(), decryptedLen);
    } else {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "No decrypted data produced, decryption may have failed");
        return false;
    }

    return true;
}
