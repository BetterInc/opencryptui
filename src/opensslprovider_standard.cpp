// Standard (non-AEAD) cipher path for OpenSSLProvider — AES-CBC, AES-CTR,
// and any mode that doesn't produce a built-in authentication tag.
// Split out of opensslprovider.cpp so that file can stay focused on the
// public API and the AEAD path lives next to its own tag-handling code.
// No behaviour change.
#include "cryptoprovider.h"
#include <openssl/evp.h>
#include "logging/secure_logger.h"

bool OpenSSLProvider::performStandardEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                                const QByteArray &key, const QByteArray &iv,
                                                QFile &inputFile, QFile &outputFile)
{
    if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_EncryptInit_ex failed");
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
            SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_EncryptUpdate failed");
            return false;
        }
        outputFile.write(outBuf.data(), outLen);
    }

    if (1 != EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char *>(outBuf.data()), &outLen))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_EncryptFinal_ex failed");
        return false;
    }
    outputFile.write(outBuf.data(), outLen);

    return true;
}

bool OpenSSLProvider::performStandardDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                                const QByteArray &key, const QByteArray &iv,
                                                QFile &inputFile, QFile &outputFile)
{
    SECURE_LOG(DEBUG, "OpenSSLProvider", "Starting standard decryption process");

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr,
                            reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data())))
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_DecryptInit_ex failed");
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
            SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_DecryptUpdate failed");
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char *>(outputBuffer.data()), &outLen))
    {
        // Any finalization failure (padding, block alignment, etc.) is a hard error.
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider",
            "EVP_DecryptFinal_ex failed - potentially incorrect key or padding error");
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    return true;
}
