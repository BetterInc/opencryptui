#include "cryptoprovider.h"
#include <QCoreApplication>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include "logging/secure_logger.h"

#ifdef __x86_64__
#include <cpuid.h>
#endif

OpenSSLProvider::OpenSSLProvider()
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Check for hardware acceleration
    m_aesNiSupported = checkHardwareSupport();
    SECURE_LOG(DEBUG, "OpenSSLProvider", QString("AES-NI %1").arg(m_aesNiSupported ? "supported" : "not supported"));
}

OpenSSLProvider::~OpenSSLProvider()
{
    // Clean up OpenSSL (though the main application should also do this)
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray OpenSSLProvider::deriveKey(const QByteArray &password, const QByteArray &salt,
                                      const QString &kdf, int iterations, int keySize)
{
    SECURE_LOG(DEBUG, "OpenSSLProvider", QString("Deriving key with KDF: %1, Iterations: %2, Key Size: %3")
             .arg(kdf).arg(iterations).arg(keySize));

    QByteArray key(keySize, 0);
    bool success = false;

    if (kdf == "PBKDF2")
    {
        // PBKDF2 key derivation using SHA-512 for government-level security
        success = PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                                    reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
                                    iterations, EVP_sha512(), key.size(),
                                    reinterpret_cast<unsigned char *>(key.data())) != 0;
    }
    else if (kdf == "Scrypt")
    {
        // Check if Scrypt is available in this OpenSSL build
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

        if (pctx == NULL)
        {
            SECURE_LOG(WARNING, "OpenSSLProvider", "Scrypt not available");
            OPENSSL_cleanse(key.data(), key.size());
            return QByteArray();
        }
        else
        {
            // Use OpenSSL's Scrypt if available
            if (EVP_PKEY_derive_init(pctx) <= 0)
            {
                EVP_PKEY_CTX_free(pctx);
                SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "EVP_PKEY_derive_init failed");
                OPENSSL_cleanse(key.data(), key.size());
                return QByteArray();
            }

            // Set Scrypt parameters
            if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_SALT,
                                  salt.size(), (void *)salt.data()) <= 0)
            {
                EVP_PKEY_CTX_free(pctx);
                SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to set salt");
                OPENSSL_cleanse(key.data(), key.size());
                return QByteArray();
            }

            // N - CPU/memory cost parameter
            uint64_t N = iterations > 0 ? iterations : 16384; // Default if iterations not specified
            if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, N, NULL) <= 0)
            {
                EVP_PKEY_CTX_free(pctx);
                SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to set N parameter");
                OPENSSL_cleanse(key.data(), key.size());
                return QByteArray();
            }

            // r - block size parameter
            uint64_t r = 8;
            if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_R, r, NULL) <= 0)
            {
                EVP_PKEY_CTX_free(pctx);
                SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to set r parameter");
                OPENSSL_cleanse(key.data(), key.size());
                return QByteArray();
            }

            // p - parallelization parameter
            uint64_t p = 1;
            if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_P, p, NULL) <= 0)
            {
                EVP_PKEY_CTX_free(pctx);
                SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to set p parameter");
                OPENSSL_cleanse(key.data(), key.size());
                return QByteArray();
            }

            // Perform key derivation
            size_t keyLen = key.size();
            success = EVP_PKEY_derive(pctx, reinterpret_cast<unsigned char *>(key.data()), &keyLen) > 0;

            EVP_PKEY_CTX_free(pctx);
        }
    }
    else
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", QString("Unsupported KDF specified: %1").arg(kdf));
        OPENSSL_cleanse(key.data(), key.size());
        return QByteArray();
    }

    if (!success)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", QString("%1 key derivation failed").arg(kdf));
        OPENSSL_cleanse(key.data(), key.size());
        return QByteArray();
    }

    return key;
}

bool OpenSSLProvider::encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                              const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    const EVP_CIPHER *cipher = getCipher(algorithm);
    if (!cipher)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", QString("Invalid algorithm: %1").arg(algorithm));
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to create EVP_CIPHER_CTX");
        return false;
    }

    // Determine if this is an AEAD cipher
    int cipherMode = EVP_CIPHER_mode(cipher);
    bool isAEADMode = (cipherMode == EVP_CIPH_GCM_MODE ||
                       cipherMode == EVP_CIPH_CCM_MODE ||
                       EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);

    // Debug
    SECURE_LOG(DEBUG, "OpenSSLProvider", 
              QString("Encrypting with %1 %2 %3")
              .arg(algorithm)
              .arg(isAEADMode ? "(AEAD mode)" : "(Standard mode)")
              .arg(useAuthentication ? "with authentication" : "without authentication"));

    // For AEAD ciphers or when useAuthentication is true
    bool result;
    if (isAEADMode || useAuthentication)
    {
        result = performAuthenticatedEncryption(ctx, cipher, key, iv, inputFile, outputFile);
    }
    else
    {
        result = performStandardEncryption(ctx, cipher, key, iv, inputFile, outputFile);
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

bool OpenSSLProvider::decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                              const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    const EVP_CIPHER *cipher = getCipher(algorithm);
    if (!cipher)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", QString("Invalid algorithm: %1").arg(algorithm));
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to create EVP_CIPHER_CTX");
        return false;
    }

    // Determine if this is an AEAD cipher
    int cipherMode = EVP_CIPHER_mode(cipher);
    bool isAEADMode = (cipherMode == EVP_CIPH_GCM_MODE ||
                       cipherMode == EVP_CIPH_CCM_MODE ||
                       EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);

    // Debug
    SECURE_LOG(DEBUG, "OpenSSLProvider",
              QString("Decrypting with %1 %2 %3")
              .arg(algorithm)
              .arg(isAEADMode ? "(AEAD mode)" : "(Standard mode)")
              .arg(useAuthentication ? "with authentication" : "without authentication"));
    
    // For AEAD ciphers or when useAuthentication is true
    bool result;
    if (isAEADMode || useAuthentication)
    {
        result = performAuthenticatedDecryption(ctx, cipher, key, iv, inputFile, outputFile);
    }
    else
    {
        result = performStandardDecryption(ctx, cipher, key, iv, inputFile, outputFile);
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

QByteArray OpenSSLProvider::generateRandomBytes(int size)
{
    QByteArray bytes(size, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()), size) != 1)
    {
        SECURE_LOG(ERROR_LEVEL, "OpenSSLProvider", "Failed to generate random bytes");
        return QByteArray();
    }
    return bytes;
}

bool OpenSSLProvider::isHardwareAccelerationSupported()
{
    return m_aesNiSupported;
}

QStringList OpenSSLProvider::supportedCiphers()
{
    // Camellia-256-CBC and Camellia-128-CBC removed: not on the CNSA 2.0 approved list
    // and CBC mode provides no built-in authentication (AEAD).
    return {
        "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
        "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-192-CBC"};
}

QStringList OpenSSLProvider::supportedKDFs()
{
    QStringList kdfs = {"PBKDF2"};

    // Check if Scrypt is available
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    if (pctx != NULL)
    {
        kdfs.append("Scrypt");
        EVP_PKEY_CTX_free(pctx);
    }

    return kdfs;
}

bool OpenSSLProvider::checkHardwareSupport()
{
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
    {
        return (ecx & bit_AES) != 0;
    }
#endif
    return false;
}

const EVP_CIPHER *OpenSSLProvider::getCipher(const QString &algorithm)
{
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
    // Camellia-256-CBC and Camellia-128-CBC intentionally omitted (not CNSA 2.0 approved).
    return nullptr;
}

// performStandardEncryption / performStandardDecryption moved to
//   src/opensslprovider_standard.cpp
// performAuthenticatedEncryption / performAuthenticatedDecryption moved to
//   src/opensslprovider_aead.cpp
