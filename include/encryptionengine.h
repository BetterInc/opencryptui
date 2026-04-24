// encryptionengine.h
#ifndef ENCRYPTIONENGINE_H
#define ENCRYPTIONENGINE_H

#include <QString>
#include <QFile>
#include <QStringList>
#include <QDateTime>
#include <QMutex>
#include <vector>
#include <memory>
#include <cstring> // For memset
#include <cmath> // For std::abs

// Forward declarations for OpenSSL types
struct evp_cipher_st;
typedef struct evp_cipher_st EVP_CIPHER;
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

#include "cryptoprovider.h"
#include "encryptionengine_diskops.h"

class EncryptionEngine
{
public:
    // Structure to hold entropy test results
    struct EntropyTestResult {
        bool passed;
        QString testName;
        QString details;
        double bitFrequency = 0.5;
        double runsValue = 1.0;
        double serialCorrelation = 0.0;
    };
    
    EncryptionEngine();
    ~EncryptionEngine();

    // Provider selection methods
    void setProvider(const QString& providerName);
    QString currentProvider() const;
    QStringList availableProviders() const;

    bool encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    
    // Secure deletion methods
    bool secureDeleteFile(const QString& filePath, int passes = 3);
    bool secureDeletePlaintext(const QString& plaintextFilePath);
    bool scrubFileInode(const QString& filePath);
    
    // Security policy methods
    bool verifyOutputPathSecurity(const QString& filePath);
    bool checkAndFixFilePermissions(const QString& filePath, QFileDevice::Permissions desiredPermissions);
    
    // Disk encryption methods
    bool encryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    bool decryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    
    // Disk wiping methods
    bool secureWipeDisk(const QString& diskPath, int passes = 3, bool verifyWipe = true);
    bool secureWipePartition(const QString& partitionPath, int passes = 3);
    enum class WipePattern {
        ZEROS,
        ONES,
        RANDOM,
        DOD_SHORT, // DoD 5220.22-M short (3 passes)
        DOD_FULL,  // DoD 5220.22-M full (7 passes)
        GUTMANN    // Peter Gutmann's 35-pass method
    };
    
    // Hidden volume support - encrypt/decrypt specific section of disk
    bool encryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize);
    bool decryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize);

    bool compressFolder(const QString& folderPath, const QString& outputFilePath);
    bool decompressFolder(const QString& filePath, const QString& outputFolderPath);

    // Removed getLastIv method for security reasons

    bool isHardwareAccelerationSupported() const;

    QByteArray deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
    QByteArray deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize);

    // Secure random number generation methods
    QByteArray generateSecureSalt(int size = 32);
    QByteArray generateSecureIV(int size = 16);
    QByteArray generateSecureRandomBytes(int size, bool isSecurityCritical = true);
    
    // Entropy health monitoring methods
    QString getEntropyHealthStatus() const;
    int getEntropyHealthScore() const;
    bool isHardwareRngAvailable() const;
    int getBitDistribution() const; 
    int getEntropyEstimate() const;
    QDateTime getLastEntropyTestTime() const;
    EntropyTestResult performEntropyTest(int sampleSize = 1024);

    const EVP_CIPHER* getCipher(const QString& algorithm);
    QStringList supportedCiphers() const;
    QStringList supportedKDFs() const;

private:
    // Removed lastIv storage for security reasons

    // -------------------------------------------------------------------------
    // OCUI file-format v2 header (Fix #2)
    // On-disk layout:
    //   [magic "OCUI" 4][format_version 1][algorithm_id 1][kdf_id 1][reserved 1]
    //   [iterations uint32 BE 4]   -- total header = 12 bytes
    //   [salt 32][iv N][ciphertext][sig trailer]
    //
    // The entire prefix (including algorithm_id / kdf_id / iterations) is covered
    // by the Ed25519 signature because generateDigitalSignature seeks to 0 and
    // reads the whole file before the trailer is appended.
    // -------------------------------------------------------------------------
    static constexpr quint32 OCUI_MAGIC       = 0x4F435549u; // "OCUI"
    static constexpr quint8  OCUI_FORMAT_VER  = 2;
    static constexpr int     OCUI_HEADER_SIZE = 12; // magic(4)+ver(1)+alg(1)+kdf(1)+rsv(1)+iters(4)

    // Algorithm IDs
    static constexpr quint8 ALG_ID_AES256_GCM        = 0x01;
    static constexpr quint8 ALG_ID_CHACHA20_POLY1305  = 0x02;
    static constexpr quint8 ALG_ID_AES256_CTR         = 0x03;
    static constexpr quint8 ALG_ID_AES256_CBC         = 0x04;
    static constexpr quint8 ALG_ID_AES128_GCM         = 0x05;
    static constexpr quint8 ALG_ID_AES128_CTR         = 0x06;
    static constexpr quint8 ALG_ID_AES192_GCM         = 0x07;
    static constexpr quint8 ALG_ID_AES192_CTR         = 0x08;
    static constexpr quint8 ALG_ID_AES128_CBC         = 0x09;
    static constexpr quint8 ALG_ID_AES192_CBC         = 0x0A;
    static constexpr quint8 ALG_ID_CAMELLIA256_CBC     = 0x0B;
    static constexpr quint8 ALG_ID_CAMELLIA128_CBC     = 0x0C;
    static constexpr quint8 ALG_ID_UNKNOWN            = 0xFF;

    // KDF IDs
    static constexpr quint8 KDF_ID_PBKDF2  = 0x01;
    static constexpr quint8 KDF_ID_ARGON2  = 0x02;
    static constexpr quint8 KDF_ID_SCRYPT  = 0x03;
    static constexpr quint8 KDF_ID_UNKNOWN = 0xFF;

    // Helpers
    static quint8 algorithmId(const QString& algorithm);
    static QString algorithmFromId(quint8 id);
    static quint8 kdfId(const QString& kdf);
    static QString kdfFromId(quint8 id);
    static int ivSizeForAlgorithm(const QString& algorithm); // Fix #7

    // Vector to hold unique pointers to providers
    std::vector<std::unique_ptr<CryptoProvider>> m_providers;
    
    // Pointer to the current active provider
    CryptoProvider* m_currentProvider;
    QString m_currentProviderName;
    
    // Initialize all available providers
    void initializeProviders();

    // Key derivation helper methods
    QByteArray readKeyfile(const QString& keyfilePath);
    QByteArray performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize);
    
    // NEW: Secure iteration calculation
    int calculateSecureIterations(const QString& kdf, int requestedIterations);
    
    // Encryption/decryption operations
    bool cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths);
    
    // OpenSSL-specific encryption/decryption methods
    bool performStandardEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    
    // Additional internal methods
    bool checkHardwareSupport();
    
    // Optional helper for retrieving a provider by name
    CryptoProvider* findProvider(const QString& providerName);
    
    // Tamper-evidence and digital signature methods
    QByteArray generateDigitalSignature(QFile& inputFile, const QByteArray& masterKey);
    void appendSignature(QFile& outputFile, const QByteArray& signature);
    bool verifySignature(QFile& inputFile, const QByteArray& masterKey, QByteArray& storedSignature);
    quint32 calculateCRC32(const QByteArray& data);

    // Fix #3: HKDF-based key separation. Derives encryption_key (32 B) and
    // signing_seed (32 B) from a 64-byte master via libsodium crypto_kdf_derive_from_key.
    // master is zeroized inside.
    static bool deriveSubkeys(QByteArray& master,
                              QByteArray& encryptionKey,
                              QByteArray& signingKey);
    
    // Hardware RNG support
    bool checkHardwareRngSupport();
    bool getHardwareRandomBytes(char* buffer, int size);
#ifdef __x86_64__
    bool getRdrandBytes(char* buffer, int size);
#endif

    // Entropy testing methods
    EntropyTestResult testEntropyQuality(const QByteArray& data);
    double testFrequency(const QByteArray& data);
    double testRuns(const QByteArray& data);
    double testSerialCorrelation(const QByteArray& data);
    
    // Entropy health monitoring
    void updateEntropyHealthMetrics(const EntropyTestResult& result);
    void hashWhitenData(const QByteArray& input, QByteArray& output);
    
    // Disk wiping helpers
    bool writeWipePattern(QFile& diskFile, WipePattern pattern, qint64 size, int passNumber, int totalPasses);
    bool verifyWipePattern(QFile& diskFile, WipePattern pattern, qint64 size);
    
    // Entropy health status metrics
    mutable QMutex m_entropyMetricsMutex;
    QString m_entropyHealthStatus = "Unknown";
    int m_entropyHealthScore = 0; 
    bool m_hardwareRngAvailable = false;
    int m_bitDistribution = 50;
    int m_entropyEstimate = 0;
    QDateTime m_lastEntropyTestTime;
};

#endif // ENCRYPTIONENGINE_H
