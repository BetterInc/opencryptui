// encryptionengine.h
#ifndef ENCRYPTIONENGINE_H
#define ENCRYPTIONENGINE_H

#include <QString>
#include <QFile>
#include <QStringList>
#include <QVector>
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

    // QString password overloads - convenience wrappers for callers that
    // already hold the password as a QString (tests, legacy code, the
    // benchmark path). They allocate a SecureString, copy in the UTF-8
    // bytes, and delegate to the SecureString overload below. The
    // intermediate QString remains in the caller's heap; the engine never
    // creates its own QString copy.
    bool encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());

    // SecureString password overloads - the real implementations. The
    // mlocked + zero-on-destroy SecureString flows through cryptOperation
    // and into deriveKey without spawning extra QString copies. Use these
    // from the worker / UI layer where the password is long-lived and
    // sensitive.
    bool encryptFile(const QString& filePath, const class SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFile(const QString& filePath, const class SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());

    // Secure deletion methods
    bool secureDeleteFile(const QString& filePath, int passes = 3);
    bool secureDeletePlaintext(const QString& plaintextFilePath);
    bool scrubFileInode(const QString& filePath);
    
    // Security policy methods
    bool verifyOutputPathSecurity(const QString& filePath);
    bool checkAndFixFilePermissions(const QString& filePath, QFileDevice::Permissions desiredPermissions);
    
    // Disk encryption methods (QString wrappers + SecureString reals - see file ops above).
    bool encryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    bool decryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    bool encryptDisk(const QString& diskPath, const class SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    bool decryptDisk(const QString& diskPath, const class SecureString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    
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

    // Removed getLastIv method for security reasons

    bool isHardwareAccelerationSupported() const;

    // ---- Cipher cascades (public: UI offers them, tests exercise them) ----
    // cascadeRecipe(id): ordered AEAD ciphers for a cascade id (empty if id==0
    //   or unknown). Layer 0 is applied first (innermost), then wrapped by the
    //   next. Each layer uses an independent HKDF subkey.
    // cascadeIdForAlgorithm(name): the cascade id for a cascade display string,
    //   or 0 if `name` is an ordinary single cipher.
    // cascadeAlgorithmNames(): display strings to offer in the UI.
    static QStringList cascadeRecipe(quint8 cascadeId);
    static quint8      cascadeIdForAlgorithm(const QString& algorithm);
    static QStringList cascadeAlgorithmNames();

    // Per-chunk AEAD primitives (public: reused by DeniableContainer and tests).
    // buildChunkNonce: XOR the 12-byte base_iv with uint32_be(chunkIndex) low 4 bytes.
    static QByteArray buildChunkNonce(const QByteArray& baseIv, quint32 chunkIndex);
    // encryptChunk: encrypt plainChunk with key+nonce, append 16-byte tag.
    static QByteArray encryptChunk(const QByteArray& key, const QByteArray& nonce,
                                   const QByteArray& plainChunk, const QString& algorithm);
    // decryptChunk: split last 16 bytes as tag, verify+decrypt (empty on auth failure).
    static QByteArray decryptChunk(const QByteArray& key, const QByteArray& nonce,
                                   const QByteArray& cipherChunkWithTag, const QString& algorithm);

    // Key derivation entry points.
    // QString variant: thin wrapper - converts to SecureString and delegates.
    // SecureString variant: the real implementation. Performs the keyfile
    // HMAC mixing, calls performKeyDerivation, returns the derived key.
    QByteArray deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
    QByteArray deriveKey(const class SecureString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
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

    // Last user-facing error from cryptOperation / deriveKey. Set when the
    // engine refuses a request (e.g. sub-floor iterations, Argon2 memory
    // allocation failure) so the worker layer can surface a clear, actionable
    // dialog rather than a generic "operation failed". Cleared at the start
    // of each cryptOperation. Stays empty when the engine succeeds.
    QString lastError() const { return m_lastError; }

    // OWASP / NIST baseline floors. Public so the UI can pin spinbox
    // minimums to the same value the engine enforces - keeping UI and engine
    // in lock-step prevents the "user picks N, engine silently runs M" lie.
    //
    // Scrypt's floor is the libsodium scryptsalsa208sha256 *opslimit*. The old
    // 16384 floor computed in ~1.7 ms - far too weak (an attacker got ~600
    // guesses/sec). 2097152 (2^21) lands ~100 ms at the INTERACTIVE memlimit,
    // a ~60x increase, putting Scrypt's real cost in the same league as
    // Argon2/PBKDF2. NOTE: raising this is intentionally a breaking change for
    // any file previously encrypted with Scrypt at the old opslimit - those
    // used a different derived key and predate any release.
    static int iterationFloorForKdf(const QString& kdf) {
        if (kdf == "Argon2") return 3;
        if (kdf == "Scrypt") return 2097152; // 2^21 opslimit ~ 100 ms
        if (kdf == "PBKDF2") return 600000;
        return 1;
    }

private:
    // Removed lastIv storage for security reasons

    // -------------------------------------------------------------------------
    // OCUI file-format constants
    //
    // v2 on-disk layout:
    //   [magic "OCUI" 4][format_version=2 1][algorithm_id 1][kdf_id 1][reserved 1]
    //   [iterations uint32 BE 4]   -- total header = 12 bytes
    //   [salt 32][iv N][ciphertext][sig trailer]
    //
    // v3 on-disk layout (AEAD only):
    //   [magic "OCUI" 4][format_version=3 1][algorithm_id 1][kdf_id 1][reserved 1]
    //   [iterations uint32 BE 4]   -- total header = 12 bytes
    //   [salt 32][base_iv 12|16]
    //   [chunk_size uint32 BE 4][chunk_count uint32 BE 4]
    //   for each chunk i: [ciphertext chunk_size bytes (or less for last)][tag 16 bytes]
    //   [sig trailer]
    //
    // v4 on-disk layout (AEAD only, deniable - no plaintext magic):
    //   [salt 32][outer_iv 12][outer_ciphertext + 16-byte outer GCM tag]
    //
    //   outer_ciphertext decrypts (AES-256-GCM, outer key) to an inner blob:
    //     [magic "OCUI" 4][format_version=4 1][alg_id 1][kdf_id 1][rsv 1]
    //     [iterations BE4][chunk_size BE4][chunk_count BE4]
    //     for each chunk i: [ciphertext][tag 16]
    //     [Ed25519 sig 64][pubkey 32]
    //
    //   Outer key = crypto_kdf_derive_from_key(master, subkey_id=3, ctx="OCUI-V4O")
    //   Inner enc key = crypto_kdf_derive_from_key(master, subkey_id=1, ctx="OCUI-KEY")
    //   Inner sig key = crypto_kdf_derive_from_key(master, subkey_id=2, ctx="OCUI-SIG")
    //   master is the first 32 bytes of the KDF output.
    //
    // The entire prefix including all chunks is covered by the Ed25519 signature.
    // -------------------------------------------------------------------------
    static constexpr quint32 OCUI_MAGIC          = 0x4F435549u; // "OCUI"
    static constexpr quint8  OCUI_FORMAT_VER     = 2;
    static constexpr quint8  OCUI_FORMAT_VER_V3  = 3;
    static constexpr quint8  OCUI_FORMAT_VER_V4  = 4;
    static constexpr int     OCUI_HEADER_SIZE    = 12; // magic(4)+ver(1)+alg(1)+kdf(1)+rsv(1)+iters(4)
    static constexpr int     OCUI_CHUNK_SIZE     = 1 << 20; // 1 MiB per chunk
    static constexpr int     OCUI_GCM_TAG_SIZE   = 16;      // GCM/Poly1305 tag bytes

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
    // Cipher cascade: chunks are encrypted through an ordered list of AEAD
    // ciphers, each with an independent subkey, so breaking the file requires
    // breaking every cipher in the chain. The specific recipe lives in the v4
    // inner header's reserved byte (a cascade id); this single algId marks
    // "this is a cascade". Built from the AEAD primitives we already trust
    // (AES-256-GCM + ChaCha20-Poly1305, different design families).
    static constexpr quint8 ALG_ID_CASCADE            = 0xC0;
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
    static bool isAeadAlgorithm(const QString& algorithm);


    // (buildChunkNonce / encryptChunk / decryptChunk are declared public above.)

    // Cascade variants: apply ciphers[] in sequence with layerKeys[]. Encrypt
    // returns the nested ciphertext (empty on error). Decrypt unwraps in
    // reverse; *ok distinguishes a real auth failure from a legitimately empty
    // plaintext chunk.
    static QByteArray cascadeEncryptChunk(const QVector<QByteArray>& layerKeys,
                                          const QByteArray& nonce,
                                          const QByteArray& plainChunk,
                                          const QStringList& ciphers);
    static QByteArray cascadeDecryptChunk(const QVector<QByteArray>& layerKeys,
                                          const QByteArray& nonce,
                                          const QByteArray& cipherChunk,
                                          const QStringList& ciphers,
                                          bool* ok);

    // v3 encrypt/decrypt implementations (called from cryptOperation).
    bool cryptOperationV3Encrypt(QFile& inputFile, QFile& outputFile,
                                 const QByteArray& encKey, const QByteArray& sigKey,
                                 const QByteArray& salt, const QByteArray& baseIv,
                                 quint8 algId, quint8 kId, int iterations,
                                 const QString& algorithm, const QString& outputPath);
    bool cryptOperationV3Decrypt(QFile& inputFile, QFile& outputFile,
                                 const QByteArray& encKey, const QByteArray& sigKey,
                                 const QByteArray& salt, const QByteArray& baseIv,
                                 const QString& algorithm, const QString& inputPath);

    // v4 encrypt/decrypt implementations (deniable outer AEAD wrapper).
    // cryptOperationV4Encrypt:
    //   - Builds inner payload (v3-style chunks + sig) into a memory buffer.
    //   - Wraps it with AES-256-GCM using the outer key.
    //   - Writes: salt(32) || outer_iv(12) || outer_ciphertext+tag to outputFile.
    // cryptOperationV4Decrypt:
    //   - Reads salt(32) || outer_iv(12) from file offset 0.
    //   - Derives master -> outer key.
    //   - Decrypts outer AEAD -> inner payload buffer.
    //   - Parses inner OCUI v4 header, verifies Ed25519, decrypts chunks.
    //   Returns true on success; false means wrong password OR not v4 format.
    bool cryptOperationV4Encrypt(QFile& inputFile, QFile& outputFile,
                                 const QByteArray& masterKeyBytes,
                                 const QByteArray& salt, const QByteArray& outerIv,
                                 quint8 algId, quint8 kId, int iterations,
                                 const QString& algorithm, const QString& outputPath,
                                 quint8 cascadeId = 0);
    bool cryptOperationV4Decrypt(QFile& inputFile, QFile& outputFile,
                                 const class SecureString& password,
                                 const QStringList& keyfilePaths,
                                 const QString& algorithm, const QString& kdf,
                                 int iterations, const QString& inputPath);

    // Derive the outer AEAD key for v4 from a 32-byte master.
    // Uses crypto_kdf_derive_from_key with context "OCUI-V4O" (subkey id 3).
    // master is NOT zeroed by this function (caller may still need enc/sig subkeys).
    static bool deriveV4OuterKey(const unsigned char* master32, QByteArray& outerKey);

    // Vector to hold unique pointers to providers
    std::vector<std::unique_ptr<CryptoProvider>> m_providers;
    
    // Pointer to the current active provider
    CryptoProvider* m_currentProvider;
    QString m_currentProviderName;
    // Reset at the start of cryptOperation. Engine writes a user-facing
    // message here whenever it refuses a request that bypassed the UI guards
    // (sub-floor iterations, KDF/alg-not-supported-by-provider, Argon2 OOM).
    QString m_lastError;
    
    // Initialize all available providers
    void initializeProviders();

    // Key derivation helper methods
    QByteArray readKeyfile(const QString& keyfilePath);
    QByteArray performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize);
    
    // NEW: Secure iteration calculation
    int calculateSecureIterations(const QString& kdf, int requestedIterations);
    
    // Encryption/decryption operations
    bool cryptOperation(const QString& inputPath, const QString& outputPath, const class SecureString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths);
    
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
