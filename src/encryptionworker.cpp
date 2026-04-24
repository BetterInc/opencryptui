#include "encryptionworker.h"
#include "logging/secure_logger.h"
#include "encryptionengine_diskops.h"
#include <QElapsedTimer>
#include <QFileInfo>
#include <QMessageBox>
#include <QPushButton>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace DiskOperations;

EncryptionWorker::EncryptionWorker(QObject *parent)
    : QObject(parent), isDisk(false), m_isHiddenVolume(false)
{
}

void EncryptionWorker::setParameters(const QString &path, const QString &password, const QString &algorithm,
                                     const QString &kdf, int iterations, bool useHMAC, bool encrypt, bool isFile, const QString &customHeader, const QStringList &keyfilePaths)
{
    this->m_path = path;
    this->m_password = password;
    this->m_algorithm = algorithm;
    this->m_kdf = kdf;
    this->m_iterations = iterations;
    this->m_useHMAC = useHMAC;
    this->m_encrypt = encrypt;
    this->m_isFile = isFile;
    this->isDisk = false;
    this->m_isHiddenVolume = false;
    this->m_customHeader = customHeader;
    this->m_keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setDiskParameters(const QString &diskPath, const QString &password, const QString &algorithm,
                                      const QString &kdf, int iterations, bool useHMAC, bool encrypt, const QStringList &keyfilePaths)
{
    this->m_path = diskPath;
    this->m_password = password;
    this->m_algorithm = algorithm;
    this->m_kdf = kdf;
    this->m_iterations = iterations;
    this->m_useHMAC = useHMAC;
    this->m_encrypt = encrypt;
    this->m_isFile = false;
    this->isDisk = true;
    this->m_isHiddenVolume = false;
    this->m_customHeader = "";
    this->m_keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setDiskParametersWithHiddenVolume(const QString &diskPath, const QString &outerPassword, const QString &hiddenPassword, 
                                                      qint64 hiddenVolumeSize, const QString &algorithm, const QString &kdf, 
                                                      int iterations, bool useHMAC, const QStringList &keyfilePaths)
{
    this->m_path = diskPath;
    this->m_password = outerPassword;
    this->m_hiddenPassword = hiddenPassword;
    this->m_hiddenVolumeSize = hiddenVolumeSize;
    this->m_algorithm = algorithm;
    this->m_kdf = kdf;
    this->m_iterations = iterations;
    this->m_useHMAC = useHMAC;
    this->m_encrypt = true;
    this->m_isFile = false;
    this->isDisk = true;
    this->m_isHiddenVolume = true;
    this->m_customHeader = "";
    this->m_keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setBenchmarkParameters(const QStringList &algorithms, const QStringList &kdfs) {
    this->m_benchmarkAlgorithms = algorithms;
    this->m_benchmarkKDFs = kdfs;
}

qint64 EncryptionWorker::getFileSizeInBytes(const QString &path) {
    QFileInfo fileInfo(path);
    return fileInfo.size();
}

void EncryptionWorker::processDiskOperation()
{
    SECURE_LOG(INFO, "EncryptionWorker", QString("Processing disk operation: Encrypt=%1, Path=%2").arg(m_encrypt).arg(m_path));
    bool success = false;
    QString errorMessage;

    try
    {
        if (m_encrypt) {
            if (m_isHiddenVolume) {
                SECURE_LOG(INFO, "EncryptionWorker", "Starting hidden volume encryption.");
                errorMessage = "Hidden volume encryption not fully implemented in worker yet.";
                success = false;
            } else {
                SECURE_LOG(INFO, "EncryptionWorker", "Starting standard disk encryption.");
                success = m_engine.encryptDisk(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_keyfilePaths);
                if (!success) errorMessage = "Disk encryption failed in engine.";
            }
        } else {
            SECURE_LOG(INFO, "EncryptionWorker", "Starting standard disk decryption.");
            success = m_engine.decryptDisk(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_keyfilePaths);
            if (!success) errorMessage = "Disk decryption failed in engine.";
        }
    }
    catch (const std::exception& e)
    {
        errorMessage = QString("Disk operation failed with exception: %1").arg(e.what());
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", errorMessage);
        success = false;
    }
    catch (...)
    {
        errorMessage = "Disk operation failed with unknown exception.";
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", errorMessage);
        success = false;
    }

    SECURE_LOG(INFO, "EncryptionWorker", QString("Disk operation finished. Success: %1").arg(success));
    emit finished(success ? QString("Disk operation completed successfully") : errorMessage, success, false);
}

void EncryptionWorker::process()
{
    if (isDisk) {
        processDiskOperation();
        return;
    }

    try
    {
        QString result;
        if (m_encrypt)
        {
            if (m_isFile)
            {
                bool success = m_engine.encryptFile(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_customHeader, m_keyfilePaths);
                result = success ? m_path + ".encrypted" : "Failed to encrypt file";
                emit progress(100);
                emit finished(QString("File encrypted successfully. Output: %1").arg(result), success, true);
            }
            else
            {
                emit progress(10);
                emit estimatedTime("Compressing folder... (est: 30 seconds)");
                
                bool success = m_engine.encryptFolder(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_customHeader, m_keyfilePaths);
                result = success ? m_path + ".encrypted" : "Failed to encrypt folder";
                emit progress(100);
                emit finished(QString("Folder encrypted successfully. Output: %1").arg(result), success, false);
            }
        }
        else
        {
            if (m_isFile)
            {
                bool success = m_engine.decryptFile(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_customHeader, m_keyfilePaths);
                result = success ? m_path.left(m_path.lastIndexOf(".encrypted")) : "Failed to decrypt file";
                emit progress(100);
                emit finished(QString("File decrypted successfully. Output: %1").arg(result), success, true);
            }
            else
            {
                emit progress(10);
                emit estimatedTime("Decrypting archive... (est: 15 seconds)");
                
                bool success = m_engine.decryptFolder(m_path, m_password, m_algorithm, m_kdf, m_iterations, m_useHMAC, m_customHeader, m_keyfilePaths);
                result = success ? m_path.left(m_path.lastIndexOf(".encrypted")) : "Failed to decrypt folder";
                emit progress(100);
                emit finished(QString("Folder decrypted successfully. Output: %1").arg(result), success, false);
            }
        }
    }
    catch (const std::exception &e)
    {
        emit progress(0);
        emit finished(QString("Operation failed: %1").arg(e.what()), false, m_isFile);
    }
    catch (...)
    {
        emit progress(0);
        emit finished("Operation failed: Unknown error", false, m_isFile);
    }
}

void EncryptionWorker::runBenchmark() {
    SECURE_LOG(INFO, "EncryptionWorker", "Starting benchmark...");

    for (const auto &algo : m_benchmarkAlgorithms) {
        for (const auto &kdf : m_benchmarkKDFs) {
            benchmarkCipher(algo, kdf, true);
            if (algo == "AES-256-GCM" || algo == "ChaCha20-Poly1305" || 
                algo == "AES-256-CTR" || algo == "AES-256-CBC" || 
                algo == "AES-128-GCM" || algo == "AES-128-CTR" || 
                algo == "AES-192-GCM" || algo == "AES-192-CTR" || 
                algo == "AES-128-CBC" || algo == "AES-192-CBC" || 
                algo == "Camellia-256-CBC" || algo == "Camellia-128-CBC") {
                benchmarkCipher(algo, kdf, false);
            }
        }
    }

    SECURE_LOG(INFO, "EncryptionWorker", "Benchmark complete.");
}

void EncryptionWorker::benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration) {
    if (kdf != "PBKDF2" && kdf != "Argon2" && kdf != "Scrypt") {
        SECURE_LOG(WARNING, "EncryptionWorker",
            QString("Skipping unknown KDF: %1").arg(kdf));
        return;
    }

    // Use a smaller buffer size for benchmarking to avoid memory issues
    // 1MB is sufficient for benchmarking throughput measurement
    const int dataSize = 1 * 1024 * 1024; // 1 MB

    // Only allocate the memory if we can
    QByteArray testData;
    try {
        testData.resize(dataSize);
        testData.fill('A');
    } catch (const std::bad_alloc&) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Memory allocation failed for benchmark data");
        return;
    }

    QByteArray key(32, 'K');
    // IV must be 12 bytes for GCM / ChaCha20-Poly1305 (96-bit nonce per NIST SP 800-38D)
    // and 16 bytes for CBC / CTR / Camellia modes.
    // Using a wrong IV size for GCM causes crypto_pwhash / EVP_EncryptInit internal
    // state corruption that leads to a segfault in EVP_EncryptUpdate.
    const int ivSize = algorithm.contains("GCM") || algorithm == "ChaCha20-Poly1305" ? 12 : 16;
    QByteArray iv(ivSize, 'I');
    // salt must be exactly 32 bytes: libsodium's crypto_pwhash_scryptsalsa208sha256
    // reads SALTBYTES (32) unconditionally — a shorter buffer is a heap overread.
    QByteArray salt(32, 'S');
    // Use minimum viable iterations per KDF so the benchmark finishes quickly
    // and does not allocate enormous amounts of RAM (Argon2 uses 1 GiB at m_cost=1<<20).
    // PBKDF2 floor is enforced by calculateSecureIterations, so pass the floor directly.
    int iterations = (kdf == "PBKDF2") ? 600000 : (kdf == "Argon2") ? 3 : 16384;

    QElapsedTimer timer;
    timer.start();

    const EVP_CIPHER *cipher = m_engine.getCipher(algorithm);

    if (!cipher) {
        SECURE_LOG(WARNING, "EncryptionWorker", 
            QString("Skipping %1 - not supported").arg(algorithm));
        return;
    }

    QStringList keyfilePaths; // If no keyfiles, use an empty QStringList
    key = m_engine.deriveKey("password", salt, keyfilePaths, kdf, iterations);
    if (key.isEmpty()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", 
            QString("Key derivation failed for KDF: %1").arg(kdf));
        return;
    }

    // Perform encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Failed to create EVP_CIPHER_CTX");
        return;
    }

    // For GCM / ChaCha20-Poly1305 the OpenSSL default IV length is 12 bytes.
    // We must initialise the cipher *without* the IV first, then set the IV
    // length explicitly via ctrl before providing the key+IV.  Skipping this
    // step and passing a mismatched IV length directly to EVP_EncryptInit_ex
    // corrupts the internal GCM state and causes a segfault in EVP_EncryptUpdate.
    if (ivSize != 16) {
        // Phase 1: load cipher and engine only (key=nullptr, iv=nullptr)
        if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptInit_ex (cipher only) failed");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        // Phase 2: set the IV length
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivSize, nullptr)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_CTRL_GCM_SET_IVLEN failed");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        // Phase 3: provide key + IV
        if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(iv.data()))) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptInit_ex (key+iv) failed");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
    } else {
        if (!EVP_EncryptInit_ex(ctx, cipher, nullptr,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(iv.data()))) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptInit_ex failed");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
    }

    // Only allocate the ciphertext buffer if we can
    QByteArray ciphertext;
    try {
        ciphertext.resize(testData.size() + EVP_MAX_BLOCK_LENGTH);
    } catch (const std::bad_alloc&) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Memory allocation failed for ciphertext buffer");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int len = 0;
    int ciphertextLen = 0;
    
    bool encryptSuccess = EVP_EncryptUpdate(ctx, 
                                reinterpret_cast<unsigned char *>(ciphertext.data()), 
                                &len,
                                reinterpret_cast<const unsigned char *>(testData.data()), 
                                testData.size()) == 1;
    
    if (!encryptSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    ciphertextLen += len;
    
    encryptSuccess = EVP_EncryptFinal_ex(ctx, 
                            reinterpret_cast<unsigned char *>(ciphertext.data()) + len, 
                            &len) == 1;
                            
    if (!encryptSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    ciphertextLen += len;
    
    // Always free the cipher context
    EVP_CIPHER_CTX_free(ctx);
    
    // Clear memory as soon as we're done with it to reduce memory footprint
    ciphertext.clear();
    testData.clear();

    qint64 elapsed = timer.elapsed();
    double throughput = (dataSize / (1024.0 * 1024.0)) / (elapsed / 1000.0);

    emit benchmarkResultReady(iterations, throughput, elapsed, algorithm, kdf);
}

EncryptionWorker::~EncryptionWorker()
{
    // No heap allocations to clean up
}

void EncryptionWorker::processBenchmark()
{
    SECURE_LOG(INFO, "EncryptionWorker", "Processing benchmark operation");
    
    try
    {
        runBenchmark();
        emit finished("Benchmark completed successfully", true, false);
    }
    catch (const std::exception &e)
    {
        emit finished(QString("Benchmark failed: %1").arg(e.what()), false, false);
    }
    catch (...)
    {
        emit finished("Benchmark failed: Unknown error", false, false);
    }
}
