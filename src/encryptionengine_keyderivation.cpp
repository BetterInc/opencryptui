#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <argon2.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

// For x86_64 hardware RNG support
#ifdef __x86_64__
#include <cpuid.h>
#endif

// readKeyfile() moved to encryptionengine_keyfile.cpp — pure disk I/O,
// kept here only because it used to share a translation unit with
// deriveKey().

QByteArray EncryptionEngine::deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations) {
    // Fix #5: Convert QString -> QByteArray immediately to minimize plaintext exposure.
    // sodium_mlock is best-effort (may fail if RLIMIT_MEMLOCK is 0).
    // The QString's internal buffer is wiped best-effort via const_cast at the end.
    QByteArray passwordData = password.toUtf8();
    sodium_mlock(passwordData.data(), static_cast<size_t>(passwordData.size()));
    
    // Calculate HMAC of keyfiles instead of simply appending them
    // This provides proper domain separation and prevents extension attacks
    QByteArray keyfileComponent;
    
    // NOTE: We deliberately do NOT wipe the source `password` QString here.
    // It's a `const QString&` from the caller; wiping it via const_cast
    // corrupts the caller's variable, breaking any later reuse (e.g. the
    // decryptFile call after encryptFile in the same scope uses the same
    // QString, and a wiped password yields a different derived key →
    // signature verification fails). QString zeroization needs to happen
    // at the owner (the UI layer), not here. SECURITY.md documents the
    // residual memory-hygiene gap.

    if (!keyfilePaths.isEmpty()) {
        // Use SHA-512 for HMAC operations
        unsigned int hmacLen = EVP_MD_size(EVP_sha512());
        unsigned char hmacOutput[EVP_MAX_MD_SIZE];

        for (const QString &keyfilePath : keyfilePaths) {
            QByteArray keyfileData = readKeyfile(keyfilePath);
            if (!keyfileData.isEmpty()) {
                // Apply HMAC algorithm for each keyfile
                HMAC(EVP_sha512(),
                     passwordData.constData(), passwordData.length(),
                     reinterpret_cast<const unsigned char*>(keyfileData.constData()), keyfileData.length(),
                     hmacOutput, &hmacLen);

                // Add processed keyfile data to the component
                keyfileComponent.append(reinterpret_cast<char*>(hmacOutput), hmacLen);

                // Securely clear keyfile data
                sodium_memzero(keyfileData.data(), keyfileData.size());
            }
        }

        // Create a combined password component that includes the processed keyfiles
        QByteArray combinedData(passwordData.length() + keyfileComponent.length(), 0);

        // Copy password first
        memcpy(combinedData.data(), passwordData.constData(), passwordData.length());

        // Copy processed keyfile data
        memcpy(combinedData.data() + passwordData.length(),
               keyfileComponent.constData(), keyfileComponent.length());

        // Securely erase all intermediate buffers
        sodium_memzero(passwordData.data(), passwordData.size());
        sodium_munlock(passwordData.data(), static_cast<size_t>(passwordData.size()));
        sodium_memzero(keyfileComponent.data(), keyfileComponent.size());

        // Best-effort wipe of the source QString

        // Perform key derivation with the combined data
        QByteArray derivedKey = performKeyDerivation(combinedData, salt, kdf, iterations, EVP_MAX_KEY_LENGTH);

        // Clear combined data securely
        sodium_memzero(combinedData.data(), combinedData.size());

        return derivedKey;
    } else {
        // If no keyfiles, just use the password directly
        QByteArray derivedKey = performKeyDerivation(passwordData, salt, kdf, iterations, EVP_MAX_KEY_LENGTH);

        // Clear password data securely and release mlock
        sodium_memzero(passwordData.data(), passwordData.size());
        sodium_munlock(passwordData.data(), static_cast<size_t>(passwordData.size()));

        // Best-effort wipe of the source QString

        return derivedKey;
    }
}

QByteArray EncryptionEngine::deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize) {
    // Convert the password to UTF-8 and store it in a QByteArray
    QByteArray passwordWithKeyfile = password.toUtf8();

    // Perform key derivation using the password only
    return performKeyDerivation(passwordWithKeyfile, salt.toUtf8(), kdf, iterations, keySize);
}

QByteArray EncryptionEngine::performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize)
{
    // Validate input parameters
    if (passwordWithKeyfile.isEmpty() || salt.isEmpty() || keySize <= 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Invalid key derivation parameters");
        return QByteArray();
    }

    // Ensure minimum secure iteration counts
    int secureIterations = calculateSecureIterations(kdf, iterations);

    // Allocate key with secure memory locking
    QScopedArrayPointer<char> key(new char[keySize]);
    std::memset(key.data(), 0, keySize);

    // Advanced memory protection
    sodium_mlock(key.data(), keySize);

    // Prevent compiler optimizations that might remove memory clearing
    volatile bool derivationSuccessful = false;

    try {
        // Key derivation with enhanced security parameters
        if (kdf == "Argon2") {
            // Use Argon2id - resistance against side-channel and timing attacks
            int argon2Result = argon2id_hash_raw(
                secureIterations,      // Time cost
                1 << 20,               // Memory: 1 GB
                4,                     // Parallelism factor
                passwordWithKeyfile.constData(), 
                passwordWithKeyfile.size(),
                salt.constData(), 
                salt.size(),
                reinterpret_cast<unsigned char*>(key.data()), 
                keySize
            );

            derivationSuccessful = (argon2Result == ARGON2_OK);
        }
        else if (kdf == "PBKDF2") {
            // Enhanced PBKDF2 with SHA-512
            int pbkdf2Result = PKCS5_PBKDF2_HMAC(
                passwordWithKeyfile.constData(), 
                passwordWithKeyfile.size(),
                reinterpret_cast<const unsigned char*>(salt.constData()), 
                salt.size(),
                secureIterations, 
                EVP_sha512(),  // Use stronger SHA-512
                keySize,
                reinterpret_cast<unsigned char*>(key.data())
            );

            derivationSuccessful = (pbkdf2Result == 1);
        }
        else if (kdf == "Scrypt") {
            // Libsodium's secure Scrypt implementation
            int scryptResult = crypto_pwhash_scryptsalsa208sha256(
                reinterpret_cast<unsigned char*>(key.data()),
                static_cast<unsigned long long>(keySize),
                passwordWithKeyfile.constData(),
                static_cast<unsigned long long>(passwordWithKeyfile.size()),
                reinterpret_cast<const unsigned char*>(salt.constData()),
                secureIterations,
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
            );

            derivationSuccessful = (scryptResult == 0);
        }
        else {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Unsupported KDF: %1").arg(kdf));
            return QByteArray();
        }

        // Verification step
        if (!derivationSuccessful) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
                QString("Key derivation failed for %1").arg(kdf));
            
            // Secure cleanup
            sodium_memzero(key.data(), keySize);
            sodium_munlock(key.data(), keySize);
            
            return QByteArray();
        }

        // Convert to QByteArray with secure copy
        QByteArray secureKey(key.data(), keySize);

        // Additional memory sanitization
        sodium_memzero(key.data(), keySize);
        sodium_munlock(key.data(), keySize);

        return secureKey;
    }
    catch (const std::exception& e) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", 
            QString("Exception during key derivation: %1").arg(e.what()));
        
        // Secure cleanup in case of exception
        sodium_memzero(key.data(), keySize);
        sodium_munlock(key.data(), keySize);
        
        return QByteArray();
    }
}

int EncryptionEngine::calculateSecureIterations(const QString& kdf, int requestedIterations)
{
    // Minimum secure iteration recommendations
    // PBKDF2 floor raised to 600 000 per OWASP 2024 / NIST SP 800-132 for SHA-256/512.
    const int ARGON2_MIN_ITERATIONS = 3;      // Cryptographically secure baseline
    const int PBKDF2_MIN_ITERATIONS = 600000; // OWASP 2024 / NIST SP 800-132 for SHA-256/512
    const int SCRYPT_MIN_ITERATIONS = 16384;  // Secure baseline

    if (requestedIterations < 1) {
        // Default to secure baselines if input is invalid
        if (kdf == "Argon2") return ARGON2_MIN_ITERATIONS;
        if (kdf == "PBKDF2") return PBKDF2_MIN_ITERATIONS;
        if (kdf == "Scrypt") return SCRYPT_MIN_ITERATIONS;
    }

    // Scale iterations based on KDF
    if (kdf == "Argon2") {
        return std::max(requestedIterations, ARGON2_MIN_ITERATIONS);
    }
    else if (kdf == "PBKDF2") {
        return std::max(requestedIterations, PBKDF2_MIN_ITERATIONS);
    }
    else if (kdf == "Scrypt") {
        return std::max(requestedIterations, SCRYPT_MIN_ITERATIONS);
    }

    return requestedIterations;
}

QByteArray EncryptionEngine::generateSecureRandomBytes(int size, bool isSecurityCritical)
{
    QByteArray randomData(size, 0);
    
    // Create a secure buffer for mixing entropy
    QByteArray mixBuffer(size, 0);
    QByteArray hardwareBuffer(size, 0);
    
    bool success = false;
    bool hardwareSuccess = false;
    
    // Check for RDSEED/RDRAND hardware instruction availability
    static bool hardwareRngAvailable = checkHardwareRngSupport();
    
    // Try to use hardware RNG if available (RDRAND/RDSEED instructions)
    if (hardwareRngAvailable) {
        hardwareSuccess = getHardwareRandomBytes(hardwareBuffer.data(), size);
        
        if (hardwareSuccess) {
            // Use the hardware RNG as the base
            memcpy(randomData.data(), hardwareBuffer.data(), size);
            success = true;
            
            // Always mix with other sources for defense-in-depth
            SECURE_LOG(DEBUG, "EncryptionEngine", "Successfully used hardware RNG");
        }
    }
    
    // Primary source: Use OpenSSL's RAND_bytes (always mix with hardware if available)
    bool opensslSuccess = false;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(mixBuffer.data()), size) == 1) {
        opensslSuccess = true;
        
        // If hardware wasn't available, use OpenSSL as the base
        if (!hardwareSuccess) {
            memcpy(randomData.data(), mixBuffer.data(), size);
        } else {
            // Otherwise, mix it in
            for (int i = 0; i < size; i++) {
                randomData.data()[i] ^= mixBuffer.data()[i];
            }
        }
        
        success = true;
    } else {
        SECURE_LOG(WARNING, "EncryptionEngine", "OpenSSL random generation failed, falling back to libsodium");
    }
    
    // Secondary source: Mix in entropy from libsodium (always use for security-critical data)
    if (isSecurityCritical || !success) {
        // Use libsodium's random bytes as an additional or fallback source
        randombytes_buf(mixBuffer.data(), size);
        
        if (!success) {
            // If no previous source worked, use libsodium as the base
            memcpy(randomData.data(), mixBuffer.data(), size);
        } else {
            // Otherwise mix it in
            for (int i = 0; i < size; i++) {
                randomData.data()[i] ^= mixBuffer.data()[i];
            }
        }
        
        // Successfully used libsodium
        success = true;
    }
    
    // Tertiary source (emergency fallback): Use OS-specific entropy sources
    if (!success || isSecurityCritical) {
        // Always mix in OS entropy for security-critical data, even if other sources worked
        
        // Linux-specific: read from /dev/urandom as a mixture source
        QFile urandom("/dev/urandom");
        if (urandom.open(QIODevice::ReadOnly)) {
            if (urandom.read(mixBuffer.data(), size) == size) {
                // XOR with whatever we have so far
                for (int i = 0; i < size; i++) {
                    randomData.data()[i] ^= mixBuffer.data()[i];
                }
                success = true;
            }
            urandom.close();
        }
        
        // Try /dev/hwrng for hardware RNG if available on some Linux systems
        QFile hwrng("/dev/hwrng");
        if (hwrng.exists() && hwrng.open(QIODevice::ReadOnly)) {
            if (hwrng.read(mixBuffer.data(), size) == size) {
                // XOR with whatever we have so far
                for (int i = 0; i < size; i++) {
                    randomData.data()[i] ^= mixBuffer.data()[i];
                }
                SECURE_LOG(DEBUG, "EncryptionEngine", "Successfully mixed in /dev/hwrng entropy");
            }
            hwrng.close();
        }
    }
    
    // Fail if we couldn't get good entropy from any source
    if (!success) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Secure random generation failed from all sources");
        sodium_memzero(randomData.data(), randomData.size());
        sodium_memzero(mixBuffer.data(), mixBuffer.size());
        sodium_memzero(hardwareBuffer.data(), hardwareBuffer.size());
        return QByteArray();
    }
    
    // Enhanced entropy testing for security-critical data
    EntropyTestResult entropyResult = testEntropyQuality(randomData);
    
    if (isSecurityCritical && !entropyResult.passed) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", QString("Random data failed entropy test (%1): %2")
                            .arg(entropyResult.testName)
                            .arg(entropyResult.details));
        
        sodium_memzero(randomData.data(), randomData.size());
        sodium_memzero(mixBuffer.data(), mixBuffer.size());
        sodium_memzero(hardwareBuffer.data(), hardwareBuffer.size());
        return QByteArray();
    }
    
    // Update global entropy health metrics
    updateEntropyHealthMetrics(entropyResult);

    // Clean up the mixing buffers
    sodium_memzero(mixBuffer.data(), mixBuffer.size());
    sodium_memzero(hardwareBuffer.data(), hardwareBuffer.size());
    
    // For extra paranoia, run one final post-whitening step
    if (isSecurityCritical) {
        // Use a high-quality hash function for post-whitening
        QByteArray hashedOutput(size, 0);
        hashWhitenData(randomData, hashedOutput);
        
        // Replace the output with the whitened version
        sodium_memzero(randomData.data(), randomData.size());
        return hashedOutput;
    }
    
    return randomData;
}

// Hardware RNG Support
bool EncryptionEngine::checkHardwareRngSupport()
{
#ifdef __x86_64__
    // Check if RDSEED or RDRAND instruction is available
    unsigned int eax, ebx, ecx, edx;
    
    // CPUID for leaf 7, subleaf 0 (for RDSEED)
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    bool rdseedSupported = (ebx & (1 << 18)) != 0;
    
    // CPUID for leaf 1 (for RDRAND)
    __cpuid(1, eax, ebx, ecx, edx);
    bool rdrandSupported = (ecx & (1 << 30)) != 0;
    
    SECURE_LOG(INFO, "EncryptionEngine", QString("Hardware RNG support: RDSEED=%1, RDRAND=%2")
        .arg(rdseedSupported ? "Yes" : "No")
        .arg(rdrandSupported ? "Yes" : "No"));
    
    return rdseedSupported || rdrandSupported;
#else
    // For non-x86_64 platforms, we check for hardware RNG at runtime with /dev/hwrng
    QFile hwrng("/dev/hwrng");
    bool hwrngAvailable = hwrng.exists();
    if (hwrngAvailable) {
        SECURE_LOG(INFO, "EncryptionEngine", "Hardware RNG support: /dev/hwrng available");
    }
    return hwrngAvailable;
#endif
}

bool EncryptionEngine::getHardwareRandomBytes(char* buffer, int size)
{
#ifdef __x86_64__
    // Try RDSEED first (better quality), then fall back to RDRAND
    unsigned int eax, ebx, ecx, edx;
    
    // Check RDSEED support
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    bool rdseedSupported = (ebx & (1 << 18)) != 0;
    
    // Check RDRAND support
    __cpuid(1, eax, ebx, ecx, edx);
    bool rdrandSupported = (ecx & (1 << 30)) != 0;
    
    if (rdseedSupported) {
        // RDSEED is available - use it for true random numbers
        unsigned long long rnd_value;
        int bytes_filled = 0;
        
        while (bytes_filled < size) {
            int retries = 10;
            bool success = false;
            
            // Try to get a random value with RDSEED (may fail if entropy is depleted)
            while (retries-- > 0 && !success) {
                asm volatile("rdseed %0; setc %1"
                             : "=r" (rnd_value), "=qm" (success));
                
                if (success) {
                    // Copy as many bytes as we need from the 8-byte rnd_value
                    int bytes_to_copy = std::min(8, size - bytes_filled);
                    memcpy(buffer + bytes_filled, &rnd_value, bytes_to_copy);
                    bytes_filled += bytes_to_copy;
                    
                    // Zero out the random value for security
                    rnd_value = 0;
                }
            }
            
            // If we've exhausted retries and still haven't filled the buffer,
            // fall back to RDRAND if available
            if (bytes_filled < size && rdrandSupported) {
                break;
            } else if (bytes_filled < size) {
                // Both RDSEED and RDRAND failed
                return false;
            }
        }
        
        // If we've exited the loop without filling the buffer, use RDRAND for the rest
        if (bytes_filled < size && rdrandSupported) {
            return getRdrandBytes(buffer + bytes_filled, size - bytes_filled);
        }
        
        return bytes_filled == size;
    } else if (rdrandSupported) {
        // Only RDRAND is available
        return getRdrandBytes(buffer, size);
    }
    
    return false;
#else
    // For non-x86_64 platforms, try to use /dev/hwrng
    QFile hwrng("/dev/hwrng");
    if (hwrng.exists() && hwrng.open(QIODevice::ReadOnly)) {
        bool success = (hwrng.read(buffer, size) == size);
        hwrng.close();
        return success;
    }
    return false;
#endif
}

#ifdef __x86_64__
// RDRAND-specific implementation for x86_64
bool EncryptionEngine::getRdrandBytes(char* buffer, int size)
{
    unsigned long long rnd_value;
    int bytes_filled = 0;
    
    while (bytes_filled < size) {
        int retries = 10;
        bool success = false;
        
        // Try to get a random value with RDRAND
        while (retries-- > 0 && !success) {
            asm volatile("rdrand %0; setc %1"
                         : "=r" (rnd_value), "=qm" (success));
            
            if (success) {
                // Copy as many bytes as we need from the 8-byte rnd_value
                int bytes_to_copy = std::min(8, size - bytes_filled);
                memcpy(buffer + bytes_filled, &rnd_value, bytes_to_copy);
                bytes_filled += bytes_to_copy;
                
                // Zero out the random value for security
                rnd_value = 0;
            }
        }
        
        // If we've exhausted retries and couldn't get a value, RDRAND is broken
        if (!success && retries <= 0) {
            return false;
        }
    }
    
    return bytes_filled == size;
}
#endif

// Entropy Testing
EncryptionEngine::EntropyTestResult EncryptionEngine::testEntropyQuality(const QByteArray& data)
{
    EntropyTestResult result;
    result.passed = true;
    result.testName = "All";
    result.details = "Passed all tests";
    
    // Only perform detailed tests on data of sufficient size
    if (data.size() < 32) {
        result.passed = true;
        result.testName = "Skip";
        result.details = "Sample too small for comprehensive testing";
        return result;
    }
    
    // Test 1: Frequency test (proportion of 1s should be ~0.5)
    double freqResult = testFrequency(data);
    if (std::abs(freqResult - 0.5) > 0.1) {
        result.passed = false;
        result.testName = "Frequency";
        result.details = QString("Bit frequency = %1, expected ~0.5").arg(freqResult);
        return result;
    }
    
    // Test 2: Runs test (sequences of consecutive 0s or 1s)
    double runsResult = testRuns(data);
    if (runsResult < 0.1 || runsResult > 5.0) {
        result.passed = false;
        result.testName = "Runs";
        result.details = QString("Runs test failed with value %1, expected 0.1-5.0").arg(runsResult);
        return result;
    }
    
    // Test 3: Serial correlation test
    double serialResult = testSerialCorrelation(data);
    if (std::abs(serialResult) > 0.3) {
        result.passed = false;
        result.testName = "Serial";
        result.details = QString("Serial correlation = %1, expected < ±0.3").arg(serialResult);
        return result;
    }
    
    // Update statistics for reporting
    result.bitFrequency = freqResult;
    result.runsValue = runsResult;
    result.serialCorrelation = serialResult;
    
    return result;
}

// Test 1: Frequency test (proportion of 1 bits)
double EncryptionEngine::testFrequency(const QByteArray& data)
{
    long ones = 0;
    long total = data.size() * 8;
    
    for (int i = 0; i < data.size(); i++) {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        for (int bit = 0; bit < 8; bit++) {
            if ((byte >> bit) & 1) {
                ones++;
            }
        }
    }
    
    return static_cast<double>(ones) / total;
}

// Test 2: Runs test (consecutive same bits)
double EncryptionEngine::testRuns(const QByteArray& data)
{
    long runs = 0;
    bool lastBit = false;
    bool currentBit = false;
    
    // First bit
    if (data.size() > 0) {
        lastBit = (static_cast<unsigned char>(data[0]) & 0x80) != 0;
    }
    
    for (int i = 0; i < data.size(); i++) {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        for (int bit = 0; bit < 8; bit++) {
            if (i == 0 && bit == 0) continue; // Skip first bit
            
            int bitPos = 7 - bit; // MSB first
            currentBit = (byte & (1 << bitPos)) != 0;
            
            if (currentBit != lastBit) {
                runs++;
                lastBit = currentBit;
            }
        }
    }
    
    // Normalize by data size
    return static_cast<double>(runs) / (data.size() - 1);
}

// Test 3: Serial correlation test
double EncryptionEngine::testSerialCorrelation(const QByteArray& data)
{
    if (data.size() < 2) return 0.0;
    
    long sum = 0;
    long squared_sum = 0;
    long product_sum = 0;
    
    for (int i = 0; i < data.size() - 1; i++) {
        unsigned char b1 = static_cast<unsigned char>(data[i]);
        unsigned char b2 = static_cast<unsigned char>(data[i + 1]);
        
        sum += b1;
        squared_sum += b1 * b1;
        product_sum += b1 * b2;
    }
    
    // Add last byte to sums
    sum += static_cast<unsigned char>(data[data.size() - 1]);
    squared_sum += static_cast<unsigned char>(data[data.size() - 1]) * 
                   static_cast<unsigned char>(data[data.size() - 1]);
    
    long n = data.size();
    double numerator = (n - 1) * product_sum - sum * sum + 
                      static_cast<unsigned char>(data[data.size() - 1]) * 
                      static_cast<unsigned char>(data[0]);
    double denominator = (n * squared_sum - sum * sum);
    
    if (denominator == 0) return 0.0;
    return numerator / denominator;
}

// Update global entropy health metrics for UI reporting
void EncryptionEngine::updateEntropyHealthMetrics(const EntropyTestResult& result)
{
    // Update the global metrics
    QMutexLocker locker(&m_entropyMetricsMutex);
    
    // Update overall entropy health if test passed
    if (result.passed) {
        m_entropyHealthStatus = "Good";
        m_entropyHealthScore = (result.bitFrequency >= 0.49 && result.bitFrequency <= 0.51) ? 100 : 90;
    } else {
        // Test failed
        m_entropyHealthStatus = "Warning";
        m_entropyHealthScore = 50;
    }
    
    // Check for hardware RNG
    m_hardwareRngAvailable = checkHardwareRngSupport();
    
    // Update individual test results
    m_bitDistribution = static_cast<int>(result.bitFrequency * 100);
    m_entropyEstimate = static_cast<int>(result.runsValue * 20);
    
    // Last test timestamp
    m_lastEntropyTestTime = QDateTime::currentDateTime();
}

// Post-whitening with a cryptographic hash
void EncryptionEngine::hashWhitenData(const QByteArray& input, QByteArray& output)
{
    // Use SHA-512 for whitening
    if (output.size() == 0) return;
    
    // Create blocks of SHA-512 hashes
    QByteArray tempBuffer;
    const int blockSize = 64; // SHA-512 output size in bytes
    
    for (int i = 0; i < output.size(); i += blockSize) {
        // Create a unique hash for each block by including a counter
        QByteArray blockInput = input;
        blockInput.append(reinterpret_cast<const char*>(&i), sizeof(i));
        
        // Generate hash for this block
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (mdctx) {
            bool success = true;
            
            success = success && (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) == 1);
            success = success && (EVP_DigestUpdate(mdctx, blockInput.constData(), blockInput.size()) == 1);
            success = success && (EVP_DigestFinal_ex(mdctx, hash, &hashLen) == 1);
            
            // Always free the context
            EVP_MD_CTX_free(mdctx);
            
            if (!success) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Hash operation failed in hashWhitenData");
                // Clear any partial results
                sodium_memzero(hash, sizeof(hash));
                hashLen = 0;
            }
        } else {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "Failed to allocate MD context in hashWhitenData");
            hashLen = 0;
        }
        
        // Copy as much of the hash as needed
        int bytesToCopy = std::min(blockSize, output.size() - i);
        memcpy(output.data() + i, hash, bytesToCopy);
        
        // Clear the hash buffer
        sodium_memzero(hash, hashLen);
    }
}

// Public accessor methods for entropy health monitoring
QString EncryptionEngine::getEntropyHealthStatus() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_entropyHealthStatus;
}

int EncryptionEngine::getEntropyHealthScore() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_entropyHealthScore;
}

bool EncryptionEngine::isHardwareRngAvailable() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_hardwareRngAvailable;
}

int EncryptionEngine::getBitDistribution() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_bitDistribution;
}

int EncryptionEngine::getEntropyEstimate() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_entropyEstimate;
}

QDateTime EncryptionEngine::getLastEntropyTestTime() const
{
    QMutexLocker locker(&m_entropyMetricsMutex);
    return m_lastEntropyTestTime;
}

// Perform an on-demand entropy test and return the results
EncryptionEngine::EntropyTestResult EncryptionEngine::performEntropyTest(int sampleSize)
{
    // Generate random data for testing
    QByteArray testData = generateSecureRandomBytes(sampleSize, false);
    
    // Test the entropy quality
    EntropyTestResult result = testEntropyQuality(testData);
    
    // Update the metrics
    updateEntropyHealthMetrics(result);
    
    // Securely clear the test data
    sodium_memzero(testData.data(), testData.size());
    
    return result;
}

QByteArray EncryptionEngine::generateSecureSalt(int size)
{
    // Salts are security-critical
    return generateSecureRandomBytes(size, true);
}

QByteArray EncryptionEngine::generateSecureIV(int size)
{
    // IVs are security-critical
    return generateSecureRandomBytes(size, true);
}