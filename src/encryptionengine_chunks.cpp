// encryptionengine_chunks.cpp
//
// Per-chunk AEAD framing helpers for OCUI v3 format.
//
// Each chunk is independently encrypted with a unique nonce derived from the
// file's random base_iv and the chunk index.  This allows tamper detection at
// chunk granularity and enables streaming decryption.
//
// Nonce construction (12-byte GCM nonces):
//   nonce_i = base_iv XOR (uint32_be(i) || 8-zero-bytes)
//
// That is: the top 8 bytes of base_iv are unchanged; only the bottom 4 bytes
// are XORed with the big-endian chunk index.  Because base_iv is random per
// file and every chunk index within a file is distinct, the full (key, nonce)
// tuple is unique across every encryption ever produced by this implementation.
// Key uniqueness is guaranteed by KDF salting (random 32-byte salt per file);
// nonce uniqueness within a file is guaranteed by index XOR.

#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QDataStream>
#include <QScopeGuard>
#include <openssl/evp.h>
#include <sodium.h>

// ---------------------------------------------------------------------------
// isAeadAlgorithm — returns true for GCM / ChaCha20-Poly1305 ciphers.
// These are the only algorithms that support the v3 per-chunk path.
// ---------------------------------------------------------------------------
/*static*/ bool EncryptionEngine::isAeadAlgorithm(const QString& algorithm)
{
    return algorithm.contains("GCM") || algorithm == "ChaCha20-Poly1305";
}

// ---------------------------------------------------------------------------
// buildChunkNonce
//
// Returns a 12-byte nonce for chunk #chunkIndex.
//
// Layout of the XOR mask: [uint32_be(chunkIndex) | 8 zero bytes]
// The high 8 bytes of base_iv are kept intact; the low 4 bytes are XORed
// with the big-endian representation of the chunk index.  This mirrors the
// specification precisely:
//
//   nonce_i = base_iv XOR (uint32_be(i) || 8 zero bytes)
// ---------------------------------------------------------------------------
/*static*/ QByteArray EncryptionEngine::buildChunkNonce(const QByteArray& baseIv,
                                                         quint32 chunkIndex)
{
    if (baseIv.size() < 12) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            QString("buildChunkNonce: baseIv too short (%1 bytes)").arg(baseIv.size()));
        return QByteArray();
    }

    QByteArray nonce = baseIv.left(12); // copy the 12-byte base_iv

    // XOR the bottom 4 bytes (bytes 8..11) with big-endian chunk index.
    const quint8 idx3 = static_cast<quint8>((chunkIndex >> 24) & 0xFF);
    const quint8 idx2 = static_cast<quint8>((chunkIndex >> 16) & 0xFF);
    const quint8 idx1 = static_cast<quint8>((chunkIndex >>  8) & 0xFF);
    const quint8 idx0 = static_cast<quint8>( chunkIndex        & 0xFF);

    nonce[8]  = static_cast<char>(static_cast<unsigned char>(nonce[8])  ^ idx3);
    nonce[9]  = static_cast<char>(static_cast<unsigned char>(nonce[9])  ^ idx2);
    nonce[10] = static_cast<char>(static_cast<unsigned char>(nonce[10]) ^ idx1);
    nonce[11] = static_cast<char>(static_cast<unsigned char>(nonce[11]) ^ idx0);

    return nonce;
}

// ---------------------------------------------------------------------------
// encryptChunk
//
// Encrypts plainChunk using AES-GCM or ChaCha20-Poly1305 with the given
// key and nonce.  Returns [ciphertext | 16-byte tag].
// Returns an empty QByteArray on any error.
// ---------------------------------------------------------------------------
/*static*/ QByteArray EncryptionEngine::encryptChunk(const QByteArray& key,
                                                      const QByteArray& nonce,
                                                      const QByteArray& plainChunk,
                                                      const QString& algorithm)
{
    const EVP_CIPHER* cipher = nullptr;
    if (algorithm == "AES-256-GCM")       cipher = EVP_aes_256_gcm();
    else if (algorithm == "AES-128-GCM")  cipher = EVP_aes_128_gcm();
    else if (algorithm == "AES-192-GCM")  cipher = EVP_aes_192_gcm();
    else if (algorithm == "ChaCha20-Poly1305") cipher = EVP_chacha20_poly1305();

    if (!cipher) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            QString("encryptChunk: unsupported algorithm '%1'").arg(algorithm));
        return QByteArray();
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    auto ctxGuard = qScopeGuard([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData()))) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "encryptChunk: EVP_EncryptInit_ex failed");
        return QByteArray();
    }

    // Allocate output: plaintext size + possible block padding + tag.
    QByteArray ciphertext(plainChunk.size() + EVP_CIPHER_block_size(cipher) + OCUI_GCM_TAG_SIZE, 0);
    int outLen = 0;

    if (!EVP_EncryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(ciphertext.data()), &outLen,
            reinterpret_cast<const unsigned char*>(plainChunk.constData()),
            plainChunk.size())) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "encryptChunk: EVP_EncryptUpdate failed");
        return QByteArray();
    }

    int finalLen = 0;
    if (!EVP_EncryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(ciphertext.data()) + outLen, &finalLen)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "encryptChunk: EVP_EncryptFinal_ex failed");
        return QByteArray();
    }
    outLen += finalLen;
    ciphertext.resize(outLen);

    // Retrieve the authentication tag (16 bytes).
    QByteArray tag(OCUI_GCM_TAG_SIZE, 0);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, OCUI_GCM_TAG_SIZE, tag.data())) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "encryptChunk: EVP_CTRL_GCM_GET_TAG failed");
        return QByteArray();
    }

    ciphertext.append(tag);
    return ciphertext; // [encrypted bytes | 16-byte tag]
}

// ---------------------------------------------------------------------------
// decryptChunk
//
// The input cipherChunkWithTag must be at least 16 bytes.
// The last 16 bytes are the GCM tag; the rest is ciphertext.
// Returns the plaintext on success, or an empty QByteArray if authentication
// fails.  The caller MUST treat an empty return as a hard authentication error
// and discard any already-written output.
// ---------------------------------------------------------------------------
/*static*/ QByteArray EncryptionEngine::decryptChunk(const QByteArray& key,
                                                      const QByteArray& nonce,
                                                      const QByteArray& cipherChunkWithTag,
                                                      const QString& algorithm)
{
    if (cipherChunkWithTag.size() < OCUI_GCM_TAG_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "decryptChunk: chunk too short to contain a tag");
        return QByteArray();
    }

    const EVP_CIPHER* cipher = nullptr;
    if (algorithm == "AES-256-GCM")           cipher = EVP_aes_256_gcm();
    else if (algorithm == "AES-128-GCM")      cipher = EVP_aes_128_gcm();
    else if (algorithm == "AES-192-GCM")      cipher = EVP_aes_192_gcm();
    else if (algorithm == "ChaCha20-Poly1305") cipher = EVP_chacha20_poly1305();

    if (!cipher) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            QString("decryptChunk: unsupported algorithm '%1'").arg(algorithm));
        return QByteArray();
    }

    // Split ciphertext and tag.
    const int cipherLen = cipherChunkWithTag.size() - OCUI_GCM_TAG_SIZE;
    QByteArray tag = cipherChunkWithTag.right(OCUI_GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    auto ctxGuard = qScopeGuard([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData()))) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "decryptChunk: EVP_DecryptInit_ex failed");
        return QByteArray();
    }

    // Set the expected tag before finalizing.
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, OCUI_GCM_TAG_SIZE, tag.data())) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "decryptChunk: EVP_CTRL_GCM_SET_TAG failed");
        return QByteArray();
    }

    QByteArray plaintext(cipherLen + EVP_CIPHER_block_size(cipher), 0);
    int outLen = 0;

    if (!EVP_DecryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(plaintext.data()), &outLen,
            reinterpret_cast<const unsigned char*>(cipherChunkWithTag.constData()),
            cipherLen)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "decryptChunk: EVP_DecryptUpdate failed");
        return QByteArray();
    }

    int finalLen = 0;
    // EVP_DecryptFinal_ex performs the GCM tag verification.  A return value
    // of 0 or less means authentication failed — return empty to signal error.
    if (EVP_DecryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(plaintext.data()) + outLen, &finalLen) <= 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "decryptChunk: GCM tag verification FAILED — chunk is corrupt or tampered");
        // Zero any partial plaintext before returning to prevent leakage.
        sodium_memzero(plaintext.data(), plaintext.size());
        return QByteArray();
    }

    outLen += finalLen;
    plaintext.resize(outLen);
    return plaintext;
}

// ---------------------------------------------------------------------------
// cryptOperationV3Encrypt
//
// Writes the v3 chunk-framed body into outputFile.  The file already has the
// 12-byte OCUI header written by the caller.  This function writes:
//   [salt 32][base_iv 12|16][chunk_size BE4][chunk_count BE4]
//   for each chunk: [ciphertext][tag 16]
//   [signature trailer]
// ---------------------------------------------------------------------------
bool EncryptionEngine::cryptOperationV3Encrypt(QFile& inputFile, QFile& outputFile,
                                                const QByteArray& encKey,
                                                const QByteArray& sigKey,
                                                const QByteArray& salt,
                                                const QByteArray& baseIv,
                                                quint8 /*algId*/, quint8 /*kId*/,
                                                int /*iterations*/,
                                                const QString& algorithm,
                                                const QString& outputPath)
{
    // Write salt and base_iv.
    outputFile.write(salt);
    outputFile.write(baseIv);

    // Compute chunk count from input size.
    const qint64 inputSize = inputFile.size();
    const qint64 chunkSz   = static_cast<qint64>(OCUI_CHUNK_SIZE);
    const quint32 chunkCount = static_cast<quint32>((inputSize + chunkSz - 1) / chunkSz);
    // Handle empty file: at least 1 chunk (will encrypt 0 bytes → just a tag).
    const quint32 effectiveCount = (chunkCount == 0) ? 1 : chunkCount;

    {
        QDataStream ds(&outputFile);
        ds.setByteOrder(QDataStream::BigEndian);
        ds << static_cast<quint32>(OCUI_CHUNK_SIZE);
        ds << effectiveCount;
    }

    if (!inputFile.seek(0)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V3 encrypt: failed to seek input");
        return false;
    }

    QByteArray readBuf(OCUI_CHUNK_SIZE, 0);
    for (quint32 i = 0; i < effectiveCount; ++i) {
        qint64 bytesRead = inputFile.read(readBuf.data(), OCUI_CHUNK_SIZE);
        if (bytesRead < 0) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 encrypt: read error at chunk %1").arg(i));
            return false;
        }
        // For an empty file the last (and only) chunk has 0 bytes.
        QByteArray plain = (bytesRead > 0) ? readBuf.left(static_cast<int>(bytesRead))
                                           : QByteArray();

        QByteArray nonce = buildChunkNonce(baseIv, i);
        if (nonce.isEmpty()) return false;

        QByteArray ct = encryptChunk(encKey, nonce, plain, algorithm);
        if (ct.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 encrypt: encryptChunk failed at chunk %1").arg(i));
            return false;
        }

        if (outputFile.write(ct) != ct.size()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 encrypt: write failed at chunk %1").arg(i));
            return false;
        }
    }

    // Append Ed25519 signature over entire file body.
    outputFile.flush();
    QByteArray signature = generateDigitalSignature(outputFile, sigKey);
    if (signature.isEmpty()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V3 encrypt: signature generation failed");
        return false;
    }
    appendSignature(outputFile, signature);

    SECURE_LOG(DEBUG, "EncryptionEngine",
        QString("V3 encrypt: wrote %1 chunks, total output %2 bytes")
        .arg(effectiveCount).arg(outputFile.size()));
    (void)outputPath;
    return true;
}

// ---------------------------------------------------------------------------
// cryptOperationV3Decrypt
//
// Reads and authenticates a v3 file.  Called after the OCUI header (12 bytes),
// salt, and base_iv have already been consumed from inputFile.
//
// Steps:
//   1. Verify the Ed25519 signature over the entire file (covers all chunks).
//   2. Read chunk_size and chunk_count from the framing header.
//   3. For each chunk: read [ciphertext | tag], authenticate+decrypt, write plaintext.
// If any step fails, the output file is removed by the caller's qScopeGuard.
// ---------------------------------------------------------------------------
bool EncryptionEngine::cryptOperationV3Decrypt(QFile& inputFile, QFile& outputFile,
                                                const QByteArray& encKey,
                                                const QByteArray& sigKey,
                                                const QByteArray& /*salt*/,
                                                const QByteArray& baseIv,
                                                const QString& algorithm,
                                                const QString& inputPath)
{
    // ------------------------------------------------------------------
    // Step 1: verify Ed25519 signature before touching any ciphertext.
    // ------------------------------------------------------------------
    {
        QFile sigFile(inputPath);
        if (!sigFile.open(QIODevice::ReadOnly)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                "V3 decrypt: cannot open file for signature verification");
            return false;
        }

        // Detect trailer.
        bool hasSig = false;
        if (sigFile.size() > 12) {
            sigFile.seek(sigFile.size() - 12);
            QDataStream ds(&sigFile);
            ds.setByteOrder(QDataStream::BigEndian);
            quint32 magic; ds >> magic;
            if (magic == 0x5349475F) { // "SIG_"
                hasSig = true;
            }
        }

        if (!hasSig) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                "V3 decrypt: file has no Ed25519 signature trailer — rejecting");
            return false;
        }

        QByteArray storedSig;
        bool valid = verifySignature(sigFile, sigKey, storedSig);
        sigFile.close();

        if (!valid) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                "V3 decrypt: Ed25519 signature verification FAILED — file tampered");
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Step 2: read framing metadata.  inputFile is currently positioned
    // just after base_iv (i.e. at the chunk_size field).
    // ------------------------------------------------------------------
    quint32 storedChunkSize = 0;
    quint32 chunkCount      = 0;
    {
        QDataStream ds(&inputFile);
        ds.setByteOrder(QDataStream::BigEndian);
        ds >> storedChunkSize >> chunkCount;
        if (ds.status() != QDataStream::Ok) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                "V3 decrypt: failed to read chunk_size / chunk_count");
            return false;
        }
    }

    if (storedChunkSize == 0 || chunkCount == 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V3 decrypt: invalid chunk framing (size or count == 0)");
        return false;
    }

    // Figure out where the signature trailer starts so we don't read past it.
    // Trailer layout: [sig bytes][SIG_ 4][sigLen 4][CRC 4] at end of file.
    qint64 sigTrailerSize = 0;
    {
        QFile tmp(inputPath);
        if (!tmp.open(QIODevice::ReadOnly)) return false;
        if (tmp.size() >= 12) {
            tmp.seek(tmp.size() - 12);
            QDataStream ds(&tmp);
            ds.setByteOrder(QDataStream::BigEndian);
            quint32 magic; ds >> magic;
            if (magic == 0x5349475F) {
                quint32 sigLen; ds >> sigLen;
                sigTrailerSize = static_cast<qint64>(sigLen) + 12;
            }
        }
        tmp.close();
    }

    const qint64 dataEnd = inputFile.size() - sigTrailerSize;

    // ------------------------------------------------------------------
    // Step 3: decrypt each chunk.
    // ------------------------------------------------------------------
    for (quint32 i = 0; i < chunkCount; ++i) {
        const qint64 remaining = dataEnd - inputFile.pos();
        if (remaining < static_cast<qint64>(OCUI_GCM_TAG_SIZE)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 decrypt: not enough data for chunk %1 (remaining=%2)").arg(i).arg(remaining));
            return false;
        }

        // For the last chunk, read exactly what remains before the trailer.
        qint64 toRead;
        if (i < chunkCount - 1) {
            toRead = static_cast<qint64>(storedChunkSize) + OCUI_GCM_TAG_SIZE;
        } else {
            toRead = remaining;
        }

        QByteArray raw = inputFile.read(toRead);
        if (raw.size() != static_cast<int>(toRead)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 decrypt: short read at chunk %1").arg(i));
            return false;
        }

        QByteArray nonce = buildChunkNonce(baseIv, i);
        if (nonce.isEmpty()) return false;

        QByteArray plain = decryptChunk(encKey, nonce, raw, algorithm);
        if (plain.isEmpty() && raw.size() > OCUI_GCM_TAG_SIZE) {
            // Non-empty ciphertext but empty result → authentication failure.
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V3 decrypt: AEAD authentication FAILED at chunk %1 — aborting").arg(i));
            return false;
        }

        if (!plain.isEmpty()) {
            if (outputFile.write(plain) != plain.size()) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("V3 decrypt: write failed at chunk %1").arg(i));
                return false;
            }
        }
    }

    SECURE_LOG(DEBUG, "EncryptionEngine",
        QString("V3 decrypt: successfully decrypted %1 chunks").arg(chunkCount));
    return true;
}

// ---------------------------------------------------------------------------
// deriveV4OuterKey
//
// Derives the 32-byte outer AEAD key for v4 format using libsodium's
// crypto_kdf_derive_from_key with context "OCUI-V4O" and subkey id 3.
//
// master32 must point to exactly crypto_kdf_KEYBYTES (32) bytes.
// outerKey is set to a 32-byte QByteArray on success.
// Returns false on crypto failure.
// ---------------------------------------------------------------------------
/*static*/ bool EncryptionEngine::deriveV4OuterKey(const unsigned char* master32,
                                                    QByteArray& outerKey)
{
    outerKey.resize(32);
    // Context must be exactly 8 bytes: "OCUI-V4O"
    int rc = crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(outerKey.data()),
        static_cast<size_t>(outerKey.size()),
        3, // subkey id 3 = outer AEAD key
        "OCUI-V4O",
        master32);
    if (rc != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "deriveV4OuterKey: crypto_kdf_derive_from_key failed");
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// cryptOperationV4Encrypt
//
// Builds the v4 deniable on-disk format:
//
//   [salt 32][outer_iv 12][outer_ciphertext + GCM_tag 16]
//
// The outer_ciphertext (after AES-256-GCM decrypt) is the inner blob:
//
//   [magic "OCUI" 4][format_version=4 1][alg_id 1][kdf_id 1][rsv 1]
//   [iterations BE4][chunk_size BE4][chunk_count BE4]          (= 20 bytes)
//   for each chunk i: [ciphertext][tag 16]
//   [Ed25519 sig 64][pubkey 32]
//
// masterKeyBytes: raw KDF output (at least 32 bytes); zeroed on exit.
// ---------------------------------------------------------------------------
bool EncryptionEngine::cryptOperationV4Encrypt(QFile& inputFile, QFile& outputFile,
                                                const QByteArray& masterKeyBytes,
                                                const QByteArray& salt,
                                                const QByteArray& outerIv,
                                                quint8 algId, quint8 kId, int iterations,
                                                const QString& algorithm,
                                                const QString& /*outputPath*/)
{
    if (masterKeyBytes.size() < static_cast<int>(crypto_kdf_KEYBYTES)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: master key too short");
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 1: Derive three subkeys from the master.
    //   - outer key  (id=3, ctx="OCUI-V4O") — wraps the inner blob
    //   - enc key    (id=1, ctx="OCUI-KEY") — per-chunk chunk encryption
    //   - sig key    (id=2, ctx="OCUI-SIG") — Ed25519 signing seed
    // -----------------------------------------------------------------------
    unsigned char kdfMaster[crypto_kdf_KEYBYTES];
    memcpy(kdfMaster, masterKeyBytes.constData(), crypto_kdf_KEYBYTES);
    // masterKeyBytes is const; caller will zero it after this function returns.

    QByteArray outerKey;
    if (!deriveV4OuterKey(kdfMaster, outerKey)) {
        sodium_memzero(kdfMaster, sizeof(kdfMaster));
        return false;
    }

    QByteArray encKey(32, 0);
    QByteArray sigKey(static_cast<int>(crypto_sign_SEEDBYTES), 0);

    int rc1 = crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(encKey.data()), 32,
        1, "OCUI-KEY", kdfMaster);
    int rc2 = crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(sigKey.data()), crypto_sign_SEEDBYTES,
        2, "OCUI-SIG", kdfMaster);

    sodium_memzero(kdfMaster, sizeof(kdfMaster));

    if (rc1 != 0 || rc2 != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 encrypt: crypto_kdf_derive_from_key failed for enc/sig keys");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 2: Build the inner blob in a QByteArray buffer.
    //
    // Inner header (20 bytes):
    //   magic(4) + ver(1) + alg(1) + kdf(1) + rsv(1) + iters(4) +
    //   chunk_size(4) + chunk_count(4)
    // -----------------------------------------------------------------------
    const qint64 inputSize = inputFile.size();
    const qint64 chunkSz   = static_cast<qint64>(OCUI_CHUNK_SIZE);
    const quint32 chunkCount = static_cast<quint32>((inputSize + chunkSz - 1) / chunkSz);
    const quint32 effectiveCount = (chunkCount == 0) ? 1 : chunkCount;

    QByteArray innerBuf;
    innerBuf.reserve(20 + effectiveCount * (OCUI_CHUNK_SIZE + OCUI_GCM_TAG_SIZE) + 96);

    {
        // Inner OCUI header.
        QDataStream ds(&innerBuf, QIODevice::Append);
        ds.setByteOrder(QDataStream::BigEndian);
        ds << quint32(OCUI_MAGIC);
        ds << quint8(OCUI_FORMAT_VER_V4);
        ds << quint8(algId);
        ds << quint8(kId);
        ds << quint8(0); // reserved
        ds << quint32(static_cast<quint32>(iterations));
        ds << quint32(static_cast<quint32>(OCUI_CHUNK_SIZE));
        ds << quint32(effectiveCount);
    }

    // Encrypt chunks and append to innerBuf.
    if (!inputFile.seek(0)) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: failed to seek input");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    // Use the salt as "base_iv" for chunk nonce construction.
    // Since v4 has no separate base_iv on disk (it's inside the payload),
    // we use the first 12 bytes of the outer IV as the chunk base_iv.
    // This is safe: outer_iv is random per file.
    QByteArray baseIv = outerIv.left(12);

    QByteArray readBuf(OCUI_CHUNK_SIZE, 0);
    for (quint32 i = 0; i < effectiveCount; ++i) {
        qint64 bytesRead = inputFile.read(readBuf.data(), OCUI_CHUNK_SIZE);
        if (bytesRead < 0) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V4 encrypt: read error at chunk %1").arg(i));
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(sigKey.data(), sigKey.size());
            sodium_memzero(outerKey.data(), outerKey.size());
            return false;
        }
        QByteArray plain = (bytesRead > 0) ? readBuf.left(static_cast<int>(bytesRead))
                                           : QByteArray();

        QByteArray nonce = buildChunkNonce(baseIv, i);
        if (nonce.isEmpty()) {
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(sigKey.data(), sigKey.size());
            sodium_memzero(outerKey.data(), outerKey.size());
            return false;
        }

        QByteArray ct = encryptChunk(encKey, nonce, plain, algorithm);
        if (ct.isEmpty()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V4 encrypt: encryptChunk failed at chunk %1").arg(i));
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(sigKey.data(), sigKey.size());
            sodium_memzero(outerKey.data(), outerKey.size());
            return false;
        }
        innerBuf.append(ct);
    }
    sodium_memzero(encKey.data(), encKey.size());

    // -----------------------------------------------------------------------
    // Step 3: Sign the inner blob (everything so far) with Ed25519.
    // Append sig(64) + pubkey(32) to innerBuf.
    // -----------------------------------------------------------------------
    {
        QByteArray pubKey(crypto_sign_PUBLICKEYBYTES, 0);
        QByteArray secKey(crypto_sign_SECRETKEYBYTES, 0);
        crypto_sign_seed_keypair(
            reinterpret_cast<unsigned char*>(pubKey.data()),
            reinterpret_cast<unsigned char*>(secKey.data()),
            reinterpret_cast<const unsigned char*>(sigKey.constData()));

        // Hash the inner blob so far.
        unsigned char hash[EVP_MAX_MD_SIZE] = {};
        unsigned int hashLen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            sodium_memzero(secKey.data(), secKey.size());
            sodium_memzero(sigKey.data(), sigKey.size());
            sodium_memzero(outerKey.data(), outerKey.size());
            return false;
        }
        bool hashOk =
            EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, innerBuf.constData(), innerBuf.size()) == 1 &&
            EVP_DigestFinal_ex(ctx, hash, &hashLen) == 1;
        EVP_MD_CTX_free(ctx);

        if (!hashOk) {
            sodium_memzero(secKey.data(), secKey.size());
            sodium_memzero(sigKey.data(), sigKey.size());
            sodium_memzero(outerKey.data(), outerKey.size());
            return false;
        }

        QByteArray sig(crypto_sign_BYTES, 0);
        unsigned long long sigLen = 0;
        crypto_sign_detached(
            reinterpret_cast<unsigned char*>(sig.data()), &sigLen,
            hash, hashLen,
            reinterpret_cast<const unsigned char*>(secKey.constData()));

        sodium_memzero(secKey.data(), secKey.size());
        sodium_memzero(hash, sizeof(hash));
        sig.resize(static_cast<int>(sigLen));
        innerBuf.append(sig);
        innerBuf.append(pubKey);
    }
    sodium_memzero(sigKey.data(), sigKey.size());

    // -----------------------------------------------------------------------
    // Step 4: Outer AES-256-GCM encrypt innerBuf.
    //   Output: [inner ciphertext][16-byte GCM tag]
    // The outer IV is always 12 bytes (GCM standard nonce length).
    // -----------------------------------------------------------------------
    const EVP_CIPHER* outerCipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    if (!ectx) {
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    auto ctxGuard = qScopeGuard([ectx]() { EVP_CIPHER_CTX_free(ectx); });

    // Force GCM IV length to 12 bytes.
    if (EVP_EncryptInit_ex(ectx, outerCipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ectx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(outerKey.constData()),
            reinterpret_cast<const unsigned char*>(outerIv.constData())) != 1) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: outer GCM init failed");
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }
    sodium_memzero(outerKey.data(), outerKey.size());

    QByteArray outerCt(innerBuf.size() + OCUI_GCM_TAG_SIZE + 16, 0);
    int outLen = 0;
    if (EVP_EncryptUpdate(ectx,
            reinterpret_cast<unsigned char*>(outerCt.data()), &outLen,
            reinterpret_cast<const unsigned char*>(innerBuf.constData()),
            innerBuf.size()) != 1) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: outer GCM update failed");
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }
    sodium_memzero(innerBuf.data(), innerBuf.size()); // wipe inner plaintext

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ectx,
            reinterpret_cast<unsigned char*>(outerCt.data()) + outLen, &finalLen) != 1) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: outer GCM final failed");
        return false;
    }
    outLen += finalLen;
    outerCt.resize(outLen);

    QByteArray outerTag(OCUI_GCM_TAG_SIZE, 0);
    if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, OCUI_GCM_TAG_SIZE, outerTag.data()) != 1) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 encrypt: outer GCM get tag failed");
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 5: Write salt || outer_iv || outer_ciphertext || outer_tag.
    // -----------------------------------------------------------------------
    outputFile.seek(0);
    outputFile.write(salt);          // 32 bytes
    outputFile.write(outerIv);       // 12 bytes
    outputFile.write(outerCt);       // innerBuf.size() bytes (encrypted)
    outputFile.write(outerTag);      // 16 bytes

    SECURE_LOG(DEBUG, "EncryptionEngine",
        QString("V4 encrypt: wrote %1 bytes (salt+iv+ct+tag), %2 chunks")
        .arg(32 + 12 + outerCt.size() + 16).arg(effectiveCount));
    return true;
}

// ---------------------------------------------------------------------------
// cryptOperationV4Decrypt
//
// Reads a v4 file: salt(32) || outer_iv(12) || outer_ct+tag.
// Returns false if outer AEAD fails (wrong password OR not a v4 file).
// On success, writes decrypted plaintext to outputFile.
// ---------------------------------------------------------------------------
bool EncryptionEngine::cryptOperationV4Decrypt(QFile& inputFile, QFile& outputFile,
                                                const QString& password,
                                                const QStringList& keyfilePaths,
                                                const QString& algorithm,
                                                const QString& kdf,
                                                int iterations,
                                                const QString& /*inputPath*/)
{
    // Minimum v4 file size: salt(32) + iv(12) + inner_min + tag(16)
    // inner_min includes at least the 20-byte inner header + sig(64) + pubkey(32) = 116
    // Plus at least one empty chunk (tag only) = 16
    // Plus outer tag = 16.  Total minimum ~ 32+12+116+16+16 = 192 bytes.
    if (inputFile.size() < 192) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: file too small");
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 1: Read salt(32) and outer_iv(12).
    // -----------------------------------------------------------------------
    if (!inputFile.seek(0)) return false;
    QByteArray v4Salt(32, 0);
    QByteArray v4Iv(12, 0);
    if (inputFile.read(v4Salt.data(), 32) != 32 ||
        inputFile.read(v4Iv.data(), 12)   != 12) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: failed to read salt/iv");
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 2: Derive master key, then outer key.
    // -----------------------------------------------------------------------
    QByteArray master = deriveKey(password, v4Salt, keyfilePaths, kdf, iterations);
    if (master.isEmpty()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 decrypt: key derivation failed");
        return false;
    }
    if (master.size() < static_cast<int>(crypto_kdf_KEYBYTES)) {
        sodium_memzero(master.data(), master.size());
        return false;
    }

    unsigned char kdfMaster[crypto_kdf_KEYBYTES];
    memcpy(kdfMaster, master.constData(), crypto_kdf_KEYBYTES);
    sodium_memzero(master.data(), master.size());

    QByteArray outerKey;
    if (!deriveV4OuterKey(kdfMaster, outerKey)) {
        sodium_memzero(kdfMaster, sizeof(kdfMaster));
        return false;
    }

    QByteArray encKey(32, 0);
    QByteArray sigKey(static_cast<int>(crypto_sign_SEEDBYTES), 0);
    int rc1 = crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(encKey.data()), 32,
        1, "OCUI-KEY", kdfMaster);
    int rc2 = crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(sigKey.data()), crypto_sign_SEEDBYTES,
        2, "OCUI-SIG", kdfMaster);
    sodium_memzero(kdfMaster, sizeof(kdfMaster));

    if (rc1 != 0 || rc2 != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 decrypt: subkey derivation failed");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 3: Outer AES-256-GCM decrypt.
    //   Ciphertext = everything from offset 44 to size-16.
    //   Tag = last 16 bytes.
    // -----------------------------------------------------------------------
    const qint64 ctStart  = 44; // 32 + 12
    const qint64 fileSize = inputFile.size();
    const qint64 ctLen    = fileSize - ctStart - OCUI_GCM_TAG_SIZE;
    if (ctLen <= 0) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: outer ciphertext length invalid");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    // Read ciphertext + tag.
    if (!inputFile.seek(ctStart)) {
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }
    QByteArray outerCt = inputFile.read(ctLen);
    QByteArray outerTag = inputFile.read(OCUI_GCM_TAG_SIZE);
    if (outerCt.size() != static_cast<int>(ctLen) ||
        outerTag.size() != OCUI_GCM_TAG_SIZE) {
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }

    const EVP_CIPHER* outerCipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    if (!dctx) {
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }
    auto ctxGuard = qScopeGuard([dctx]() { EVP_CIPHER_CTX_free(dctx); });

    if (EVP_DecryptInit_ex(dctx, outerCipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(dctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(outerKey.constData()),
            reinterpret_cast<const unsigned char*>(v4Iv.constData())) != 1) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: outer GCM init failed");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(outerKey.data(), outerKey.size());
        return false;
    }
    sodium_memzero(outerKey.data(), outerKey.size());

    if (EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, OCUI_GCM_TAG_SIZE, outerTag.data()) != 1) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: set outer GCM tag failed");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        return false;
    }

    QByteArray innerBuf(static_cast<int>(ctLen) + 16, 0);
    int outLen = 0;
    if (EVP_DecryptUpdate(dctx,
            reinterpret_cast<unsigned char*>(innerBuf.data()), &outLen,
            reinterpret_cast<const unsigned char*>(outerCt.constData()),
            static_cast<int>(ctLen)) != 1) {
        SECURE_LOG(DEBUG, "EncryptionEngine", "V4 decrypt: outer GCM update failed");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(dctx,
            reinterpret_cast<unsigned char*>(innerBuf.data()) + outLen, &finalLen) <= 0) {
        // AEAD authentication failed — wrong password OR not a v4 file.
        SECURE_LOG(DEBUG, "EncryptionEngine",
            "V4 decrypt: outer GCM authentication FAILED (wrong password or not v4)");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }
    outLen += finalLen;
    innerBuf.resize(outLen);

    // -----------------------------------------------------------------------
    // Step 4: Parse inner OCUI v4 header from innerBuf.
    // -----------------------------------------------------------------------
    if (innerBuf.size() < 20) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine", "V4 decrypt: inner blob too small");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    quint32 innerMagic     = 0;
    quint8  innerVer       = 0;
    quint8  innerAlgId     = 0;
    quint8  innerKdfId     = 0;
    quint8  innerRsv       = 0;
    quint32 innerIters     = 0;
    quint32 innerChunkSize = 0;
    quint32 innerChunkCnt  = 0;

    {
        // Read 20 bytes: magic(4)+ver(1)+alg(1)+kdf(1)+rsv(1)+iters(4)+chunk_size(4)+chunk_count(4)
        const unsigned char* p = reinterpret_cast<const unsigned char*>(innerBuf.constData());
        innerMagic     = (quint32(p[0]) << 24) | (quint32(p[1]) << 16) |
                         (quint32(p[2]) <<  8) |  quint32(p[3]);
        innerVer       = p[4];
        innerAlgId     = p[5];
        innerKdfId     = p[6];
        innerRsv       = p[7]; (void)innerRsv;
        innerIters     = (quint32(p[8]) << 24)  | (quint32(p[9]) << 16)  |
                         (quint32(p[10]) <<  8) |  quint32(p[11]);
        innerChunkSize = (quint32(p[12]) << 24) | (quint32(p[13]) << 16) |
                         (quint32(p[14]) <<  8) |  quint32(p[15]);
        innerChunkCnt  = (quint32(p[16]) << 24) | (quint32(p[17]) << 16) |
                         (quint32(p[18]) <<  8) |  quint32(p[19]);
    }

    if (innerMagic != OCUI_MAGIC || innerVer != OCUI_FORMAT_VER_V4) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: inner blob has wrong magic or version");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    // Validate alg/kdf match what caller requested.
    const quint8 callerAlgId = algorithmId(algorithm);
    const quint8 callerKdfId = kdfId(kdf);
    if (innerAlgId != callerAlgId || innerKdfId != callerKdfId) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: algorithm/KDF mismatch in inner header");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    // Enforce PBKDF2 floor.
    if (innerKdfId == KDF_ID_PBKDF2 && innerIters < 600000) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: PBKDF2 iterations below floor");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    if (innerChunkSize == 0 || innerChunkCnt == 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: inner chunk_size or chunk_count is zero");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 5: Verify Ed25519 signature in the inner blob.
    //
    // Layout of innerBuf after header (20 bytes):
    //   [chunk data ...][sig 64][pubkey 32]
    //
    // The signature covers innerBuf[0 .. N-96) where N = innerBuf.size().
    // -----------------------------------------------------------------------
    const int sigAndKey = static_cast<int>(crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES);
    if (innerBuf.size() < 20 + sigAndKey) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: inner blob too small to contain signature");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(sigKey.data(), sigKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    const int signedLen   = innerBuf.size() - sigAndKey;
    const unsigned char* sigBytes = reinterpret_cast<const unsigned char*>(
        innerBuf.constData() + signedLen);
    const unsigned char* pubKeyBytes = sigBytes + crypto_sign_BYTES;

    // Verify the stored public key matches what we'd derive from sigKey.
    QByteArray expectedPub(crypto_sign_PUBLICKEYBYTES, 0);
    QByteArray derivedSec(crypto_sign_SECRETKEYBYTES, 0);
    crypto_sign_seed_keypair(
        reinterpret_cast<unsigned char*>(expectedPub.data()),
        reinterpret_cast<unsigned char*>(derivedSec.data()),
        reinterpret_cast<const unsigned char*>(sigKey.constData()));
    sodium_memzero(derivedSec.data(), derivedSec.size());
    sodium_memzero(sigKey.data(), sigKey.size());

    if (sodium_memcmp(pubKeyBytes, expectedPub.constData(), crypto_sign_PUBLICKEYBYTES) != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: public key mismatch — file tampered or wrong password");
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }

    // Hash signed region and verify.
    unsigned char hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hashLen = 0;
    {
        EVP_MD_CTX* hctx = EVP_MD_CTX_new();
        if (!hctx) {
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }
        bool hashOk =
            EVP_DigestInit_ex(hctx, EVP_sha512(), nullptr) == 1 &&
            EVP_DigestUpdate(hctx, innerBuf.constData(), signedLen) == 1 &&
            EVP_DigestFinal_ex(hctx, hash, &hashLen) == 1;
        EVP_MD_CTX_free(hctx);
        if (!hashOk) {
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }
    }

    if (crypto_sign_verify_detached(sigBytes, hash, hashLen, pubKeyBytes) != 0) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
            "V4 decrypt: Ed25519 signature verification FAILED — file tampered");
        sodium_memzero(hash, sizeof(hash));
        sodium_memzero(encKey.data(), encKey.size());
        sodium_memzero(innerBuf.data(), innerBuf.size());
        return false;
    }
    sodium_memzero(hash, sizeof(hash));

    // -----------------------------------------------------------------------
    // Step 6: Decrypt chunks and write plaintext to outputFile.
    //
    // Chunk data starts at innerBuf offset 20 and ends at signedLen.
    // Use the outer IV's first 12 bytes as base_iv (same as encrypt side).
    // -----------------------------------------------------------------------
    QByteArray baseIv = v4Iv.left(12);
    qint64 pos = 20; // after inner header
    const qint64 chunkDataEnd = static_cast<qint64>(signedLen);

    for (quint32 i = 0; i < innerChunkCnt; ++i) {
        const qint64 remaining = chunkDataEnd - pos;
        if (remaining < static_cast<qint64>(OCUI_GCM_TAG_SIZE)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V4 decrypt: not enough data for chunk %1").arg(i));
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }

        qint64 toRead;
        if (i < innerChunkCnt - 1) {
            toRead = static_cast<qint64>(innerChunkSize) + OCUI_GCM_TAG_SIZE;
        } else {
            toRead = remaining;
        }

        if (pos + toRead > chunkDataEnd) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V4 decrypt: chunk %1 extends beyond signed region").arg(i));
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }

        QByteArray raw = innerBuf.mid(static_cast<int>(pos), static_cast<int>(toRead));
        pos += toRead;

        QByteArray nonce = buildChunkNonce(baseIv, i);
        if (nonce.isEmpty()) {
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }

        QByteArray plain = decryptChunk(encKey, nonce, raw, algorithm);
        if (plain.isEmpty() && raw.size() > OCUI_GCM_TAG_SIZE) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                QString("V4 decrypt: AEAD authentication FAILED at chunk %1").arg(i));
            sodium_memzero(encKey.data(), encKey.size());
            sodium_memzero(innerBuf.data(), innerBuf.size());
            return false;
        }

        if (!plain.isEmpty()) {
            if (outputFile.write(plain) != plain.size()) {
                SECURE_LOG(ERROR_LEVEL, "EncryptionEngine",
                    QString("V4 decrypt: write failed at chunk %1").arg(i));
                sodium_memzero(encKey.data(), encKey.size());
                sodium_memzero(innerBuf.data(), innerBuf.size());
                return false;
            }
        }
    }

    sodium_memzero(encKey.data(), encKey.size());
    sodium_memzero(innerBuf.data(), innerBuf.size());

    SECURE_LOG(DEBUG, "EncryptionEngine",
        QString("V4 decrypt: successfully decrypted %1 chunks").arg(innerChunkCnt));
    return true;
}
