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
