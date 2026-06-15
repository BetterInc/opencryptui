#include "deniable_container.h"
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <cstring>

// Header plaintext (encrypted inside each slot), 76 bytes:
//   magic(8) "OCUIVOL1" | ver(1) | kind(1) | pad(6) |
//   dataOffset(8 BE) | dataLen(8 BE) | baseNonce(12) | dataKey(32)
static const char   HDR_MAGIC[8] = {'O','C','U','I','V','O','L','1'};
static constexpr int HDR_PT_LEN  = 8 + 1 + 1 + 6 + 8 + 8 + 12 + 32; // 76
static constexpr int SALT_LEN    = 32;
static constexpr int NONCE_LEN   = 12;
static constexpr int TAG_LEN     = 16;
static constexpr qint64 CHUNK    = 1 << 20; // 1 MiB, matches engine chunking

static void put64(unsigned char* p, quint64 v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<unsigned char>((v >> (56 - 8*i)) & 0xFF);
}
static quint64 get64(const unsigned char* p) {
    quint64 v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

qint64 DeniableContainer::chunkedSize(qint64 plainLen)
{
    if (plainLen <= 0) return 0;
    const qint64 nChunks = (plainLen + CHUNK - 1) / CHUNK;
    return plainLen + nChunks * TAG_LEN;
}

qint64 DeniableContainer::minSize(qint64 outerLen, qint64 hiddenLen)
{
    return DATA_OFF + chunkedSize(outerLen) + chunkedSize(hiddenLen);
}

// Fill [offset, offset+len) of an open file with CSPRNG random bytes.
static bool fillRandom(QFile& f, qint64 offset, qint64 len)
{
    if (!f.seek(offset)) return false;
    QByteArray block(1 << 20, 0);
    qint64 remaining = len;
    while (remaining > 0) {
        const int n = static_cast<int>(qMin<qint64>(remaining, block.size()));
        if (RAND_bytes(reinterpret_cast<unsigned char*>(block.data()), n) != 1)
            return false;
        if (f.write(block.constData(), n) != n) return false;
        remaining -= n;
    }
    return true;
}

// Build one 136-byte header preamble: salt | nonce | AES-256-GCM(plaintext)+tag.
// headerKey = first 32 bytes of deriveKey(password, salt).
static QByteArray buildHeaderSlot(EncryptionEngine& eng, const QString& password,
                                  const QString& kdf, int iterations,
                                  quint8 kind, quint64 dataOffset, quint64 dataLen,
                                  const QByteArray& baseNonce, const QByteArray& dataKey)
{
    QByteArray salt(SALT_LEN, 0);
    QByteArray nonce(NONCE_LEN, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), SALT_LEN) != 1) return {};
    if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), NONCE_LEN) != 1) return {};

    QByteArray master = eng.deriveKey(password, salt, {}, kdf, iterations);
    if (master.size() < 32) { if(!master.isEmpty()) sodium_memzero(master.data(), master.size()); return {}; }
    QByteArray headerKey = master.left(32);
    sodium_memzero(master.data(), master.size());

    // Assemble plaintext.
    QByteArray pt(HDR_PT_LEN, 0);
    unsigned char* p = reinterpret_cast<unsigned char*>(pt.data());
    memcpy(p, HDR_MAGIC, 8);
    p[8] = 1;            // version
    p[9] = kind;         // 1=outer, 2=hidden
    // p[10..15] reserved (zero)
    put64(p + 16, dataOffset);
    put64(p + 24, dataLen);
    memcpy(p + 32, baseNonce.constData(), NONCE_LEN);     // 32..43
    memcpy(p + 44, dataKey.constData(), 32);              // 44..75

    // AES-256-GCM encrypt.
    QByteArray out = salt + nonce;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bool ok = ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(headerKey.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData())) == 1;
    QByteArray ct(HDR_PT_LEN, 0);
    int outLen = 0, finalLen = 0;
    if (ok) ok = EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ct.data()), &outLen,
                                   p, HDR_PT_LEN) == 1;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ct.data()) + outLen, &finalLen) == 1;
    QByteArray tag(TAG_LEN, 0);
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) == 1;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    sodium_memzero(headerKey.data(), headerKey.size());
    sodium_memzero(pt.data(), pt.size());
    if (!ok) return {};

    out += ct + tag;
    return out; // 32 + 12 + 76 + 16 = 136 bytes
}

// Try to open a header slot. On success returns true and fills the out-params.
// dataKeyOut is the (sensitive) per-volume data key — caller must wipe it.
static bool tryOpenSlot(EncryptionEngine& eng, QFile& f, qint64 slotOffset,
                        const QString& password, const QString& kdf, int iterations,
                        quint8& kindOut, quint64& dataOffsetOut, quint64& dataLenOut,
                        QByteArray& baseNonceOut, QByteArray& dataKeyOut)
{
    if (!f.seek(slotOffset)) return false;
    QByteArray pre = f.read(SALT_LEN + NONCE_LEN + HDR_PT_LEN + TAG_LEN); // 136
    if (pre.size() != SALT_LEN + NONCE_LEN + HDR_PT_LEN + TAG_LEN) return false;

    QByteArray salt  = pre.left(SALT_LEN);
    QByteArray nonce = pre.mid(SALT_LEN, NONCE_LEN);
    QByteArray ct    = pre.mid(SALT_LEN + NONCE_LEN, HDR_PT_LEN);
    QByteArray tag   = pre.right(TAG_LEN);

    QByteArray master = eng.deriveKey(password, salt, {}, kdf, iterations);
    if (master.size() < 32) { if(!master.isEmpty()) sodium_memzero(master.data(), master.size()); return false; }
    QByteArray headerKey = master.left(32);
    sodium_memzero(master.data(), master.size());

    QByteArray pt(HDR_PT_LEN, 0);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bool ok = ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(headerKey.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData())) == 1;
    int outLen = 0, finalLen = 0;
    if (ok) ok = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(pt.data()), &outLen,
                                   reinterpret_cast<const unsigned char*>(ct.constData()), HDR_PT_LEN) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data()) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(pt.data()) + outLen, &finalLen) > 0;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    sodium_memzero(headerKey.data(), headerKey.size());

    if (!ok) { sodium_memzero(pt.data(), pt.size()); return false; } // wrong password / not this slot

    const unsigned char* p = reinterpret_cast<const unsigned char*>(pt.constData());
    if (sodium_memcmp(p, HDR_MAGIC, 8) != 0) { sodium_memzero(pt.data(), pt.size()); return false; }

    kindOut       = p[9];
    dataOffsetOut = get64(p + 16);
    dataLenOut    = get64(p + 24);
    baseNonceOut  = QByteArray(reinterpret_cast<const char*>(p + 32), NONCE_LEN);
    dataKeyOut    = QByteArray(reinterpret_cast<const char*>(p + 44), 32);
    sodium_memzero(pt.data(), pt.size());
    return true;
}

// Encrypt `data` as AES-256-GCM chunks and write at fileOffset.
static bool writeDataRegion(QFile& f, qint64 fileOffset, const QByteArray& data,
                            const QByteArray& dataKey, const QByteArray& baseNonce)
{
    if (!f.seek(fileOffset)) return false;
    const qint64 len = data.size();
    const qint64 nChunks = (len + CHUNK - 1) / CHUNK;
    for (qint64 i = 0; i < nChunks; ++i) {
        const qint64 off = i * CHUNK;
        const int n = static_cast<int>(qMin<qint64>(CHUNK, len - off));
        QByteArray nonce = EncryptionEngine::buildChunkNonce(baseNonce, static_cast<quint32>(i));
        QByteArray ct = EncryptionEngine::encryptChunk(dataKey, nonce, data.mid(static_cast<int>(off), n), "AES-256-GCM");
        if (ct.isEmpty()) return false;
        if (f.write(ct.constData(), ct.size()) != ct.size()) return false;
    }
    return true;
}

// Read+decrypt a chunked data region. Returns empty + ok=false on auth failure.
static QByteArray readDataRegion(QFile& f, qint64 fileOffset, qint64 plainLen,
                                 const QByteArray& dataKey, const QByteArray& baseNonce, bool* ok)
{
    *ok = false;
    QByteArray out;
    out.reserve(static_cast<int>(plainLen));
    const qint64 nChunks = (plainLen + CHUNK - 1) / CHUNK;
    qint64 pos = fileOffset;
    for (qint64 i = 0; i < nChunks; ++i) {
        const int n = static_cast<int>(qMin<qint64>(CHUNK, plainLen - i * CHUNK));
        const int onDisk = n + TAG_LEN;
        if (!f.seek(pos)) return {};
        QByteArray raw = f.read(onDisk);
        if (raw.size() != onDisk) return {};
        pos += onDisk;
        QByteArray nonce = EncryptionEngine::buildChunkNonce(baseNonce, static_cast<quint32>(i));
        QByteArray plain = EncryptionEngine::decryptChunk(dataKey, nonce, raw, "AES-256-GCM");
        if (plain.isEmpty() && n > 0) return {}; // auth failure (real ciphertext didn't verify)
        out.append(plain);
    }
    *ok = true;
    return out;
}

bool DeniableContainer::create(EncryptionEngine& eng,
                               const QString& path, qint64 sizeBytes,
                               const QString& outerPassword, const QByteArray& outerData,
                               const QString& kdf, int iterations,
                               const QString& hiddenPassword, const QByteArray& hiddenData,
                               QString* error)
{
    auto fail = [&](const QString& m) { if (error) *error = m; SECURE_LOG(ERROR_LEVEL, "DeniableContainer", m); return false; };

    const bool hasHidden = !hiddenPassword.isEmpty();
    const qint64 outerOnDisk  = chunkedSize(outerData.size());
    const qint64 hiddenOnDisk = hasHidden ? chunkedSize(hiddenData.size()) : 0;

    if (sizeBytes < minSize(outerData.size(), hasHidden ? hiddenData.size() : 0))
        return fail("Container size too small for the requested data.");
    if (hasHidden && outerPassword == hiddenPassword)
        return fail("Outer and hidden passwords must differ.");
    // No-overlap: outer data (front) must not reach the hidden data (tail).
    const qint64 hiddenDataOffset = sizeBytes - hiddenOnDisk;
    if (hasHidden && (DATA_OFF + outerOnDisk > hiddenDataOffset))
        return fail("Outer data would overlap the hidden volume; use a larger container.");

    QFile f(path);
    if (!f.open(QIODevice::ReadWrite | QIODevice::Truncate))
        return fail("Cannot open container path for writing.");
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (!f.resize(sizeBytes)) { f.close(); return fail("Cannot size the container."); }

    // 1) Fill the ENTIRE file with CSPRNG random. This is what makes the
    //    (absent) hidden header and all free space indistinguishable from real
    //    encrypted data.
    if (!fillRandom(f, 0, sizeBytes)) { f.close(); QFile::remove(path); return fail("Random fill failed."); }

    // 2) Outer header + data.
    QByteArray outerKey(32, 0), outerNonce(NONCE_LEN, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(outerKey.data()), 32);
    RAND_bytes(reinterpret_cast<unsigned char*>(outerNonce.data()), NONCE_LEN);
    QByteArray outerHdr = buildHeaderSlot(eng, outerPassword, kdf, iterations,
                                          1, DATA_OFF, outerData.size(), outerNonce, outerKey);
    bool ok = !outerHdr.isEmpty();
    if (ok) { f.seek(OUTER_HDR_OFF); ok = f.write(outerHdr) == outerHdr.size(); }
    if (ok) ok = writeDataRegion(f, DATA_OFF, outerData, outerKey, outerNonce);
    sodium_memzero(outerKey.data(), outerKey.size());
    if (!ok) { f.close(); QFile::remove(path); return fail("Failed to write outer volume."); }

    // 3) Hidden header + data (tail), only if requested.
    if (hasHidden) {
        QByteArray hKey(32, 0), hNonce(NONCE_LEN, 0);
        RAND_bytes(reinterpret_cast<unsigned char*>(hKey.data()), 32);
        RAND_bytes(reinterpret_cast<unsigned char*>(hNonce.data()), NONCE_LEN);
        QByteArray hHdr = buildHeaderSlot(eng, hiddenPassword, kdf, iterations,
                                          2, static_cast<quint64>(hiddenDataOffset),
                                          hiddenData.size(), hNonce, hKey);
        bool hok = !hHdr.isEmpty();
        if (hok) { f.seek(HIDDEN_HDR_OFF); hok = f.write(hHdr) == hHdr.size(); }
        if (hok) hok = writeDataRegion(f, hiddenDataOffset, hiddenData, hKey, hNonce);
        sodium_memzero(hKey.data(), hKey.size());
        if (!hok) { f.close(); QFile::remove(path); return fail("Failed to write hidden volume."); }
    }

    f.flush();
    f.close();
    return true;
}

DeniableContainer::OpenResult DeniableContainer::open(EncryptionEngine& eng, const QString& path,
                                                      const QString& password,
                                                      const QString& kdf, int iterations)
{
    OpenResult r;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) { r.error = "Cannot open container."; return r; }
    if (f.size() < DATA_OFF) { r.error = "File too small to be a container."; return r; }

    // Try the outer slot first, then the hidden slot. The password selects the
    // volume; trying both means the outer password yields the decoy and the
    // hidden password yields the hidden volume, with no external tell.
    const qint64 offsets[2] = { OUTER_HDR_OFF, HIDDEN_HDR_OFF };
    for (qint64 slot : offsets) {
        quint8 kind = 0; quint64 dataOffset = 0, dataLen = 0;
        QByteArray baseNonce, dataKey;
        if (!tryOpenSlot(eng, f, slot, password, kdf, iterations,
                         kind, dataOffset, dataLen, baseNonce, dataKey))
            continue;

        // Sanity-bound the advertised data region against the file.
        if (static_cast<qint64>(dataOffset) < DATA_OFF ||
            static_cast<qint64>(dataOffset) + chunkedSize(static_cast<qint64>(dataLen)) > f.size()) {
            sodium_memzero(dataKey.data(), dataKey.size());
            r.error = "Container header inconsistent."; return r;
        }

        bool dok = false;
        QByteArray data = readDataRegion(f, static_cast<qint64>(dataOffset),
                                         static_cast<qint64>(dataLen), dataKey, baseNonce, &dok);
        sodium_memzero(dataKey.data(), dataKey.size());
        if (!dok) { r.error = "Container data failed authentication (tampered)."; return r; }

        r.ok = true;
        r.kind = (kind == 2) ? VolumeKind::Hidden : VolumeKind::Outer;
        r.data = data;
        return r;
    }

    r.error = "Wrong password, or not an OpenCryptUI container.";
    return r;
}
