// hwkey_stub.cpp — Software-only, always-compiling HwKey implementation.
//
// PURPOSE:
//   This translation unit provides the fallback implementation that compiles
//   and links on every platform, with no dependency on TPM, Secure Enclave,
//   or CNG headers. It is used:
//     (a) directly when no hardware backend is present (Backend::None), and
//     (b) as the actual wrap/unwrap path called by platform TUs while real
//         hardware APIs are not yet implemented (scaffolding phase).
//
// TWO-LAYER WRAP FORMAT (wrappedBlob_v2):
// ============================================================================
//
//   Outer layer (AES-256-GCM, "meta-wrap"):
//     [ nonce      12 bytes — uniformly random per wrap call ]
//     [ ciphertext  N bytes — AES-256-GCM(K_meta, innerBlob || backendId) ]
//     [ GCM tag    16 bytes ]
//
//   Inner layer (ChaCha20-Poly1305, "stub wrap"):
//     [ magic    2 bytes : 0x4F 0x43 "OC" ]
//     [ version  1 byte : 0x01            ]
//     [ nonce   12 bytes                  ]
//     [ ciphertext  len(dek) bytes        ]
//     [ Poly1305 tag 16 bytes             ]
//
//   The inner layer is produced by Stub::wrapKeyInner() using ChaCha20-Poly1305
//   with K_meta (same per-installation key). The outer layer then re-encrypts
//   the inner blob plus a 1-byte backendId using AES-256-GCM with K_meta.
//
//   Forensic view: the on-disk blob starts with 12 uniformly random bytes
//   (the outer nonce). There is no magic header, no backend-identifying
//   structure, and no ASN.1 or TPM2_PUBLIC marker visible to an external scan.
//   Every wrapped blob looks identical in structure regardless of which
//   backend produced the inner blob.
//
// K_meta (per-installation key):
//   32 random bytes written at QStandardPaths::AppDataLocation +
//   "/.opencryptui-stubkey" on first use, mode 0600.
//
// SECURITY PROPERTIES:
//   - Outer AES-256-GCM tag provides integrity for both the DEK ciphertext
//     and the backendId. Flipping any byte in the blob causes unwrapKey() to
//     return empty and set errorOut.
//   - K_meta is tied to this user account on this machine (file permissions
//     0600). An attacker with local read access to the data directory can
//     recover K_meta, so this is NOT equivalent to hardware protection.
//   - The two-layer design ensures that when real backend blobs (TPM2_PRIVATE,
//     PKCS#11 CKO_SECRET_KEY ciphertext, etc.) are introduced in future, the
//     outer AEAD envelope will uniformly conceal their structure on disk.
//
// NOTE: Do not remove or weaken the AEAD layers — tamper-detection tests
//       rely on the tag checks in both layers.

#include "hwkey.h"

#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstring>

// ---------------------------------------------------------------------------
// Internal namespace — not exposed outside this TU.
// ---------------------------------------------------------------------------
namespace {

// Inner-layer (ChaCha20-Poly1305) wire-format constants.
constexpr unsigned char kMagic0 = 0x4F; // 'O'
constexpr unsigned char kMagic1 = 0x43; // 'C'
constexpr unsigned char kInnerVersion = 0x01;
constexpr int kInnerHeaderSize = 3;    // magic(2) + version(1)
constexpr int kInnerNonceSize  = 12;   // 96-bit nonce for ChaCha20-Poly1305
constexpr int kInnerTagSize    = 16;   // 128-bit Poly1305 tag

// Outer-layer (AES-256-GCM) wire-format constants.
constexpr int kOuterNonceSize  = 12;   // 96-bit nonce for AES-256-GCM
constexpr int kOuterTagSize    = 16;   // 128-bit GCM tag
// The outer plaintext appends a 1-byte backendId to the inner blob.
constexpr int kBackendIdSize   = 1;

// Shared key material.
constexpr int kWrapKeySize     = 32;   // 256-bit AES / ChaCha20 key (K_meta)

// Backend ID byte embedded in the outer AEAD envelope.
// Allows future backends to embed their own blob while keeping the outer
// format stable. The stub always uses 0x00.
constexpr unsigned char kBackendIdStub = 0x00;

// ---------------------------------------------------------------------------
// stubKeyPath() — canonical location for the per-user wrapping key file.
// ---------------------------------------------------------------------------
static QString stubKeyPath()
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return dir + QLatin1String("/.opencryptui-stubkey");
}

// ---------------------------------------------------------------------------
// loadOrCreateStubKey() — load existing K_meta or generate+persist a new one.
//   Returns 32-byte key on success, empty on error.
// ---------------------------------------------------------------------------
static QByteArray loadOrCreateStubKey(QString* errorOut)
{
    const QString path = stubKeyPath();

    // Ensure the parent directory exists.
    QDir dir = QFileInfo(path).absoluteDir();
    if (!dir.exists()) {
        if (!dir.mkpath(dir.absolutePath())) {
            if (errorOut)
                *errorOut = QString("HwKey::Stub: cannot create data directory: %1")
                                .arg(dir.absolutePath());
            return {};
        }
    }

    QFile f(path);

    // --- Load existing key ---------------------------------------------------
    if (f.exists()) {
        if (!f.open(QIODevice::ReadOnly)) {
            if (errorOut)
                *errorOut = QString("HwKey::Stub: cannot read stub key file: %1")
                                .arg(path);
            return {};
        }
        QByteArray key = f.readAll();
        f.close();
        if (key.size() != kWrapKeySize) {
            if (errorOut)
                *errorOut = QString("HwKey::Stub: stub key file has wrong size "
                                    "(got %1, want %2)")
                                .arg(key.size()).arg(kWrapKeySize);
            return {};
        }
        return key;
    }

    // --- Generate new key and persist it -------------------------------------
    QByteArray newKey(kWrapKeySize, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(newKey.data()),
                   kWrapKeySize) != 1) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: RAND_bytes failed generating stub key");
        return {};
    }

    // Open with O_CREAT|O_EXCL semantics via QIODevice::NewOnly so a race
    // between two processes can't silently clobber an existing key.
    if (!f.open(QIODevice::WriteOnly | QIODevice::NewOnly)) {
        // Another process may have written it between our exists() check and now.
        // Try reading instead.
        if (f.open(QIODevice::ReadOnly)) {
            QByteArray existing = f.readAll();
            f.close();
            if (existing.size() == kWrapKeySize)
                return existing;
        }
        if (errorOut)
            *errorOut = QString("HwKey::Stub: cannot write stub key file: %1")
                            .arg(path);
        return {};
    }

    // Set permissions to owner-read/write only (0600) before writing.
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    f.write(newKey);
    f.flush();
    f.close();

    return newKey;
}

// ---------------------------------------------------------------------------
// innerWrapKey() — inner ChaCha20-Poly1305 wrap.
//   Produces the inner blob that the outer AES-256-GCM layer will envelope.
//   Not exposed outside this TU.
// ---------------------------------------------------------------------------
static QByteArray innerWrapKey(const QByteArray& dek,
                               const QByteArray& wrapKey,
                               QString* errorOut)
{
    // Generate a random 12-byte nonce.
    std::array<unsigned char, kInnerNonceSize> nonce;
    if (RAND_bytes(nonce.data(), kInnerNonceSize) != 1) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: RAND_bytes failed for inner nonce");
        return {};
    }

    // Allocate output buffer: header + nonce + ciphertext + tag
    const int ctLen = dek.size();
    QByteArray blob(kInnerHeaderSize + kInnerNonceSize + ctLen + kInnerTagSize,
                    Qt::Uninitialized);
    unsigned char* p = reinterpret_cast<unsigned char*>(blob.data());

    // Write header.
    p[0] = kMagic0;
    p[1] = kMagic1;
    p[2] = kInnerVersion;
    p += kInnerHeaderSize;

    // Write nonce.
    std::memcpy(p, nonce.data(), kInnerNonceSize);
    p += kInnerNonceSize;

    // Encrypt with ChaCha20-Poly1305.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: EVP_CIPHER_CTX_new failed (inner wrap)");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    kInnerNonceSize, nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(wrapKey.constData()),
                                   nonce.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, p, &outLen,
                                  reinterpret_cast<const unsigned char*>(dek.constData()),
                                  ctLen) == 1);
    ok = ok && (outLen == ctLen);
    p += ctLen;

    int finalLen = 0;
    ok = ok && (EVP_EncryptFinal_ex(ctx, p, &finalLen) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                    kInnerTagSize, p + finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: ChaCha20-Poly1305 encryption failed");
        return {};
    }

    return blob;
}

// ---------------------------------------------------------------------------
// innerUnwrapKey() — inner ChaCha20-Poly1305 unwrap.
//   Returns the original DEK on success, empty on failure.
// ---------------------------------------------------------------------------
static QByteArray innerUnwrapKey(const QByteArray& innerBlob,
                                 const QByteArray& wrapKey,
                                 QString* errorOut)
{
    const int minSize = kInnerHeaderSize + kInnerNonceSize + 0 + kInnerTagSize;
    if (innerBlob.size() < minSize) {
        if (errorOut)
            *errorOut = QString("HwKey::Stub: inner blob too short "
                                "(got %1 bytes, need >= %2)")
                            .arg(innerBlob.size()).arg(minSize);
        return {};
    }

    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(innerBlob.constData());

    if (p[0] != kMagic0 || p[1] != kMagic1 || p[2] != kInnerVersion) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: invalid inner blob header");
        return {};
    }
    p += kInnerHeaderSize;

    const unsigned char* nonce = p;
    p += kInnerNonceSize;

    const int ctLen = innerBlob.size() - kInnerHeaderSize - kInnerNonceSize - kInnerTagSize;
    const unsigned char* ct  = p;
    const unsigned char* tag = ct + ctLen;

    QByteArray dek(ctLen, Qt::Uninitialized);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: EVP_CIPHER_CTX_new failed (inner unwrap)");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    kInnerNonceSize, nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(wrapKey.constData()),
                                   nonce) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx,
                                  reinterpret_cast<unsigned char*>(dek.data()),
                                  &outLen, ct, ctLen) == 1);
    ok = ok && (outLen == ctLen);

    // Supply the expected Poly1305 tag before calling DecryptFinal.
    // Cast away const: EVP_CTRL_AEAD_SET_TAG takes void*; OpenSSL copies bytes.
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                    kInnerTagSize,
                                    const_cast<unsigned char*>(tag)) == 1);

    int finalLen = 0;
    const bool tagOk = ok && (EVP_DecryptFinal_ex(
                                   ctx,
                                   reinterpret_cast<unsigned char*>(dek.data()) + outLen,
                                   &finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!tagOk) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: inner Poly1305 tag verification failed "
                                      "— blob tampered or wrapping key mismatch");
        dek.fill(0);
        return {};
    }

    return dek;
}

// ---------------------------------------------------------------------------
// outerWrap() — AES-256-GCM envelope over (innerBlob || backendId).
//   This is the final on-disk format: 12-byte nonce + GCM ciphertext + 16-byte tag.
//   The first byte a forensic tool sees is a uniformly random nonce byte.
// ---------------------------------------------------------------------------
static QByteArray outerWrap(const QByteArray& innerBlob,
                            unsigned char backendId,
                            const QByteArray& kMeta,
                            QString* errorOut)
{
    // Plaintext for the outer AEAD: innerBlob followed by the 1-byte backendId.
    QByteArray plaintext = innerBlob;
    plaintext.append(static_cast<char>(backendId));
    const int ptLen = plaintext.size();

    // Generate a random 12-byte outer nonce.
    std::array<unsigned char, kOuterNonceSize> nonce;
    if (RAND_bytes(nonce.data(), kOuterNonceSize) != 1) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: RAND_bytes failed for outer nonce");
        return {};
    }

    // Output: nonce + ciphertext + GCM tag (no outer header — the nonce IS
    // the first bytes of the blob, so it looks uniformly random from byte 0).
    QByteArray blob(kOuterNonceSize + ptLen + kOuterTagSize, Qt::Uninitialized);
    unsigned char* dst = reinterpret_cast<unsigned char*>(blob.data());

    std::memcpy(dst, nonce.data(), kOuterNonceSize);
    dst += kOuterNonceSize;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: EVP_CIPHER_CTX_new failed (outer wrap)");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                    kOuterNonceSize, nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(kMeta.constData()),
                                   nonce.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, dst, &outLen,
                                  reinterpret_cast<const unsigned char*>(plaintext.constData()),
                                  ptLen) == 1);
    ok = ok && (outLen == ptLen);
    dst += ptLen;

    int finalLen = 0;
    ok = ok && (EVP_EncryptFinal_ex(ctx, dst, &finalLen) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                    kOuterTagSize, dst + finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: AES-256-GCM outer wrap failed");
        return {};
    }

    return blob;
}

// ---------------------------------------------------------------------------
// outerUnwrap() — verify GCM tag and decrypt the outer AES-256-GCM envelope.
//   On success sets backendIdOut and returns the inner blob bytes.
// ---------------------------------------------------------------------------
static QByteArray outerUnwrap(const QByteArray& blob,
                              unsigned char* backendIdOut,
                              const QByteArray& kMeta,
                              QString* errorOut)
{
    // Minimum: nonce(12) + backendId(1) + tag(16) = 29 bytes.
    const int minSize = kOuterNonceSize + kBackendIdSize + kOuterTagSize;
    if (blob.size() < minSize) {
        if (errorOut)
            *errorOut = QString("HwKey::Stub: outer blob too short "
                                "(got %1 bytes, need >= %2)")
                            .arg(blob.size()).arg(minSize);
        return {};
    }

    const unsigned char* src =
        reinterpret_cast<const unsigned char*>(blob.constData());

    const unsigned char* nonce = src;
    src += kOuterNonceSize;

    // The ciphertext covers innerBlob + backendId; tag follows.
    const int ctLen = blob.size() - kOuterNonceSize - kOuterTagSize;
    const unsigned char* ct  = src;
    const unsigned char* tag = ct + ctLen;

    QByteArray plaintext(ctLen, Qt::Uninitialized);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: EVP_CIPHER_CTX_new failed (outer unwrap)");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                    kOuterNonceSize, nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(kMeta.constData()),
                                   nonce) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx,
                                  reinterpret_cast<unsigned char*>(plaintext.data()),
                                  &outLen, ct, ctLen) == 1);
    ok = ok && (outLen == ctLen);

    // Supply the GCM tag before DecryptFinal.
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                    kOuterTagSize,
                                    const_cast<unsigned char*>(tag)) == 1);

    int finalLen = 0;
    const bool tagOk = ok && (EVP_DecryptFinal_ex(
                                   ctx,
                                   reinterpret_cast<unsigned char*>(plaintext.data()) + outLen,
                                   &finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!tagOk) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub: outer AES-256-GCM tag verification failed "
                                      "— blob tampered or wrapping key mismatch");
        plaintext.fill(0);
        return {};
    }

    // Extract the backendId from the last byte of the plaintext.
    if (backendIdOut)
        *backendIdOut = static_cast<unsigned char>(plaintext[plaintext.size() - 1]);

    // Return everything except the trailing backendId byte.
    return plaintext.left(plaintext.size() - kBackendIdSize);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// HwKey::Stub namespace — inner wrap/unwrap called by platform TUs and by the
// public wrapKey/unwrapKey functions when no real hardware is wired in.
// ---------------------------------------------------------------------------
namespace HwKey {
namespace Stub {

// ---------------------------------------------------------------------------
// wrapKey() — two-layer wrap: ChaCha20-Poly1305 inner + AES-256-GCM outer.
//
//   API CONTRACT:
//     This function always routes wrapKey() to the software stub, regardless
//     of which hardware backend detect() reported. This is intentional during
//     the scaffolding phase. wrappingBackend() == Backend::Stub reflects this.
//     When real tpm2-tss / SecureEnclave / NCrypt calls are implemented, the
//     platform TU will call its own backend first, then pass the result to
//     outerWrap() as the innerBlob before routing here.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    if (dek.isEmpty()) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::wrapKey: empty DEK is not allowed");
        return {};
    }

    // Load (or create) the per-user K_meta.
    QByteArray kMeta = loadOrCreateStubKey(errorOut);
    if (kMeta.isEmpty())
        return {};

    // Inner layer: ChaCha20-Poly1305 wrap of the DEK.
    QString innerError;
    QByteArray innerBlob = innerWrapKey(dek, kMeta, &innerError);
    if (innerBlob.isEmpty()) {
        if (errorOut)
            *errorOut = innerError;
        return {};
    }

    // Outer layer: AES-256-GCM envelope over (innerBlob || backendId).
    return outerWrap(innerBlob, kBackendIdStub, kMeta, errorOut);
}

// ---------------------------------------------------------------------------
// unwrapKey() — verify outer GCM tag, then verify inner Poly1305 tag, decrypt.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    // Load the per-user K_meta.
    QByteArray kMeta = loadOrCreateStubKey(errorOut);
    if (kMeta.isEmpty())
        return {};

    // Outer unwrap: AES-256-GCM. Recovers innerBlob + backendId.
    unsigned char backendId = 0xFF;
    QString outerError;
    QByteArray innerBlob = outerUnwrap(wrappedBlob, &backendId, kMeta, &outerError);
    if (innerBlob.isEmpty()) {
        if (errorOut)
            *errorOut = outerError;
        return {};
    }

    // Inner unwrap: ChaCha20-Poly1305. Recovers the original DEK.
    return innerUnwrapKey(innerBlob, kMeta, errorOut);
}

} // namespace Stub

// ---------------------------------------------------------------------------
// Public API — routes through the active backend.
//
// Platform TUs (hwkey_linux.cpp etc.) define detect() with a real probe on
// their OS and call Stub::wrapKey/unwrapKey during the scaffolding phase.
// hwkey_stub.cpp provides the detect() / wrapKey / unwrapKey fallback used
// when no platform TU is compiled (i.e., unsupported OS).
//
// wrappingBackend() is defined here (not in platform TUs) because the answer
// is always Backend::Stub until a real hardware implementation exists — that
// is a global invariant, not a per-platform one.
// ---------------------------------------------------------------------------

// wrappingBackend() — what wrapKey() will ACTUALLY use right now.
//   Always returns Backend::Stub until a real hardware implementation lands.
//   See the API HONESTY CONTRACT in hwkey.h.
Backend wrappingBackend()
{
    return Backend::Stub;
}

#if !defined(Q_OS_LINUX) && !defined(Q_OS_MACOS) && !defined(Q_OS_WIN)
Capabilities detect()
{
    // No platform TU — report that no hardware was found. effectiveBackend is
    // always Stub (the software fallback is still functional).
    return Capabilities{
        /*backend=*/        Backend::None,
        /*effectiveBackend=*/Backend::Stub,
        /*supportsKeyWrap=*/false,  // no real HW wrap on this platform
        /*supportsSign=*/   false,
        /*device_name=*/    QLatin1String("None (stub only)")
    };
}

QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    return Stub::wrapKey(dek, errorOut);
}

QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    return Stub::unwrapKey(wrappedBlob, errorOut);
}
#endif // !Q_OS_LINUX && !Q_OS_MACOS && !Q_OS_WIN

} // namespace HwKey
