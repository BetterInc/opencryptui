// hwkey_stub.cpp — Software-only, always-compiling HwKey implementation.
//
// PURPOSE:
//   This translation unit provides the fallback implementation that compiles
//   and links on every platform, with no dependency on TPM, Secure Enclave,
//   or CNG headers. It is used:
//     (a) directly when no hardware backend is present (Backend::None), and
//     (b) as a placeholder called by platform TUs while real hardware APIs
//         are not yet implemented (scaffolding phase).
//
// ALGORITHM — ChaCha20-Poly1305 with per-installation random wrapping key:
//   The stub derives a 256-bit wrapping key from a per-user secret persisted
//   at QStandardPaths::AppDataLocation + "/.opencryptui-stubkey" (mode 0600).
//   On first use, 32 random bytes are written to that file.  Wrap format:
//
//     [ magic  2 bytes : 0x4F 0x43 "OC" ]
//     [ version 1 byte: 0x01            ]
//     [ nonce  12 bytes                 ]
//     [ ciphertext  len(dek) bytes      ]
//     [ AEAD tag 16 bytes               ]
//
//   Total overhead: 31 bytes per wrapped key.
//
// SECURITY PROPERTIES:
//   - AEAD tag provides integrity: flipping any byte in the blob causes
//     unwrapKey() to return empty and set errorOut.
//   - The wrapping key is tied to this user account on this machine (file
//     permissions 0600). An attacker with local read access to the data
//     directory can recover the wrapping key, so this is NOT equivalent to
//     hardware protection.
//   - In production, the platform-specific backends replace stub calls with
//     genuine hardware operations. The stub exists so CI and machines without
//     hardware can still complete the wrap/unwrap protocol and run tests.
//
// NOTE: Do not remove or weaken the AEAD — the tamper-detection test relies
//       on the tag check in unwrapKey().

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

// Wire-format constants.
constexpr unsigned char kMagic0 = 0x4F; // 'O'
constexpr unsigned char kMagic1 = 0x43; // 'C'
constexpr unsigned char kVersion = 0x01;
constexpr int kHeaderSize  = 3;   // magic(2) + version(1)
constexpr int kNonceSize   = 12;  // 96-bit nonce for ChaCha20-Poly1305
constexpr int kTagSize     = 16;  // 128-bit Poly1305 tag
constexpr int kWrapKeySize = 32;  // 256-bit ChaCha20 key

// ---------------------------------------------------------------------------
// stubKeyPath() — canonical location for the per-user wrapping key file.
// ---------------------------------------------------------------------------
static QString stubKeyPath()
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return dir + QLatin1String("/.opencryptui-stubkey");
}

// ---------------------------------------------------------------------------
// loadOrCreateStubKey() — load existing key or generate+persist a new one.
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

} // anonymous namespace

// ---------------------------------------------------------------------------
// HwKey::Stub namespace — called from platform TUs and the detect/wrap/unwrap
// functions below when no real hardware backend is wired in.
// ---------------------------------------------------------------------------
namespace HwKey {
namespace Stub {

// ---------------------------------------------------------------------------
// wrapKey() — ChaCha20-Poly1305 software wrap.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    if (dek.isEmpty()) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::wrapKey: empty DEK is not allowed");
        return {};
    }

    // Load (or create) the per-user wrapping key.
    QByteArray wrapKey = loadOrCreateStubKey(errorOut);
    if (wrapKey.isEmpty())
        return {};

    // Generate a random 12-byte nonce.
    std::array<unsigned char, kNonceSize> nonce;
    if (RAND_bytes(nonce.data(), kNonceSize) != 1) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::wrapKey: RAND_bytes failed for nonce");
        return {};
    }

    // Allocate output buffer: header + nonce + ciphertext + tag
    const int ctLen = dek.size();
    QByteArray blob(kHeaderSize + kNonceSize + ctLen + kTagSize, Qt::Uninitialized);
    unsigned char* p = reinterpret_cast<unsigned char*>(blob.data());

    // Write header.
    p[0] = kMagic0;
    p[1] = kMagic1;
    p[2] = kVersion;
    p += kHeaderSize;

    // Write nonce.
    std::memcpy(p, nonce.data(), kNonceSize);
    p += kNonceSize;

    // Encrypt with ChaCha20-Poly1305.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::wrapKey: EVP_CIPHER_CTX_new failed");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    kNonceSize, nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(wrapKey.constData()),
                                   nonce.data()) == 1);
    // No AAD in the stub — the blob is self-contained.
    ok = ok && (EVP_EncryptUpdate(ctx, p, &outLen,
                                  reinterpret_cast<const unsigned char*>(dek.constData()),
                                  ctLen) == 1);
    ok = ok && (outLen == ctLen);
    p += ctLen;

    int finalLen = 0;
    ok = ok && (EVP_EncryptFinal_ex(ctx, p, &finalLen) == 1);
    // Retrieve the 16-byte Poly1305 authentication tag.
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                    kTagSize, p + finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::wrapKey: EVP encryption failed");
        return {};
    }

    return blob;
}

// ---------------------------------------------------------------------------
// unwrapKey() — verify Poly1305 tag, then decrypt.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    const int minSize = kHeaderSize + kNonceSize + 0 + kTagSize;
    if (wrappedBlob.size() < minSize) {
        if (errorOut)
            *errorOut = QString("HwKey::Stub::unwrapKey: blob too short "
                                "(got %1 bytes, need >= %2)")
                            .arg(wrappedBlob.size()).arg(minSize);
        return {};
    }

    const unsigned char* p = reinterpret_cast<const unsigned char*>(wrappedBlob.constData());

    // Validate magic/version header.
    if (p[0] != kMagic0 || p[1] != kMagic1 || p[2] != kVersion) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::unwrapKey: invalid blob header");
        return {};
    }
    p += kHeaderSize;

    const unsigned char* nonce = p;
    p += kNonceSize;

    const int ctLen = wrappedBlob.size() - kHeaderSize - kNonceSize - kTagSize;
    const unsigned char* ct  = p;
    // The tag immediately follows the ciphertext.
    const unsigned char* tag = ct + ctLen;

    // Load the per-user wrapping key.
    QByteArray wrapKey = loadOrCreateStubKey(errorOut);
    if (wrapKey.isEmpty())
        return {};

    QByteArray dek(ctLen, Qt::Uninitialized);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::unwrapKey: EVP_CIPHER_CTX_new failed");
        return {};
    }

    int outLen = 0;
    bool ok = true;

    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                   nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    kNonceSize, nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(wrapKey.constData()),
                                   nonce) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx,
                                  reinterpret_cast<unsigned char*>(dek.data()),
                                  &outLen,
                                  ct, ctLen) == 1);
    ok = ok && (outLen == ctLen);

    // Supply the expected tag before calling DecryptFinal — tag mismatch
    // causes DecryptFinal to return 0 (authentication failure).
    // We cast away const here because EVP_CTRL_AEAD_SET_TAG takes void*;
    // OpenSSL copies the bytes and does not mutate them.
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                    kTagSize,
                                    const_cast<unsigned char*>(tag)) == 1);

    int finalLen = 0;
    // EVP_DecryptFinal_ex returns 0 when the tag does not match.
    const bool tagOk = ok && (EVP_DecryptFinal_ex(
                                   ctx,
                                   reinterpret_cast<unsigned char*>(dek.data()) + outLen,
                                   &finalLen) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!tagOk) {
        if (errorOut)
            *errorOut = QLatin1String("HwKey::Stub::unwrapKey: authentication tag "
                                      "verification failed — blob is tampered or "
                                      "wrapping key mismatch");
        // Zero the partial output before discarding it.
        dek.fill(0);
        return {};
    }

    return dek;
}

} // namespace Stub

// ---------------------------------------------------------------------------
// Public API — routes through the active backend.
// Platform TUs (hwkey_linux.cpp etc.) call these same free functions after
// their backend detection; they fall through to Stub when hardware is absent.
// ---------------------------------------------------------------------------

// detect() is implemented in the platform-specific TU that is compiled on
// each OS. hwkey_stub.cpp provides the fallback implementation used when no
// platform TU overrides it (i.e., on any platform where the real TU hasn't
// been wired in yet, or where detection finds nothing).
//
// On Linux/macOS/Windows the platform TU defines detect() with a real probe;
// this symbol is the unconditional fallback.
#if !defined(Q_OS_LINUX) && !defined(Q_OS_MACOS) && !defined(Q_OS_WIN)
Capabilities detect()
{
    return Capabilities{
        Backend::None,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/false,
        /*device_name=*/QLatin1String("None (stub only)")
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
