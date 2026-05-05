// hwkey.h — Hardware-backed key wrapping abstraction for OpenCryptUI.
//
// SECURITY NOTES:
// ============================================================================
//
// NON-PORTABILITY IS A FEATURE (for TPM / Secure Enclave):
//   A key wrapped by the Linux TPM 2.0 or macOS Secure Enclave is bound to
//   that specific piece of hardware (and, on TPM, to PCR state reflecting the
//   boot chain). The wrapped blob is ciphertext that can only be decrypted
//   by the same device. Copying the blob to a different machine gives an
//   attacker nothing useful. This ties confidentiality of the DEK to physical
//   possession of the device — exactly what a security researcher needs.
//
// PKCS#11 / YUBIKEY PORTABILITY:
//   YubiKey and Nitrokey devices implement PKCS#11. The private key never
//   leaves the token, but the token itself is portable (USB). A researcher can
//   carry their wrapping key on a YubiKey and use it on any machine that has
//   the appropriate PKCS#11 driver. This is a deliberate and documented
//   trade-off: physical possession of the token + knowledge of the PIN is
//   required to unwrap a DEK on any machine.
//
// ORACLE RISK AND PIN STRENGTH:
//   A wrapped DEK written alongside an encrypted file gives an offline
//   attacker an oracle: they can test PIN guesses by attempting to unwrap
//   the blob. The ONLY thing preventing brute-force is the hardware's
//   rate-limiting and lockout policy.
//
//   Recommended minimum PIN/passphrase strength by backend:
//     - TPM 2.0 (LinuxTPM2 / WindowsTPM): hardware lockout typically triggers
//       after 3–10 failed attempts. Even so, use >= 6 random digits or a
//       memorable passphrase (>= 4 random words from a large wordlist,
//       >= 50 bits of entropy). Dictionary words alone are NOT sufficient.
//     - Secure Enclave (MacSecureEnclave): biometric (Touch ID / Face ID) is
//       the primary authenticator — PIN fallback should be >= 6 digits with
//       "erase after 10 attempts" enabled in macOS settings.
//     - PKCS#11 (YubiKey/Nitrokey): token-side PIN lockout (default: 3 tries
//       before lock). Use a PIN of >= 8 characters; prefer a random passphrase
//       stored in a password manager. Avoid numeric-only PINs.
//
//   In all cases: a hardware-enforced lockout after N failures is the last
//   line of defence. Choose N conservatively in your device's management
//   software.
//
// ============================================================================

#pragma once

#include <QString>
#include <QByteArray>

namespace HwKey {

// ---------------------------------------------------------------------------
// Backend enumeration — which hardware (or software fallback) is active.
// ---------------------------------------------------------------------------
enum class Backend {
    None,               // No hardware available — falls back to password-only.
    LinuxTPM2,          // tpm2-tss on Linux (/dev/tpmrm0 resource manager).
    MacSecureEnclave,   // Apple Secure Enclave via CryptoKit / Security.framework.
    WindowsTPM,         // BCrypt / NCrypt CNG on Windows.
    PKCS11,             // YubiKey, Nitrokey, smart cards via PKCS#11.
};

// ---------------------------------------------------------------------------
// Capabilities — result of detect(). Cheap struct, always fully populated.
// ---------------------------------------------------------------------------
struct Capabilities {
    Backend backend        = Backend::None;
    bool supportsKeyWrap   = false;  // can wrap/unwrap an external DEK
    bool supportsSign      = false;  // can sign with a hardware-resident key
    QString device_name;             // e.g. "TPM 2.0", "Secure Enclave", "YubiKey 5C"
};

// ---------------------------------------------------------------------------
// detect() — probe available hardware. Safe to call on every startup.
//   Returns a fully-populated Capabilities struct. When backend == None the
//   caller should inform the user that hardware key protection is unavailable
//   and fall back to password-derived key protection only.
// ---------------------------------------------------------------------------
Capabilities detect();

// ---------------------------------------------------------------------------
// wrapKey() — wrap an in-memory data-encryption-key (DEK) with hardware.
//
//   dek        — raw key bytes to protect (typically 32 bytes / 256 bit AES).
//   errorOut   — if non-null and wrapping fails, receives a human-readable
//                message suitable for display in a dialog or log entry.
//
//   Returns:   — opaque blob to be persisted alongside the encrypted file.
//                The format is backend-specific and intentionally opaque; do
//                not attempt to parse it outside of unwrapKey().
//                Returns empty QByteArray on failure (errorOut is set).
//
//   Portability: blobs from TPM/Secure Enclave backends are device-bound and
//   will NOT unwrap on a different machine. PKCS11 blobs unwrap wherever the
//   physical token is present.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut = nullptr);

// ---------------------------------------------------------------------------
// unwrapKey() — recover a DEK from a previously-wrapped blob.
//
//   wrappedBlob — blob previously returned by wrapKey().
//   errorOut    — if non-null and unwrapping fails, receives a human-readable
//                 message. Common reasons: wrong device, PCR mismatch (TPM),
//                 wrong PIN/biometric, tampered blob (AEAD tag mismatch).
//
//   Returns:    — original DEK bytes on success.
//                Returns empty QByteArray on failure (errorOut is set).
//
//   Biometric / PIN prompts: on macOS and YubiKey backends the OS or driver
//   will surface a system-modal prompt; on Linux TPM 2.0 the tpm2-tss
//   session handles PIN verification transparently.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut = nullptr);

} // namespace HwKey
