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
// API HONESTY CONTRACT:
//   detect() and wrappingBackend() answer two DIFFERENT questions:
//     - detect().backend        → which hardware is PRESENT on this machine.
//     - wrappingBackend()       → which backend wrapKey() will ACTUALLY use.
//   Today all wrapKey() implementations route to the software stub (Stub),
//   regardless of which hardware detect() reports. These two values will only
//   converge once a real hardware implementation replaces the stub routing.
//   Callers that display "TPM-protected" to users MUST gate on
//   wrappingBackend() == the hardware backend, not on detect().backend.
//
// ============================================================================

#pragma once

#include <QString>
#include <QByteArray>

namespace HwKey {

// ---------------------------------------------------------------------------
// Backend enumeration — which hardware (or software fallback) is active.
//
// Distinction between None and Stub:
//   None  — No hardware crypto available AND the software fallback is also
//            not in use (e.g., key-wrapping entirely disabled). The caller
//            should inform the user that hardware key protection is unavailable
//            and fall back to password-derived key protection only.
//   Stub  — Software-only AEAD wrap using a per-installation key stored at
//            ~/.config/opencryptui/.opencryptui-stubkey (mode 0600). Provides
//            correct AEAD integrity (tamper detection) and DEK confidentiality
//            against unprivileged third parties, but is NOT hardware-bound.
//            The wrapping key lives in the filesystem — an attacker with local
//            read access can recover it.
// ---------------------------------------------------------------------------
enum class Backend {
    None,               // No hardware available and no software fallback active.
    Stub,               // Software-only AEAD fallback (per-installation key).
    LinuxTPM2,          // tpm2-tss on Linux (/dev/tpmrm0 resource manager).
    MacSecureEnclave,   // Apple Secure Enclave via CryptoKit / Security.framework.
    WindowsTPM,         // BCrypt / NCrypt CNG on Windows.
    PKCS11,             // YubiKey, Nitrokey, smart cards via PKCS#11.
};

// ---------------------------------------------------------------------------
// Capabilities — result of detect(). Cheap struct, always fully populated.
//
// Fields:
//   backend         — which hardware is PRESENT (may differ from what
//                     wrapKey() actually uses — see effectiveBackend).
//   effectiveBackend — what wrapKey() will ACTUALLY route to right now.
//                      Until real hardware implementations land, this is
//                      always Backend::Stub regardless of backend.
//   supportsKeyWrap — true only when a REAL hardware wrap is implemented and
//                     wrapKey() calls into actual TPM/SE/PKCS#11 APIs.
//                     Always false in the current scaffolding phase.
//   supportsSign    — true when hardware-resident signing is implemented.
//   device_name     — human-readable description for UI display.
//
// WARNING: supportsKeyWrap == false means wrapKey() goes through the software
// stub even when backend reports a hardware device. Do NOT display
// "TPM-protected" to the user unless supportsKeyWrap == true.
// ---------------------------------------------------------------------------
struct Capabilities {
    Backend backend          = Backend::None;  // hardware that is PRESENT
    Backend effectiveBackend = Backend::Stub;  // backend wrapKey() ACTUALLY uses
    bool supportsKeyWrap     = false;  // true only when real HW wrap is implemented
    bool supportsSign        = false;  // can sign with a hardware-resident key
    QString device_name;               // e.g. "TPM 2.0", "Secure Enclave", "YubiKey 5C"
};

// ---------------------------------------------------------------------------
// detect() — probe available hardware. Safe to call on every startup.
//   Returns a fully-populated Capabilities struct.
//
//   IMPORTANT: caps.backend reports what hardware is PRESENT. It does NOT
//   imply that wrapKey() uses that hardware. Check caps.supportsKeyWrap or
//   call wrappingBackend() to know what wrapKey() will actually do.
// ---------------------------------------------------------------------------
Capabilities detect();

// ---------------------------------------------------------------------------
// wrappingBackend() — return the backend that wrapKey() will ACTUALLY use.
//
//   Today this always returns Backend::Stub because all platform TUs still
//   delegate wrapKey() to the software stub. When a real hardware
//   implementation is wired in, this will return the hardware backend.
//
//   Callers that wish to display "key is TPM-protected" to users MUST check
//   that wrappingBackend() == Backend::LinuxTPM2 (or the appropriate platform
//   enum), not just that detect().backend is non-None.
// ---------------------------------------------------------------------------
Backend wrappingBackend();

// ---------------------------------------------------------------------------
// wrapKey() — wrap an in-memory data-encryption-key (DEK).
//
//   dek        — raw key bytes to protect (typically 32 bytes / 256 bit AES).
//   errorOut   — if non-null and wrapping fails, receives a human-readable
//                message suitable for display in a dialog or log entry.
//
//   Returns:   — opaque blob to be persisted alongside the encrypted file.
//                Blob layout (wrappedBlob_v2, uniform across all backends):
//
//                  [ randomNonce  12 bytes  ]
//                  [ AES-256-GCM ciphertext  len(backendBlob) + 1 byte ]
//                  [ GCM auth tag 16 bytes  ]
//
//                The outer AEAD layer uses K_meta (the per-installation key
//                from .opencryptui-stubkey). Inside the AEAD envelope the
//                plaintext is: backendBlob || backendId (1 byte). This means
//                every wrapped blob looks like 12 nonce bytes + random
//                ciphertext + 16 tag bytes to a forensic scan — no
//                backend-distinguishing structure is visible.
//
//                Returns empty QByteArray on failure (errorOut is set).
//
//   CURRENT BEHAVIOUR: regardless of which backend detect() reports, wrapKey()
//   routes to the stub (wrappingBackend() == Backend::Stub). The backend blob
//   inside the AEAD envelope is the ChaCha20-Poly1305 stub output.
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
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut = nullptr);

} // namespace HwKey
