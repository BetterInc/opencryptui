# Security Policy — OpenCryptUI

## Threat Model

OpenCryptUI is built for **security researchers** protecting their own work
(0-day research, exploit development, sensitive client data). The design
prioritises **plausible deniability and minimal forensic fingerprint** over
features that would otherwise be conventional (TPM key sealing, in-binary
branding, etc.).

### What OpenCryptUI protects against

- Opportunistic attackers who obtain an encrypted file without the passphrase.
- Casual forensic examination — `binwalk`, `strings`, `file` — of storage media.
- A compromised endpoint reading stale memory (we mlock + zero secrets where possible).
- Tampering with encrypted files (Ed25519 signature + per-chunk AEAD detect any byte flip).
- A device thief who has the disk but not the passphrase (Argon2id ~1 GiB cost).

### What OpenCryptUI does NOT protect against

- Nation-state adversaries with physical access to a running machine: cold-boot,
  DMA, or hardware-implant attacks.
- Quantum adversaries running Shor's algorithm (PQ hybrid is scaffolded, not yet
  wired into the production format — see Post-Quantum section).
- Kernel-level malware / rootkits / firmware implants that read process memory or
  intercept passphrase entry.
- Passphrase-extraction attacks: keyloggers, shoulder surfing, social engineering,
  rubber-hose cryptanalysis.
- Metadata: filenames, sizes, mtime, and directory structure are NOT encrypted.

### Discoverability — what an attacker CAN learn

This matters for plausible deniability. Honest accounting of what's visible:

| Surface | Currently visible? | Mitigation status |
|---|---|---|
| Plaintext "OCUI" magic at file offset 0 | **YES** | format v4 (planned) moves magic into the encrypted region |
| File length pattern (chunked AEAD has predictable per-chunk overhead) | YES | inherent — accept it |
| Existence of OpenCryptUI binary on disk reveals tool choice | YES | future `OCUI_STEALTH=ON` build option strips identifying strings |
| TPM use (any Backend other than `None`) | leak via TPM2_BLOB structure | **see Hardware Backends below — TPM is NOT recommended for this threat model** |
| YubiKey use | leak only via "user owns a YubiKey" — token is portable + destructible | recommended hardware path |
| Software-only encryption | leaves no hardware fingerprint | **default and recommended** |

---

## Cryptographic Posture

| Primitive         | Algorithm                              | Notes                                   |
|-------------------|----------------------------------------|-----------------------------------------|
| Default AEAD      | AES-256-GCM, ChaCha20-Poly1305        | Recommended for all new encryptions     |
| Block ciphers     | AES-128/192/256-CBC, AES-128/192/256-CTR | Available; no built-in authentication |
| KDF (default)     | Argon2id                               | Memory: 1 GiB, 3 iterations (default)  |
| KDF (alternative) | PBKDF2-SHA512, Scrypt                  | Available via settings                  |
| Signing           | Ed25519 (via libsodium)               | Tamper evidence on ciphertext           |

**Cipher selection**: Camellia-256-CBC and Camellia-128-CBC have been removed.
They are not on the CNSA 2.0 approved list and provide no authenticated encryption.

---

## Hardware Backends

For a security researcher's threat model, the trade-off space is more nuanced
than "hardware = better". Each backend leaves a different forensic fingerprint:

| Backend | "Owns this hardware" signal | On-disk blob fingerprint | Device-seizure recovery | Status |
|---|---|---|---|---|
| **Software-only** | none | none — looks like random data | n/a — keys are passphrase-derived, you carry the passphrase | **default**, fully working |
| **TPM 2.0** (Linux/Windows/Mac) | **none** — TPM is now in nearly every device made after 2018, mandated by Windows 11 | TPM2_PUBLIC structure recognisable on disk **unless we wrap it inside our own format** | bad — keys stay on the seized device | scaffolded, real wiring TBD |
| **YubiKey / PKCS#11** | **strong** — only ~10–15M units globally; possession of a token is itself a signal | recognisable as PKCS#11 wrap unless wrapped-inside-our-format | good — token is portable, can be hidden / palmed / destroyed | scaffolded, real wiring TBD |

### What each option is good for

- **Software-only**: minimum footprint. No hardware artifact on or off the
  device. The default. Recommended for users whose threat model includes
  forensic examination of the device but not theft of the live machine.

- **TPM**: protects against an attacker who has the disk but not the booted
  laptop. The "user has a TPM" signal is essentially null because everyone
  does — Windows 11 requires it, all Apple Silicon Macs have a Secure
  Enclave, every recent Intel/AMD has fTPM. The risk is the on-disk wrapped
  blob fingerprinting as TPM2_PUBLIC. We mitigate that by **wrapping the
  TPM blob inside our own AEAD-encrypted format**, so a forensic scan sees
  random ciphertext, not "this is a TPM-sealed key".

- **YubiKey/PKCS#11**: best for users who travel with their keys and need to
  separate the "decrypt-capable" hardware from the laptop. The trade-off
  is that **token possession itself is a signal** — owning a YubiKey is
  much rarer than owning a TPM-equipped laptop, and a forensic examiner
  finding a YubiKey on you flags above-average opsec. Acceptable for
  threat models where you control whether the token is found at all
  (you can hide/destroy it before search); not acceptable if mere
  possession is enough to invite scrutiny.

### Mitigations that apply to BOTH hardware backends

For either TPM or PKCS#11 to be deniability-acceptable, the wrapped key
blob produced by the hardware MUST be encrypted inside our own file
format — not stored as recognisable TPM2 / PKCS#11 ASN.1 on disk. Format
v4 (planned) does this; until then, hardware backends should not be used
in deniability-sensitive scenarios.

### What's currently misleading

`HwKey::detect()` may report `Backend::LinuxTPM2`, `MacSecureEnclave`,
or `WindowsTPM` if the underlying hardware is present, but
`HwKey::wrapKey()` currently routes to the software stub on every code
path. The API surface lies. This is being corrected: either the platform
backends get real implementations or the detection is suppressed until
they do. Track the active state via the runtime `HwKey::Capabilities`
struct's `supportsKeyWrap` field — that one is honest.

---

## Known Limitations

### Memory Safety

Passphrases pass through `QString`, which is reference-counted, implicitly shared,
and may be copied to multiple heap locations before the caller can zero them.
A best-effort zero is applied after key derivation, but additional copies may
linger in memory until overwritten by the allocator.

**Mitigation**: On systems that handle classified or highly sensitive material,
disable swap before use:

```
# Linux
sudo swapoff -a

# macOS
# Swap is encrypted by default on FileVault systems; still prefer disabling
# hibernation: sudo pmset -a hibernatemode 0
```

Windows users should ensure the pagefile is encrypted (BitLocker) or disabled.

### Memory Locking (mlock)

Argon2-derived key material is protected with `sodium_mlock()`, which attempts
to prevent the key from being swapped to disk and excluded from core dumps.

- **Windows**: `sodium_mlock` is a no-op; memory locking is not performed.
- **Linux**: Subject to `RLIMIT_MEMLOCK`. The default limit (64 KiB on many
  distributions) may be insufficient. Check with `ulimit -l` and increase in
  `/etc/security/limits.conf` if needed.

Treat `sodium_mlock` as defense-in-depth, not a guaranteed guarantee.

### Post-Quantum Security

All current ciphers are classical:

- **AES-256**: ~128-bit security under Grover's algorithm on a quantum computer.
  Considered adequate for mid-term use.
- **ChaCha20-Poly1305**: Similar post-quantum profile to AES-256.
- **Ed25519**: Fully broken by a sufficiently large quantum computer running
  Shor's algorithm. Data signed today could have its signatures forged post-quantum.

**Harvest-now, decrypt-later risk**: Ciphertext encrypted today with AES-256-GCM
retains ~128 bits of PQ security. Ciphertext encrypted with AES-128 variants
retains ~64 bits — insufficient against a quantum adversary.

**Planned roadmap**: Hybrid ML-KEM (Kyber) + Ed25519 for key encapsulation, and
ML-DSA (Dilithium) for signing, once stable Qt/OpenSSL integration is available.

### Side Channels

OpenSSL and libsodium are relied upon for constant-time cryptographic primitives.
However, comparison of public verification data (e.g., derived public keys) uses
`QByteArray` equality, which is not guaranteed constant-time. The risk is low
because the value being compared is derived from the password, but it is a
best-practice gap.

### Signing Key Derivation

Historically, the signing key was derived from the same password as the encryption
key via SHA-512 with a string domain separator. A concurrent hardening pass is
introducing HKDF-based key separation to ensure cryptographic independence between
the encryption key and the signing key. Until that pass is deployed, treat signing
and encryption keys as sharing the same root secret.

---

## Standards Conformance

- **FIPS 140-3**: OpenCryptUI is NOT FIPS 140-3 validated. The OpenSSL library
  used may be built in FIPS mode separately, but no validation has been performed
  on OpenCryptUI itself.
- **CNSA 2.0**: OpenCryptUI is NOT CNSA 2.0 compliant. Camellia ciphers have been
  removed as a first step; full CNSA 2.0 compliance would additionally require
  removal of AES-128 variants and migration to post-quantum algorithms.

---

## Secure Operation Advice

1. **KDF**: Use Argon2id with default parameters (memory: 1 GiB, iterations: 3).
   Do not reduce parameters unless required by hardware constraints.

2. **Passphrases**: Use at least 20 characters, or 6 diceware words, for storage
   against well-resourced adversaries. Shorter passphrases may be acceptable for
   temporary or low-sensitivity files.

3. **Cipher choice**: Prefer AES-256-GCM or ChaCha20-Poly1305 (AEAD modes that
   provide both confidentiality and integrity). Avoid CBC and CTR modes unless
   interoperability requires them — they provide no built-in authentication.

4. **Keyfiles**: Store keyfiles on a separate physical medium (e.g., USB token)
   where possible. A keyfile stored alongside the encrypted file provides no
   additional security.

5. **Swap**: Disable or encrypt swap on machines that process sensitive data
   (see Memory Safety above).

6. **Updates**: Keep OpenSSL and libsodium up to date. Cryptographic libraries
   receive security patches that OpenCryptUI inherits.

