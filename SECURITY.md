# Security Policy — OpenCryptUI

## Threat Model

### What OpenCryptUI protects against

- Opportunistic attackers who obtain a copy of an encrypted file without the passphrase.
- Casual forensic examination of storage media (e.g., lost laptop, discarded drive).
- Accidental disclosure of file contents to unauthorized processes that do not have
  access to the passphrase or keyfile.

### What OpenCryptUI does NOT protect against

- Nation-state adversaries with physical access to a running machine and the ability
  to perform cold-boot, DMA, or hardware-implant attacks.
- Quantum adversaries running Shor's algorithm on a cryptographically relevant
  quantum computer (see Post-Quantum section below).
- Kernel-level malware or rootkits that can read process memory or intercept
  passphrase entry before encryption occurs.
- Adversaries who obtain the passphrase or keyfile by other means (social engineering,
  keyloggers, shoulder surfing).
- Metadata: file names, sizes, access timestamps, and directory structure are NOT
  encrypted.

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

