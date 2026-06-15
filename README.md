# OpenCryptUI

OpenCryptUI is a Qt-based graphical user interface application for file and folder encryption. It supports various encryption algorithms and key derivation functions.

![Open Crypt UI](opencryptui.png)

## Features

- Encrypt and decrypt files, folders, and disk volumes.
- Support for multiple encryption algorithms: AES-256-CBC, AES-256-GCM, AES-256-CTR, ChaCha20-Poly1305, Camellia (128/256), AES-128-CBC, and others.
- Support for multiple key derivation functions: PBKDF2, Argon2, and Scrypt.
- Enforced authenticated encryption with HMAC / AEAD for integrity checks.
- Memory protection: Sensitive keys are securely erased from memory after use with constant-time operations.
- Advanced secure memory management: Memory locking (mlock) prevents sensitive data from being swapped to disk.
- Military-grade entropy sources: Multiple hardware and software random sources with continuous quality monitoring.
- Hardware RNG support: Utilizes RDSEED/RDRAND CPU instructions if available for true hardware entropy.
- Tamper-evident wrappers: Digital signatures and integrity verification to detect data tampering.
- Secure deletion: Multi-pass file wiping with full inode scrubbing to prevent data recovery.
- Keyfile support with domain separation: Cryptographically secure HMAC-based keyfile processing.
- Hardware acceleration support: Automatically detects AES-NI and other hardware features.
- Real-time entropy health monitoring with quality metrics and testing.
- Built-in benchmark: Compare performance of different cipher/KDF combos in MB/s and ms.
- GUI-based folder compression and encryption using `.tar.gz` wrapping.
- Multi-provider backend: OpenSSL, libsodium, and Argon2 are all supported and switchable at runtime.

### Advanced features

- **Cipher cascades** - encrypt through multiple AEAD ciphers in sequence
  (AES-256-GCM + ChaCha20-Poly1305, and a triple variant), each with an
  independent subkey, so the file is only broken if *every* cipher is broken.
  Selectable in the File/Folder algorithm dropdowns.
- **Deniable encrypted containers with hidden volumes** - a fixed-size
  container file that is indistinguishable from random data end-to-end (no
  magic bytes). One password opens the outer (decoy) volume; an optional
  second password opens a hidden volume whose very existence cannot be proven
  without it. *File > Create / Open Encrypted Container.* This supersedes the
  old disk-header "hidden volume" flag (which announced its own existence in a
  cleartext header and is therefore not used).
- **Mountable encrypted volumes (on-the-fly encryption)** - `opencryptui-mount`
  exposes an encrypted volume as a live virtual disk image (`disk.img`),
  decrypting on read and encrypting on write; put any filesystem on it and
  loop-mount. Built with `-DOCUI_ENABLE_FUSE=ON` (needs `libfuse3-dev`).
  Authenticated per-block AES-256-GCM with a fresh nonce per write.
- **Whole-USB / raw-device encryption (Linux)** -
  `opencryptui-mount --format-device <device>` formats an entire device as an
  encrypted volume, with a typed `ERASE` confirmation and refusal of mounted
  devices. *Linux only* for now; Windows/macOS raw-device support is not
  implemented (the cross-platform way to encrypt a USB is a container file on
  it - no admin required). See [Cross-platform notes](#cross-platform-notes).

### Cross-platform notes

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| File / folder / cascade / container encryption | OK | OK | OK |
| Deniable containers + hidden volumes | OK | OK | OK |
| Mounting a container (FUSE) | OK libfuse3 | needs macFUSE (same source) | needs WinFsp (same source) |
| Whole raw-device encryption | OK | X not implemented | X not implemented |

The cryptography is identical on all platforms; only the OS *device/mount
layer* differs. The container-file model needs no admin rights and behaves
identically everywhere.

> **Note on assurance:** the cryptography here is carefully built and tested,
> but OpenCryptUI has **not** had an independent security audit. For protecting
> high-value data against capable adversaries, that audit gap matters more than
> any single feature.

## Dependencies

- Qt 5 or later
- OpenSSL
- Libsodium
- Argon2
- CMake

## Building the Project

To build the project, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. Configure the project with CMake:
   ```bash
   cmake -S . -B build
   ```

3. Build the project:
   ```bash
   cmake --build build --config Release
   ```

4. Run the application:
   ```bash
   cd build
   ./OpenCryptUI
   ```

5. Run the tests:
   ```bash
   cd build
   ./OpenCryptUITest
   ```

## Detailed Installation Instructions

For detailed installation instructions, please refer to the following:

- [Linux](installation/linux.md)
- [Windows](installation/windows.md)
- [macOS](installation/osx.md)

## Usage

1. Launch the application:
   ```bash
   ./OpenCryptUI
   ```

2. Use the "File Encryption" tab to encrypt or decrypt individual files:
   - Browse and select the file.
   - Enter the password.
   - Choose the encryption algorithm and key derivation function.
   - Set the number of iterations.
   - (Optional) Enable HMAC integrity check.
   - (Optional) Add one or multiple keyfiles.
   - Click "Encrypt" or "Decrypt".

3. Use the "Folder Encryption" tab to encrypt or decrypt entire folders:
   - Browse and select the folder.
   - Enter the password.
   - Choose the encryption algorithm and key derivation function.
   - Set the number of iterations.
   - (Optional) Enable HMAC integrity check.
   - (Optional) Add one or multiple keyfiles.
   - Click "Encrypt Folder" or "Decrypt Folder".

## Contributing

Contributions are welcome! If you find a bug or want to add a new feature, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Todo

OpenCryptUI aims to implement several additional features found in expert-level encryption tools and hardened security workflows:

- **Independent security audit** - the most important outstanding item; nothing below substitutes for external review.
- **Windows/macOS raw-device encryption** - whole-device works on Linux today; the others need `DeviceIoControl`/`DKIOC` + volume locking/alignment.
- **macOS/Windows mount packaging** - the FUSE driver source is cross-platform; ship/test it against macFUSE and WinFsp.
- **Shamir Secret Sharing:** Optionally split the encryption key into multiple shares (e.g. 3-of-5) to improve redundancy and reduce risk.
- **Hardware token integration:** Support for YubiKey (HMAC challenge/response or PGP smartcard mode) during key derivation.
- **Double-layer encryption:** Encrypt file using symmetric key, then encrypt that key with user's PGP or RSA hardware key.
- **Ephemeral unlock mode:** Temporary decryption with automatic cleanup after timeout or UI close.

Implemented since the original roadmap: cipher cascades, deniable containers
with **hidden volumes** (real plausible deniability, not the old cleartext-flag
scaffold), on-the-fly mountable volumes (FUSE), and Linux whole-device
encryption. See [Advanced features](#advanced-features).