# Post-Quantum Hybrid Encryption in OpenCryptUI

## Why hybrid?

Classical asymmetric cryptography (X25519 ECDH, Ed25519 signatures) relies on
the difficulty of the elliptic-curve discrete-logarithm problem.  Shor's
algorithm, running on a cryptographically-relevant quantum computer (CRQC),
solves this in polynomial time, rendering today's classical asymmetric keys
worthless.

The practical threat to *symmetric* ciphers is more modest: Grover's algorithm
provides a quadratic speedup for key search, effectively halving the security
level.  AES-256-GCM and ChaCha20-Poly1305 retain approximately 128 bits of
post-quantum security — acceptable for most threat models.

**Harvest-now-decrypt-later (HNDL)** changes the calculus for long-lived
secrets.  An adversary with network access today can archive encrypted traffic
and files and decrypt them once a CRQC becomes available — potentially years
from now.  For security researchers whose zero-days, source code, or
communications may stay sensitive for a decade, this is a realistic threat.

The hybrid approach adopted here costs little (a ~1600-byte overhead in the
file header) and hedges completely: if either the classical (X25519) or the
post-quantum (ML-KEM-1024) component is broken in isolation, the attacker
still cannot recover the data-encryption key because the final KEK is derived
from *both* shared secrets jointly via HKDF-SHA-256.

## Algorithm choices

| Role | Algorithm | Standard |
|------|-----------|----------|
| Classical KEM | X25519 ECDH | RFC 7748 |
| Post-quantum KEM | ML-KEM-1024 | NIST FIPS 203 |
| Combiner | HKDF-SHA-256, info = `OCUI-HYBRID-V1` | RFC 5869 |
| DEK wrapping | AES-256-GCM | NIST SP 800-38D |

ML-KEM-1024 provides NIST security level 5 (≥256-bit classical, ≥128-bit
post-quantum).

## Installing liboqs

### Linux — Ubuntu / Debian

A packaged version may be available:

```bash
sudo apt update && sudo apt install liboqs-dev
```

Check whether the package exists first:

```bash
apt-cache search liboqs
```

If the package is not available (common on Ubuntu < 24.04), build from source:

```bash
sudo apt install cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -B build \
      -DOQS_DIST_BUILD=ON \
      -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --parallel $(nproc)
sudo cmake --install build
sudo ldconfig
```

Verify:

```bash
pkg-config --modversion liboqs
```

### macOS

```bash
brew install liboqs
```

If the formula is not yet in the default tap, install from the
open-quantum-safe tap:

```bash
brew tap open-quantum-safe/liboqs
brew install open-quantum-safe/liboqs/liboqs
```

Verify the install prefix for CMake:

```bash
brew --prefix liboqs
# typically /opt/homebrew/opt/liboqs  (Apple Silicon)
#         or /usr/local/opt/liboqs   (Intel)
```

### Windows — MSYS2 (MinGW-w64 toolchain)

liboqs is not yet available as a pre-built MSYS2 package.  Build from source
inside the MinGW-w64 shell:

```bash
# Open "MSYS2 MinGW 64-bit" terminal
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
          mingw-w64-x86_64-openssl git

git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -B build -G Ninja \
      -DOQS_DIST_BUILD=ON \
      -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="C:/msys64/mingw64"
cmake --build build
cmake --install build
```

The install prefix `C:/msys64/mingw64` places headers and libraries where the
MinGW-w64 toolchain already searches, so no extra CMake hints are needed.

## How OpenCryptUI picks up liboqs

The CMake orchestrator needs to add the following block to `CMakeLists.txt`
(note: do **not** add it yourself — this README documents the requirement for
the orchestrator):

```cmake
find_package(liboqs QUIET)

if(liboqs_FOUND)
    message(STATUS "liboqs found — building with PQ hybrid support")
    target_compile_definitions(opencryptui PRIVATE OCUI_HAVE_LIBOQS)
    target_sources(opencryptui PRIVATE src/pq_hybrid.cpp)
    target_link_libraries(opencryptui PRIVATE OQS::oqs)
else()
    message(STATUS "liboqs NOT found — PQ hybrid support disabled (stub build)")
    target_sources(opencryptui PRIVATE src/pq_hybrid_stub.cpp)
endif()

# Same pattern for the test executable:
if(liboqs_FOUND)
    target_compile_definitions(test_pq_hybrid PRIVATE OCUI_HAVE_LIBOQS)
    target_sources(test_pq_hybrid PRIVATE src/pq_hybrid.cpp)
    target_link_libraries(test_pq_hybrid PRIVATE OQS::oqs)
else()
    target_sources(test_pq_hybrid PRIVATE src/pq_hybrid_stub.cpp)
endif()
```

If liboqs is installed to a non-standard prefix (e.g., `/usr/local`), pass
`-Dliboqs_DIR=/usr/local/lib/cmake/liboqs` to the CMake configure step.

## File-format integration (open question for follow-up)

The current OCUI file format stores a fixed header followed by the ciphertext
and an HMAC trailer.  The `HybridWrappedKey` struct produced by
`PqHybrid::wrap()` adds approximately **1.7 KB** of data per recipient
(92 bytes classical blob + 1628 bytes PQ blob + 32 bytes fingerprint).

Two options exist; the orchestrator / maintainer should decide before
shipping:

1. **OCUI v4 trailer**: Append the wrapped blobs as a new optional section
   after the existing HMAC trailer, identified by a magic tag.  This keeps
   everything in one file and simplifies key management.  Downside: requires
   a format version bump and careful backward-compatibility logic.

2. **Sidecar `.pq` file**: Store the wrapped blobs in a separate
   `<filename>.enc.pq` file next to the main `.enc` file.  This avoids any
   change to the existing format and keeps the PQ layer fully decoupled.
   Downside: two files must travel together; losing the sidecar means losing
   the ability to decrypt in PQ mode.

**Recommendation for follow-up**: Option 1 (v4 trailer) is preferable for
usability; the sidecar approach is safer as a first iteration because it
cannot corrupt existing files.  Flag for design discussion before merging PQ
support into the main branch.
