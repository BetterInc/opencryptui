// pq_hybrid.h — Post-quantum hybrid key-wrapping for OpenCryptUI.
//
// This header defines the PqHybrid namespace which provides a classical +
// post-quantum key-encapsulation layer on top of the existing AES-256-GCM /
// ChaCha20-Poly1305 file encryption engine.  The PQ component uses ML-KEM-1024
// (NIST FIPS 203, formerly Kyber1024) via liboqs.  The classical component uses
// X25519 ECDH via libsodium.
//
// Build-system integration (TODO for CMake orchestrator):
//   find_package(liboqs REQUIRED)        # locates OQS::oqs target
//   if(liboqs_FOUND)
//     target_compile_definitions(opencryptui PRIVATE OCUI_HAVE_LIBOQS)
//     target_link_libraries(opencryptui PRIVATE OQS::oqs)
//   endif()
//
// When OCUI_HAVE_LIBOQS is not defined at compile time, all functions fall back
// to stubs in pq_hybrid_stub.cpp so the rest of the engine compiles and links
// without liboqs installed.

#ifndef PQ_HYBRID_H
#define PQ_HYBRID_H

#include <QByteArray>
#include <QString>

namespace PqHybrid {

// ---------------------------------------------------------------------------
// HybridWrappedKey — the blob stored alongside each encrypted file.
//
// Both halves must be present and valid to recover the DEK; an attacker who
// breaks only X25519 (Shor's algorithm) or only ML-KEM-1024 still cannot
// recover the DEK because the final KEK is derived from both shared secrets
// jointly via HKDF.
// ---------------------------------------------------------------------------
struct HybridWrappedKey {
    // X25519 ECDH ephemeral public key (32 bytes) || AES-256-GCM( kek_classical, dek )
    // Layout: [32 bytes ephemeral pubkey][12 bytes nonce][48 bytes ciphertext+tag]
    QByteArray classicalBlob;   // 92 bytes when populated

    // ML-KEM-1024 encapsulated shared secret || AES-256-GCM( kek_pq, dek )
    // Layout: [1568 bytes ML-KEM ct][12 bytes nonce][48 bytes ciphertext+tag]
    QByteArray pqBlob;          // 1628 bytes when populated

    // SHA-256 fingerprint of (classicalPublic || pqPublic) for key identification.
    // Not secret; used to match a blob to the recipient key pair at decrypt time.
    QByteArray fingerprint;     // 32 bytes
};

// ---------------------------------------------------------------------------
// KeyPair — generated once per recipient and stored securely by the caller.
//
// Public halves go into the file header; secret halves should be wrapped by the
// hardware-key layer (HwKey) before storage.
// ---------------------------------------------------------------------------
struct KeyPair {
    QByteArray classicalPublic;  // 32 bytes  (X25519)
    QByteArray classicalSecret;  // 32 bytes  (X25519)
    QByteArray pqPublic;         // 1568 bytes (ML-KEM-1024 encapsulation key)
    QByteArray pqSecret;         // 3168 bytes (ML-KEM-1024 decapsulation key)
};

// ---------------------------------------------------------------------------
// isAvailable()
//
// Returns true iff the library was built with OCUI_HAVE_LIBOQS and the runtime
// liboqs shared library is present and loadable.  Always returns false in the
// stub build.
// ---------------------------------------------------------------------------
bool isAvailable();

// ---------------------------------------------------------------------------
// generateKeyPair()
//
// Generates a fresh hybrid key pair using libsodium (X25519) and liboqs
// (ML-KEM-1024).  Returns an all-empty KeyPair if isAvailable() is false.
// ---------------------------------------------------------------------------
KeyPair generateKeyPair();

// ---------------------------------------------------------------------------
// wrap()
//
// Wraps a 32-byte DEK for a recipient identified by their hybrid public key.
//
// Combiner construction:
//   1. Ephemeral X25519 key pair is generated.
//   2. classical_ss = X25519(ephemeral_secret, recipientClassicalPublic)   (32 B)
//   3. (pq_ct, pq_ss) = ML-KEM-1024.Encap(recipientPqPublic)
//      pq_ss is 32 bytes; pq_ct is 1568 bytes.
//   4. salt = random 32 bytes (stored in the blob header, not secret)
//   5. kek = HKDF-SHA256(
//                ikm  = classical_ss || pq_ss,   // 64 bytes
//                salt = salt,
//                info = "OCUI-HYBRID-V1",
//                len  = 32)
//   6. classicalBlob = ephemeralPubkey(32) || AES-256-GCM_Encrypt(kek, dek)
//   7. pqBlob        = pq_ct(1568)         || AES-256-GCM_Encrypt(kek, dek)
//      (Both halves encrypt the same DEK under the same kek so that unwrap can
//       verify each independently before XOR-combining.)
//
// Returns an empty HybridWrappedKey if isAvailable() is false or on any error.
// ---------------------------------------------------------------------------
HybridWrappedKey wrap(const QByteArray& dek,
                      const QByteArray& classicalPublic,
                      const QByteArray& pqPublic);

// ---------------------------------------------------------------------------
// unwrap()
//
// Recovers the DEK from a HybridWrappedKey.  BOTH classical and PQ paths are
// executed and both must produce the same DEK; this ensures that a compromise
// of only one algorithm does not break security.
//
// Algorithm:
//   1. Extract ephemeralPubkey from classicalBlob; compute
//      classical_ss = X25519(classicalSecret, ephemeralPubkey).
//   2. Extract pq_ct from pqBlob; compute
//      pq_ss = ML-KEM-1024.Decap(pqSecret, pq_ct).
//   3. Reconstruct kek via the same HKDF call as wrap().
//   4. Decrypt classicalBlob ciphertext → dek_c.
//   5. Decrypt pqBlob ciphertext        → dek_p.
//   6. Verify dek_c == dek_p; fail if not (integrity / tampering check).
//   7. Return dek_c.
//
// On any failure, returns an empty QByteArray and, if errorOut is non-null,
// writes a human-readable error string.
// ---------------------------------------------------------------------------
QByteArray unwrap(const HybridWrappedKey& blob,
                  const QByteArray& classicalSecret,
                  const QByteArray& pqSecret,
                  QString* errorOut = nullptr);

} // namespace PqHybrid

#endif // PQ_HYBRID_H
