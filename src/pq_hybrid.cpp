// pq_hybrid.cpp — Full implementation using liboqs + libsodium.
//
// Compiled ONLY when OCUI_HAVE_LIBOQS is defined.  The CMake orchestrator must
// conditionally compile this file; pq_hybrid_stub.cpp provides the same
// symbols when the define is absent so the link always succeeds.

#ifdef OCUI_HAVE_LIBOQS

#include "pq_hybrid.h"

#include <oqs/oqs.h>      // ML-KEM-1024 (liboqs)
#include <sodium.h>       // X25519, random, HKDF helpers
#include <openssl/evp.h>  // EVP_aes_256_gcm, HKDF via EVP_KDF (OpenSSL 3.x)
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <QDebug>
#include <array>
#include <cstring>

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------
static constexpr int DEK_LEN          = 32;   // AES-256 key length
static constexpr int KEK_LEN          = 32;   // HKDF output length
static constexpr int SALT_LEN         = 32;   // HKDF salt length (random)
static constexpr int GCM_NONCE_LEN    = 12;
static constexpr int GCM_TAG_LEN      = 16;
static constexpr int X25519_PUB_LEN   = 32;
static constexpr int X25519_SEC_LEN   = 32;
static constexpr int MLKEM_CT_LEN     = 1568; // ML-KEM-1024 ciphertext
static constexpr int MLKEM_SS_LEN     = 32;   // ML-KEM-1024 shared secret
static constexpr int MLKEM_PUB_LEN    = 1568;
static constexpr int MLKEM_SEC_LEN    = 3168;

static const char* HKDF_INFO         = "OCUI-HYBRID-V1";
static const size_t HKDF_INFO_LEN    = 14; // strlen("OCUI-HYBRID-V1")

// AES-256-GCM encrypted DEK: [GCM_NONCE_LEN][DEK_LEN + GCM_TAG_LEN]
static constexpr int WRAPPED_DEK_LEN = GCM_NONCE_LEN + DEK_LEN + GCM_TAG_LEN;

// classicalBlob layout: [X25519_PUB_LEN][SALT_LEN][WRAPPED_DEK_LEN]
static constexpr int CLASSICAL_BLOB_LEN = X25519_PUB_LEN + SALT_LEN + WRAPPED_DEK_LEN;

// pqBlob layout: [MLKEM_CT_LEN][WRAPPED_DEK_LEN]
// The same salt lives in classicalBlob; we read it from there during unwrap.
static constexpr int PQ_BLOB_LEN = MLKEM_CT_LEN + WRAPPED_DEK_LEN;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Derive a 32-byte KEK using HKDF-SHA-256 (OpenSSL 3.x EVP_KDF API).
// ikm  = classical_ss (32) || pq_ss (32)  — 64 bytes total
// salt = random 32 bytes
// info = "OCUI-HYBRID-V1"
static bool deriveKek(const unsigned char* classical_ss,
                      const unsigned char* pq_ss,
                      const unsigned char* salt,
                      unsigned char* kek_out)
{
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        qWarning() << "PqHybrid: EVP_KDF_fetch(HKDF) failed";
        return false;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        qWarning() << "PqHybrid: EVP_KDF_CTX_new failed";
        return false;
    }

    // IKM = classical_ss || pq_ss
    unsigned char ikm[64];
    std::memcpy(ikm,      classical_ss, 32);
    std::memcpy(ikm + 32, pq_ss,        32);

    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA2-256"), 0);
    params[idx++] = OSSL_PARAM_construct_octet_string("key",   ikm,  sizeof(ikm));
    params[idx++] = OSSL_PARAM_construct_octet_string("salt",  const_cast<unsigned char*>(salt), SALT_LEN);
    params[idx++] = OSSL_PARAM_construct_octet_string("info",  const_cast<char*>(HKDF_INFO), HKDF_INFO_LEN);
    params[idx++] = OSSL_PARAM_construct_end();

    size_t out_len = KEK_LEN;
    bool ok = (EVP_KDF_derive(kctx, kek_out, out_len, params) == 1);
    EVP_KDF_CTX_free(kctx);

    sodium_memzero(ikm, sizeof(ikm));
    return ok;
}

// AES-256-GCM encrypt plaintext (DEK_LEN bytes) under kek.
// Output: [nonce (12)][ciphertext (DEK_LEN)][tag (16)] — WRAPPED_DEK_LEN bytes total.
static bool aesGcmEncryptDek(const unsigned char* kek,
                              const unsigned char* plaintext,
                              unsigned char* out)
{
    unsigned char* nonce = out;
    unsigned char* ct    = out + GCM_NONCE_LEN;
    unsigned char* tag   = ct  + DEK_LEN;

    randombytes_buf(nonce, GCM_NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr)) break;
        if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, kek, nonce)) break;

        int outl = 0;
        if (!EVP_EncryptUpdate(ctx, ct, &outl, plaintext, DEK_LEN)) break;
        int finl = 0;
        if (!EVP_EncryptFinal_ex(ctx, ct + outl, &finl)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-256-GCM decrypt. Returns false on authentication failure (tampering).
static bool aesGcmDecryptDek(const unsigned char* kek,
                              const unsigned char* in,   // WRAPPED_DEK_LEN bytes
                              unsigned char* plaintext_out)
{
    const unsigned char* nonce = in;
    const unsigned char* ct    = in + GCM_NONCE_LEN;
    // tag is appended after ciphertext — make a mutable copy for the OpenSSL API
    unsigned char tag[GCM_TAG_LEN];
    std::memcpy(tag, ct + DEK_LEN, GCM_TAG_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr)) break;
        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, kek, nonce)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag)) break;

        int outl = 0;
        if (!EVP_DecryptUpdate(ctx, plaintext_out, &outl, ct, DEK_LEN)) break;
        int finl = 0;
        // EVP_DecryptFinal_ex returns <= 0 on tag mismatch (authentication failure)
        if (EVP_DecryptFinal_ex(ctx, plaintext_out + outl, &finl) <= 0) break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

namespace PqHybrid {

bool isAvailable()
{
    // OQS_VERSION_TEXT is defined by oqs/oqs.h — if we compiled this TU, it's
    // definitely available at runtime too (statically linked or the .so was
    // found by the linker).
    return true;
}

KeyPair generateKeyPair()
{
    KeyPair kp;

    // --- X25519 via libsodium ---
    kp.classicalPublic.resize(X25519_PUB_LEN);
    kp.classicalSecret.resize(X25519_SEC_LEN);
    crypto_kx_keypair(
        reinterpret_cast<unsigned char*>(kp.classicalPublic.data()),
        reinterpret_cast<unsigned char*>(kp.classicalSecret.data()));

    // --- ML-KEM-1024 via liboqs ---
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        // Fallback: try legacy Kyber1024 name for older liboqs versions
        kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    }
    if (!kem) {
        qWarning() << "PqHybrid: OQS_KEM_new(ML-KEM-1024) failed — liboqs may lack this algorithm";
        kp = KeyPair{};
        return kp;
    }

    kp.pqPublic.resize(static_cast<int>(kem->length_public_key));
    kp.pqSecret.resize(static_cast<int>(kem->length_secret_key));

    if (OQS_KEM_keypair(kem,
                        reinterpret_cast<unsigned char*>(kp.pqPublic.data()),
                        reinterpret_cast<unsigned char*>(kp.pqSecret.data()))
        != OQS_SUCCESS)
    {
        qWarning() << "PqHybrid: OQS_KEM_keypair failed";
        OQS_KEM_free(kem);
        kp = KeyPair{};
        return kp;
    }

    OQS_KEM_free(kem);
    return kp;
}

HybridWrappedKey wrap(const QByteArray& dek,
                      const QByteArray& classicalPublic,
                      const QByteArray& pqPublic)
{
    HybridWrappedKey result;

    if (dek.size() != DEK_LEN) {
        qWarning() << "PqHybrid::wrap: DEK must be exactly 32 bytes, got" << dek.size();
        return result;
    }
    if (classicalPublic.size() != X25519_PUB_LEN) {
        qWarning() << "PqHybrid::wrap: classical public key must be 32 bytes";
        return result;
    }
    if (pqPublic.size() != MLKEM_PUB_LEN) {
        qWarning() << "PqHybrid::wrap: PQ public key must be 1568 bytes, got" << pqPublic.size();
        return result;
    }

    // --- Step 1: X25519 ephemeral ECDH ---
    unsigned char eph_pub[X25519_PUB_LEN];
    unsigned char eph_sec[X25519_SEC_LEN];
    crypto_kx_keypair(eph_pub, eph_sec);

    unsigned char classical_ss[32];
    // crypto_scalarmult: scalar = eph_sec, point = recipient pub → shared secret
    if (crypto_scalarmult(classical_ss, eph_sec,
                          reinterpret_cast<const unsigned char*>(classicalPublic.constData()))
        != 0)
    {
        qWarning() << "PqHybrid::wrap: X25519 scalar mult failed (low-order point?)";
        sodium_memzero(eph_sec, sizeof(eph_sec));
        return result;
    }
    sodium_memzero(eph_sec, sizeof(eph_sec));

    // --- Step 2: ML-KEM-1024 encapsulation ---
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        qWarning() << "PqHybrid::wrap: OQS_KEM_new failed";
        return result;
    }

    QByteArray pq_ct(static_cast<int>(kem->length_ciphertext), '\0');
    unsigned char pq_ss[MLKEM_SS_LEN];

    if (OQS_KEM_encaps(kem,
                       reinterpret_cast<unsigned char*>(pq_ct.data()),
                       pq_ss,
                       reinterpret_cast<const unsigned char*>(pqPublic.constData()))
        != OQS_SUCCESS)
    {
        qWarning() << "PqHybrid::wrap: OQS_KEM_encaps failed";
        OQS_KEM_free(kem);
        sodium_memzero(pq_ss, sizeof(pq_ss));
        return result;
    }
    OQS_KEM_free(kem);

    // --- Step 3: Derive KEK via HKDF-SHA-256 ---
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);

    unsigned char kek[KEK_LEN];
    if (!deriveKek(classical_ss, pq_ss, salt, kek)) {
        sodium_memzero(classical_ss, sizeof(classical_ss));
        sodium_memzero(pq_ss, sizeof(pq_ss));
        return result;
    }
    sodium_memzero(classical_ss, sizeof(classical_ss));
    sodium_memzero(pq_ss, sizeof(pq_ss));

    // --- Step 4: Encrypt DEK ---
    unsigned char wrapped_dek[WRAPPED_DEK_LEN];
    if (!aesGcmEncryptDek(kek, reinterpret_cast<const unsigned char*>(dek.constData()), wrapped_dek)) {
        sodium_memzero(kek, sizeof(kek));
        qWarning() << "PqHybrid::wrap: AES-GCM encryption failed";
        return result;
    }
    sodium_memzero(kek, sizeof(kek));

    // --- Step 5: Build classicalBlob = [eph_pub(32)][salt(32)][wrapped_dek(60)] ---
    result.classicalBlob.resize(CLASSICAL_BLOB_LEN);
    unsigned char* cb = reinterpret_cast<unsigned char*>(result.classicalBlob.data());
    std::memcpy(cb,                          eph_pub,     X25519_PUB_LEN);
    std::memcpy(cb + X25519_PUB_LEN,         salt,        SALT_LEN);
    std::memcpy(cb + X25519_PUB_LEN + SALT_LEN, wrapped_dek, WRAPPED_DEK_LEN);

    // --- Step 6: Build pqBlob = [pq_ct(1568)][wrapped_dek(60)] ---
    result.pqBlob.resize(PQ_BLOB_LEN);
    unsigned char* pb = reinterpret_cast<unsigned char*>(result.pqBlob.data());
    std::memcpy(pb,             pq_ct.constData(), MLKEM_CT_LEN);
    std::memcpy(pb + MLKEM_CT_LEN, wrapped_dek,   WRAPPED_DEK_LEN);

    // --- Step 7: Fingerprint = SHA-256(classicalPublic || pqPublic) ---
    unsigned char fp[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st,
        reinterpret_cast<const unsigned char*>(classicalPublic.constData()),
        static_cast<unsigned long long>(classicalPublic.size()));
    crypto_hash_sha256_update(&st,
        reinterpret_cast<const unsigned char*>(pqPublic.constData()),
        static_cast<unsigned long long>(pqPublic.size()));
    crypto_hash_sha256_final(&st, fp);
    result.fingerprint = QByteArray(reinterpret_cast<const char*>(fp),
                                    static_cast<int>(crypto_hash_sha256_BYTES));

    sodium_memzero(wrapped_dek, sizeof(wrapped_dek));
    return result;
}

QByteArray unwrap(const HybridWrappedKey& blob,
                  const QByteArray& classicalSecret,
                  const QByteArray& pqSecret,
                  QString* errorOut)
{
    auto fail = [&](const char* msg) -> QByteArray {
        qWarning() << "PqHybrid::unwrap:" << msg;
        if (errorOut) *errorOut = QString::fromLatin1(msg);
        return QByteArray{};
    };

    // --- Validate blob sizes ---
    if (blob.classicalBlob.size() != CLASSICAL_BLOB_LEN)
        return fail("classicalBlob has unexpected size");
    if (blob.pqBlob.size() != PQ_BLOB_LEN)
        return fail("pqBlob has unexpected size");
    if (classicalSecret.size() != X25519_SEC_LEN)
        return fail("classicalSecret must be 32 bytes");
    if (pqSecret.size() != MLKEM_SEC_LEN)
        return fail("pqSecret must be 3168 bytes");

    const unsigned char* cb = reinterpret_cast<const unsigned char*>(blob.classicalBlob.constData());
    const unsigned char* eph_pub    = cb;
    const unsigned char* salt       = cb + X25519_PUB_LEN;
    const unsigned char* wrapped_c  = cb + X25519_PUB_LEN + SALT_LEN;

    const unsigned char* pb = reinterpret_cast<const unsigned char*>(blob.pqBlob.constData());
    const unsigned char* pq_ct      = pb;
    const unsigned char* wrapped_p  = pb + MLKEM_CT_LEN;

    // --- Step 1: X25519 ---
    unsigned char classical_ss[32];
    if (crypto_scalarmult(classical_ss,
                          reinterpret_cast<const unsigned char*>(classicalSecret.constData()),
                          eph_pub) != 0)
        return fail("X25519 scalar mult failed");

    // --- Step 2: ML-KEM-1024 decapsulation ---
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        sodium_memzero(classical_ss, sizeof(classical_ss));
        return fail("OQS_KEM_new failed");
    }

    unsigned char pq_ss[MLKEM_SS_LEN];
    if (OQS_KEM_decaps(kem,
                       pq_ss,
                       pq_ct,
                       reinterpret_cast<const unsigned char*>(pqSecret.constData()))
        != OQS_SUCCESS)
    {
        OQS_KEM_free(kem);
        sodium_memzero(classical_ss, sizeof(classical_ss));
        return fail("ML-KEM-1024 decapsulation failed");
    }
    OQS_KEM_free(kem);

    // --- Step 3: Derive KEK ---
    unsigned char kek[KEK_LEN];
    if (!deriveKek(classical_ss, pq_ss, salt, kek)) {
        sodium_memzero(classical_ss, sizeof(classical_ss));
        sodium_memzero(pq_ss, sizeof(pq_ss));
        return fail("HKDF derivation failed");
    }
    sodium_memzero(classical_ss, sizeof(classical_ss));
    sodium_memzero(pq_ss, sizeof(pq_ss));

    // --- Step 4+5: Decrypt both halves ---
    unsigned char dek_c[DEK_LEN];
    unsigned char dek_p[DEK_LEN];

    bool ok_c = aesGcmDecryptDek(kek, wrapped_c, dek_c);
    bool ok_p = aesGcmDecryptDek(kek, wrapped_p, dek_p);
    sodium_memzero(kek, sizeof(kek));

    if (!ok_c) return fail("classicalBlob AES-GCM authentication failed (tampered?)");
    if (!ok_p) return fail("pqBlob AES-GCM authentication failed (tampered?)");

    // --- Step 6: Both halves must agree ---
    if (sodium_memcmp(dek_c, dek_p, DEK_LEN) != 0) {
        sodium_memzero(dek_c, sizeof(dek_c));
        sodium_memzero(dek_p, sizeof(dek_p));
        return fail("DEK mismatch between classical and PQ blobs — possible attack or corruption");
    }

    QByteArray dek(reinterpret_cast<const char*>(dek_c), DEK_LEN);
    sodium_memzero(dek_c, sizeof(dek_c));
    sodium_memzero(dek_p, sizeof(dek_p));
    return dek;
}

} // namespace PqHybrid

#endif // OCUI_HAVE_LIBOQS
