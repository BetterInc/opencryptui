// Static algorithm / KDF lookup tables and the cipher-IV-size helper.
// Pure functions — extracted from encryptionengine_crypto.cpp to keep the
// orchestration code there focused on the encrypt/decrypt flow. No
// behaviour change; declarations live in include/encryptionengine.h.
#include "encryptionengine.h"

// IV size depends on the cipher mode.
//   AES-GCM / ChaCha20-Poly1305 → 12 bytes (96-bit nonce per spec)
//   AES-CBC / AES-CTR / Camellia → 16 bytes
//   XChaCha20                    → 24 bytes (not currently exposed, but guarded)
/*static*/ int EncryptionEngine::ivSizeForAlgorithm(const QString& algorithm)
{
    if (algorithm.contains("GCM") ||
        algorithm == "ChaCha20-Poly1305")
        return 12;
    if (algorithm == "XChaCha20")
        return 24;
    return 16; // CBC, CTR, Camellia, fallback
}

// Algorithm <-> numeric-ID mappings. The ID is stored in the OCUI v2
// file header so decrypt can cryptographically bind the cipher choice
// rather than trust a runtime parameter.
/*static*/ quint8 EncryptionEngine::algorithmId(const QString& algorithm)
{
    if (algorithm == "AES-256-GCM")        return ALG_ID_AES256_GCM;
    if (algorithm == "ChaCha20-Poly1305")  return ALG_ID_CHACHA20_POLY1305;
    if (algorithm == "AES-256-CTR")        return ALG_ID_AES256_CTR;
    if (algorithm == "AES-256-CBC")        return ALG_ID_AES256_CBC;
    if (algorithm == "AES-128-GCM")        return ALG_ID_AES128_GCM;
    if (algorithm == "AES-128-CTR")        return ALG_ID_AES128_CTR;
    if (algorithm == "AES-192-GCM")        return ALG_ID_AES192_GCM;
    if (algorithm == "AES-192-CTR")        return ALG_ID_AES192_CTR;
    if (algorithm == "AES-128-CBC")        return ALG_ID_AES128_CBC;
    if (algorithm == "AES-192-CBC")        return ALG_ID_AES192_CBC;
    if (algorithm == "Camellia-256-CBC")   return ALG_ID_CAMELLIA256_CBC;
    if (algorithm == "Camellia-128-CBC")   return ALG_ID_CAMELLIA128_CBC;
    return ALG_ID_UNKNOWN;
}

/*static*/ QString EncryptionEngine::algorithmFromId(quint8 id)
{
    switch (id) {
    case ALG_ID_AES256_GCM:        return "AES-256-GCM";
    case ALG_ID_CHACHA20_POLY1305: return "ChaCha20-Poly1305";
    case ALG_ID_AES256_CTR:        return "AES-256-CTR";
    case ALG_ID_AES256_CBC:        return "AES-256-CBC";
    case ALG_ID_AES128_GCM:        return "AES-128-GCM";
    case ALG_ID_AES128_CTR:        return "AES-128-CTR";
    case ALG_ID_AES192_GCM:        return "AES-192-GCM";
    case ALG_ID_AES192_CTR:        return "AES-192-CTR";
    case ALG_ID_AES128_CBC:        return "AES-128-CBC";
    case ALG_ID_AES192_CBC:        return "AES-192-CBC";
    case ALG_ID_CAMELLIA256_CBC:   return "Camellia-256-CBC";
    case ALG_ID_CAMELLIA128_CBC:   return "Camellia-128-CBC";
    default:                       return QString();
    }
}

/*static*/ quint8 EncryptionEngine::kdfId(const QString& kdf)
{
    if (kdf == "PBKDF2") return KDF_ID_PBKDF2;
    if (kdf == "Argon2") return KDF_ID_ARGON2;
    if (kdf == "Scrypt") return KDF_ID_SCRYPT;
    return KDF_ID_UNKNOWN;
}

/*static*/ QString EncryptionEngine::kdfFromId(quint8 id)
{
    switch (id) {
    case KDF_ID_PBKDF2: return "PBKDF2";
    case KDF_ID_ARGON2: return "Argon2";
    case KDF_ID_SCRYPT: return "Scrypt";
    default:            return QString();
    }
}
