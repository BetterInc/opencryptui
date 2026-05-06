// hwkey_macos.cpp — macOS Secure Enclave hardware key wrapping (scaffolding).
//
// BACKEND: Apple Secure Enclave via Security.framework.
//
// DETECTION:
//   SecKeyCreateRandomKey() with kSecAttrTokenIDSecureEnclave is the canonical
//   way to test Secure Enclave availability. We call it with a minimal ECC key
//   request; if it succeeds the SE is present. On Intel Macs without a T2 chip
//   (pre-2018) and on iOS Simulator this will fail gracefully.
//
// CURRENT STATUS — SCAFFOLDING:
//   detect() returns MacSecureEnclave in the backend field when the SE is
//   available, None otherwise. HOWEVER, supportsKeyWrap is ALWAYS false and
//   effectiveBackend is ALWAYS Backend::Stub, because wrapKey/unwrapKey still
//   delegate to the software stub. See the API HONESTY CONTRACT in hwkey.h.
//
//   Until real SE ECIES calls replace the stub routing:
//     detect().backend          == MacSecureEnclave  (hardware IS present)
//     detect().supportsKeyWrap  == false             (HW wrap NOT implemented)
//     detect().effectiveBackend == Stub              (software actually runs)
//     wrappingBackend()         == Stub              (confirmed by public API)
//
//   DO NOT display "Secure Enclave protected" to the user based solely on
//   detect().backend. Gate on supportsKeyWrap == true or
//   wrappingBackend() == Backend::MacSecureEnclave.
//
// TODO(hwkey-real-impl): macOS Secure Enclave real implementation steps:
//   1. Key creation: SecKeyCreateRandomKey() with:
//        - kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom
//        - kSecAttrKeySizeInBits = 256 (P-256; only curve SE supports)
//        - kSecAttrTokenID = kSecAttrTokenIDSecureEnclave
//        - kSecAttrAccessControl: SecAccessControlCreateWithFlags() with
//          kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryAny
//          (or kSecAccessControlDevicePasscode as fallback)
//        - kSecAttrApplicationLabel = "com.opencryptui.hwkey" for retrieval
//        - kSecAttrIsPermanent = kCFBooleanTrue (persist in Secure Enclave)
//
//   2. Wrap: SecKeyCreateEncryptedData() with:
//        - algorithm = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
//        - The DEK bytes as the plaintext CFData.
//        - Returns a CFData blob (encrypted to the SE public key); only the
//          SE private key can decrypt it.
//        - Pass the resulting blob to outerWrap() as backendBlob so the
//          on-disk format conceals the ECIES structure.
//
//   3. Unwrap: SecKeyCreateDecryptedData() with the same algorithm.
//        - The OS will surface a LAContext biometric/passcode challenge
//          automatically if the access control flags require it.
//        - Pre-create an LAContext with localizedReason "Decrypt file key"
//          to control the prompt text shown to the user.
//
//   4. Key retrieval (existing keys): SecItemCopyMatching() with
//        - kSecClass = kSecClassKey
//        - kSecAttrApplicationLabel = "com.opencryptui.hwkey"
//        - kSecReturnRef = kCFBooleanTrue
//
//   5. Biometric UX: call LAContext evaluatePolicy:localizedReason:reply:
//      before SecKeyCreateDecryptedData() if you want a custom prompt.
//
//   6. macOS 12+ / CryptoKit alternative: use CryptoKit.SecureEnclave.P256
//      from a Swift bridging module, which is higher-level and avoids some
//      CF memory management pitfalls in C++ code.
//
//   7. When real wrapping is implemented, set supportsKeyWrap = true in the
//      MacSecureEnclave branch of detect(), set effectiveBackend =
//      Backend::MacSecureEnclave, and update wrappingBackend() accordingly.
//
//   Header to include: <Security/Security.h> (already linked via
//   SECURITY_FRAMEWORK in CMakeLists.txt for Darwin targets).

#include "hwkey.h"

#ifdef Q_OS_MACOS

// Security.framework is linked via CMakeLists.txt (SECURITY_FRAMEWORK).
#include <Security/Security.h>

namespace HwKey {

// Forward declarations for the stub fallback functions defined in hwkey_stub.cpp.
namespace Stub {
QByteArray wrapKey(const QByteArray& dek, QString* errorOut);
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut);
} // namespace Stub

// ---------------------------------------------------------------------------
// probeSecureEnclave() — return true iff a Secure Enclave key can be created.
//   We attempt SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave.
//   If the call succeeds we immediately delete the probe key and return true.
// ---------------------------------------------------------------------------
static bool probeSecureEnclave()
{
    CFErrorRef error = nullptr;

    // Build access control: require private key usage, no biometric gate
    // (probe only — we don't want a biometric prompt during detection).
    SecAccessControlRef access =
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage,
            &error);
    if (!access) {
        if (error) CFRelease(error);
        return false;
    }

    // Build the key attributes dictionary.
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(attrs, kSecAttrKeyType,
                         kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256;
    CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault,
                                         kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsNum);
    CFRelease(bitsNum);
    CFDictionarySetValue(attrs, kSecAttrTokenID,
                         kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(attrs, kSecAttrAccessControl, access);
    // Use a unique temporary label so we can delete the probe key afterward.
    CFDictionarySetValue(attrs, kSecAttrLabel,
                         CFSTR("com.opencryptui.hwkey.probe"));
    CFDictionarySetValue(attrs, kSecAttrIsPermanent, kCFBooleanFalse);

    SecKeyRef key = SecKeyCreateRandomKey(attrs, &error);
    CFRelease(attrs);
    CFRelease(access);

    if (!key) {
        if (error) CFRelease(error);
        return false;
    }

    CFRelease(key);
    return true;
}

// ---------------------------------------------------------------------------
// detect() — macOS implementation.
//
//   Returns backend = MacSecureEnclave when the SE is accessible, reporting
//   that hardware IS present. However, supportsKeyWrap is always false and
//   effectiveBackend is always Backend::Stub because the real SE ECIES
//   implementation is not yet wired in. wrapKey() routes to the stub.
// ---------------------------------------------------------------------------
Capabilities detect()
{
    if (probeSecureEnclave()) {
        return Capabilities{
            /*backend=*/        Backend::MacSecureEnclave,
            /*effectiveBackend=*/Backend::Stub,  // real HW wrap not yet implemented
            /*supportsKeyWrap=*/false,  // stub routes here; NOT hardware-bound
            /*supportsSign=*/   false,  // SE ECDSA not yet scaffolded
            /*device_name=*/    QLatin1String("Apple Secure Enclave")
        };
    }
    return Capabilities{
        /*backend=*/        Backend::None,
        /*effectiveBackend=*/Backend::Stub,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/   false,
        /*device_name=*/    QLatin1String("None (Secure Enclave unavailable)")
    };
}

// ---------------------------------------------------------------------------
// wrapKey() — macOS implementation.
//
//   API CONTRACT: delegates to the software stub. wrappingBackend() == Stub.
//   Even when the Secure Enclave is present, this function uses the software
//   fallback until TODO(hwkey-real-impl) is completed.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with SecKeyCreateEncryptedData() using
    // kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, then pass the
    // resulting CFData blob to outerWrap() to conceal the ECIES structure.
    return Stub::wrapKey(dek, errorOut);
}

// ---------------------------------------------------------------------------
// unwrapKey() — macOS implementation.
//   Scaffolding: delegates to stub until real SE ECIES calls are in place.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with SecKeyCreateDecryptedData() with
    //   an LAContext providing the biometric prompt.
    return Stub::unwrapKey(wrappedBlob, errorOut);
}

} // namespace HwKey

#endif // Q_OS_MACOS
