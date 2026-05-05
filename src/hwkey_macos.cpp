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
//   detect() returns MacSecureEnclave when available, None otherwise.
//   wrapKey/unwrapKey delegate to the stub until the real SE API is in place.
//   See the TODO block below for concrete next steps.
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
//        - Persist the resulting blob alongside the encrypted file.
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
//      Alternatively rely on the automatic prompt triggered by the access
//      control on the SE key.
//
//   6. macOS 12+ / CryptoKit alternative: use CryptoKit.SecureEnclave.P256
//      from a Swift bridging module, which is higher-level and avoids some
//      CF memory management pitfalls in C++ code.
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
// ---------------------------------------------------------------------------
Capabilities detect()
{
    if (probeSecureEnclave()) {
        return Capabilities{
            Backend::MacSecureEnclave,
            /*supportsKeyWrap=*/true,
            /*supportsSign=*/true, // SE supports ECDSA P-256
            /*device_name=*/QLatin1String("Apple Secure Enclave")
        };
    }
    return Capabilities{
        Backend::None,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/false,
        /*device_name=*/QLatin1String("None (Secure Enclave unavailable)")
    };
}

// ---------------------------------------------------------------------------
// wrapKey() — macOS implementation.
//   Scaffolding: delegates to stub until real SE ECIES calls are in place.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with SecKeyCreateEncryptedData() using
    //   kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM.
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
