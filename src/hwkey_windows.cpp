// hwkey_windows.cpp — Windows TPM 2.0 hardware key wrapping via CNG (scaffolding).
//
// BACKEND: Windows CNG NCrypt / BCrypt via ncrypt.h / bcrypt.h.
//
// DETECTION:
//   NCryptOpenStorageProvider(NCRYPT_TPM_KEY_STORAGE_PROVIDER) is the
//   canonical Windows CNG call for TPM-backed key storage. If it succeeds a
//   TPM 2.0 is present and accessible. We open and immediately close the
//   provider handle as a probe.
//
// CURRENT STATUS — SCAFFOLDING:
//   detect() probes for the TPM provider and returns WindowsTPM in the backend
//   field if found, None otherwise. HOWEVER, supportsKeyWrap is ALWAYS false
//   and effectiveBackend is ALWAYS Backend::Stub, because wrapKey/unwrapKey
//   still delegate to the software stub. See the API HONESTY CONTRACT in hwkey.h.
//
//   Until real NCryptEncrypt/NCryptDecrypt calls replace the stub routing:
//     detect().backend          == WindowsTPM  (hardware IS present)
//     detect().supportsKeyWrap  == false       (HW wrap NOT implemented)
//     detect().effectiveBackend == Stub        (software actually runs)
//     wrappingBackend()         == Stub        (confirmed by public API)
//
//   DO NOT display "TPM-protected" to the user based solely on
//   detect().backend. Gate on supportsKeyWrap == true or
//   wrappingBackend() == Backend::WindowsTPM.
//
// TODO(hwkey-real-impl): Windows CNG / TPM real implementation steps:
//   1. Open TPM provider:
//        NCryptOpenStorageProvider(&hProvider,
//                                  MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)
//      or the TPM-specific:
//        NCryptOpenStorageProvider(&hProvider,
//                                  NCRYPT_TPM_KEY_STORAGE_PROVIDER, 0)
//
//   2. Key generation (first use): NCryptCreatePersistedKey() with:
//        - pszKeyName = L"OpenCryptUI_WrapKey"
//        - dwLegacyKeySpec = AT_KEYEXCHANGE
//        - dwFlags = NCRYPT_OVERWRITE_KEY_FLAG (only on first run)
//      Then NCryptSetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, "RSA"/"ECDH"...)
//      and NCryptFinalizeKey(hKey, NCRYPT_UI_PROTECT_KEY_FLAG) to bind a
//      PIN/password UI prompt. For TPM-resident keys, set property
//      NCRYPT_TPM_PAD_OAEP_FLAG or use the NCRYPT_PKCS1_PADDING_FLAG.
//
//   3. Wrap: NCryptEncrypt() with hKey (public) and the DEK plaintext.
//        - dwFlags = NCRYPT_PAD_OAEP_FLAG + BCRYPT_OAEP_PADDING_INFO
//          specifying BCRYPT_SHA256_ALGORITHM as the hash.
//        - First call with pbOutput=NULL to get required output size.
//        - Pass the resulting buffer to outerWrap() as backendBlob so the
//          on-disk format conceals the OAEP-wrapped structure.
//
//   4. Unwrap: NCryptDecrypt() with hKey (private, TPM-resident) and the
//      blob. Windows will surface a CNG UI prompt (consent dialog or PIN
//      entry) automatically based on the key's NCRYPT_UI_PROTECT_KEY_FLAG.
//
//   5. PIN / consent UX: set NCRYPT_UI_PROTECT_KEY_FLAG in NCryptFinalizeKey()
//      to require user presence. For stronger protection set
//      NCRYPT_UI_APPCONTAINER_ACCESS_MEDIUM_FLAG.
//
//   6. When real wrapping is implemented, set supportsKeyWrap = true in the
//      WindowsTPM branch of detect(), set effectiveBackend =
//      Backend::WindowsTPM, and update wrappingBackend() in hwkey_stub.cpp
//      accordingly.
//
//   Headers: <ncrypt.h>, <bcrypt.h>. Link: ncrypt.lib, bcrypt.lib.
//   Add to CMakeLists.txt for WIN32 targets:
//     target_link_libraries(HwKeyLib PRIVATE ncrypt bcrypt)

#include "hwkey.h"

#ifdef Q_OS_WIN

// Windows SDK headers. Order matters: windows.h must come before ncrypt.h.
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <ncrypt.h>

namespace HwKey {

// Forward declarations for the stub fallback functions defined in hwkey_stub.cpp.
namespace Stub {
QByteArray wrapKey(const QByteArray& dek, QString* errorOut);
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut);
} // namespace Stub

// ---------------------------------------------------------------------------
// probeWindowsTPM() — attempt to open the CNG TPM key storage provider.
//   Returns true iff the provider opens successfully.
// ---------------------------------------------------------------------------
static bool probeWindowsTPM()
{
    NCRYPT_PROV_HANDLE hProvider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProvider,
        MS_PLATFORM_KEY_STORAGE_PROVIDER,
        0);
    if (status == ERROR_SUCCESS && hProvider != 0) {
        NCryptFreeObject(hProvider);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// detect() — Windows implementation.
//
//   Returns backend = WindowsTPM when the CNG TPM provider is accessible,
//   reporting that hardware IS present. However, supportsKeyWrap is always
//   false and effectiveBackend is always Backend::Stub because the real
//   NCryptEncrypt implementation is not yet wired in. wrapKey() routes to
//   the stub.
// ---------------------------------------------------------------------------
Capabilities detect()
{
    if (probeWindowsTPM()) {
        return Capabilities{
            /*backend=*/        Backend::WindowsTPM,
            /*effectiveBackend=*/Backend::Stub,  // real HW wrap not yet implemented
            /*supportsKeyWrap=*/false,  // stub routes here; NOT hardware-bound
            /*supportsSign=*/   false,
            /*device_name=*/    QLatin1String("Windows Platform TPM (CNG)")
        };
    }
    return Capabilities{
        /*backend=*/        Backend::None,
        /*effectiveBackend=*/Backend::Stub,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/   false,
        /*device_name=*/    QLatin1String("None (no CNG TPM provider)")
    };
}

// ---------------------------------------------------------------------------
// wrapKey() — Windows implementation.
//
//   API CONTRACT: delegates to the software stub. wrappingBackend() == Stub.
//   Even when a CNG TPM provider is present, this function uses the software
//   fallback until TODO(hwkey-real-impl) is completed.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with NCryptEncrypt() using
    // MS_PLATFORM_KEY_STORAGE_PROVIDER and NCRYPT_PAD_OAEP_FLAG, then pass
    // the result to outerWrap() to conceal the OAEP structure on disk.
    return Stub::wrapKey(dek, errorOut);
}

// ---------------------------------------------------------------------------
// unwrapKey() — Windows implementation.
//   Scaffolding: delegates to stub until real NCryptDecrypt calls are in place.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with NCryptDecrypt() which will
    //   trigger the CNG UI consent/PIN dialog automatically.
    return Stub::unwrapKey(wrappedBlob, errorOut);
}

} // namespace HwKey

#endif // Q_OS_WIN
