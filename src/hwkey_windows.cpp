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
//   detect() probes for the TPM provider and returns WindowsTPM if found,
//   None otherwise. wrapKey/unwrapKey delegate to the stub.
//   See the TODO block below for concrete next steps.
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
//        - Serialize: write cbResult (4 bytes LE) + pbResult into blob.
//
//   4. Unwrap: NCryptDecrypt() with hKey (private, TPM-resident) and the
//      blob. Windows will surface a CNG UI prompt (consent dialog or PIN
//      entry) automatically based on the key's NCRYPT_UI_PROTECT_KEY_FLAG.
//
//   5. PIN / consent UX: set NCRYPT_UI_PROTECT_KEY_FLAG in NCryptFinalizeKey()
//      to require user presence. For stronger protection set
//      NCRYPT_UI_APPCONTAINER_ACCESS_MEDIUM_FLAG.
//      Alternatively use CryptUIWizImport for a richer dialog.
//
//   6. Platform Crypto Provider (TBS):
//      For lower-level TPM2 access without NCrypt, use Tbsi_Context_Create()
//      (TBS API) and Tbsip_Submit_Command() to send TPM2_CC_Seal / Unseal
//      commands directly. This requires parsing TPM2B structures manually;
//      prefer the NCrypt path for maintainability.
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
// ---------------------------------------------------------------------------
Capabilities detect()
{
    if (probeWindowsTPM()) {
        return Capabilities{
            Backend::WindowsTPM,
            /*supportsKeyWrap=*/true,
            /*supportsSign=*/false, // signing not scaffolded yet
            /*device_name=*/QLatin1String("Windows Platform TPM (CNG)")
        };
    }
    return Capabilities{
        Backend::None,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/false,
        /*device_name=*/QLatin1String("None (no CNG TPM provider)")
    };
}

// ---------------------------------------------------------------------------
// wrapKey() — Windows implementation.
//   Scaffolding: delegates to stub until real NCryptEncrypt calls are in place.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with NCryptEncrypt() using
    //   MS_PLATFORM_KEY_STORAGE_PROVIDER and NCRYPT_PAD_OAEP_FLAG.
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
