// hwkey_linux.cpp — Linux TPM 2.0 hardware key wrapping (scaffolding).
//
// BACKEND: LinuxTPM2 via tpm2-tss (ESAPI / FAPI).
//
// DETECTION:
//   The TPM resource manager character device is /dev/tpmrm0. Its presence
//   indicates a TPM 2.0 with kernel resource manager (tpm2-abrmd or kernel
//   RM). We also check read/write access so we don't falsely advertise the
//   backend when the process lacks permission (common in containers/CI).
//
// CURRENT STATUS — SCAFFOLDING:
//   detect() probes /dev/tpmrm0 and returns LinuxTPM2 if available,
//   None otherwise. wrapKey/unwrapKey delegate to the stub implementation
//   in hwkey_stub.cpp until the real tpm2-tss ESAPI calls are in place.
//   See the TODO block below for the concrete next steps.
//
// TODO(hwkey-real-impl): Linux TPM 2.0 real implementation steps:
//   1. Link against tpm2-tss: libtss2-esys, libtss2-rc, libtss2-mu.
//      Add to CMakeLists: pkg_search_module(TSS2_ESYS REQUIRED tss2-esys)
//      and link EncryptionLib/TestHwKeyStub against ${TSS2_ESYS_LIBRARIES}.
//
//   2. Session setup: call Esys_Initialize() with a TCTI pointing to
//      /dev/tpmrm0 (use Tss2_TctiLdr_Initialize("device", "/dev/tpmrm0")).
//      Then Esys_Startup(ctx, TPM2_SU_CLEAR) if not already started.
//
//   3. Primary key creation: Esys_CreatePrimary() with:
//        - hierarchy = ESYS_TR_RH_OWNER
//        - inSensitive.userAuth = PIN bytes (prompt user via Qt dialog)
//        - inPublic.type = TPM2_ALG_ECC, scheme = TPM2_ALG_NULL
//          (parent for wrapping; ECC p256 is widely supported on TPM 2.0)
//        - Persist it with Esys_EvictControl() so it survives reboot.
//
//   4. Wrap (seal): Esys_Create() under the primary key with:
//        - inSensitive.data = dek (the raw DEK bytes)
//        - inPublic.type = TPM2_ALG_KEYEDHASH, scheme = TPM2_ALG_NULL
//        - Optionally bind to PCR 0+7 (Secure Boot) via creationPCR to
//          detect firmware tampering.
//        - Serialize the TPM2B_PRIVATE + TPM2B_PUBLIC output blobs and
//          prepend the HwKey blob header (magic 0x4C54 "LT", version 0x01).
//
//   5. Unwrap (unseal): Esys_Load() the persisted blobs back under the
//      primary key, then Esys_Unseal() to recover the plaintext DEK.
//      Provide PIN via Esys_TR_SetAuth() before Esys_Unseal().
//
//   6. PIN prompt UX: open a Qt modal QInputDialog (echo mode Password)
//      before calling Esys_TR_SetAuth(). On failure the TPM increments its
//      dictionary-attack counter; after DA lockout call Esys_DictionaryAttackLockReset()
//      with the lockout authorization (or inform the user to wait for the
//      auto-reset interval).
//
//   7. Session HMAC: wrap the Esys_Unseal() call in an HMAC session
//      (Esys_StartAuthSession with TPM2_SE_HMAC) for command integrity and
//      to prevent interposer attacks on the LPC/SPI bus.
//
//   Key algorithm recommendation: AES-256 CFB as the wrapped key type
//   inside the TPM, or a keyedhash (sealed data) for carrying an external
//   AES-256-GCM DEK.

#include "hwkey.h"

#ifdef Q_OS_LINUX

#include <QFile>
#include <QFileInfo>

namespace HwKey {

// Forward declarations for the stub fallback functions defined in hwkey_stub.cpp.
// These are always compiled on every platform.
namespace Stub {
QByteArray wrapKey(const QByteArray& dek, QString* errorOut);
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut);
} // namespace Stub

static constexpr char kTpmDevice[] = "/dev/tpmrm0";

// ---------------------------------------------------------------------------
// probeTPM() — return true iff /dev/tpmrm0 exists and is accessible.
// ---------------------------------------------------------------------------
static bool probeTPM()
{
    // QFileInfo::exists() does a stat(2); does not open the device.
    if (!QFileInfo::exists(QString::fromLatin1(kTpmDevice)))
        return false;
    // Check that we can actually open it for reading; permission failures
    // would cause confusing "TPM available" messages in containers.
    QFile dev(QString::fromLatin1(kTpmDevice));
    if (!dev.open(QIODevice::ReadOnly))
        return false;
    dev.close();
    return true;
}

// ---------------------------------------------------------------------------
// detect() — Linux implementation.
// ---------------------------------------------------------------------------
Capabilities detect()
{
    if (probeTPM()) {
        return Capabilities{
            Backend::LinuxTPM2,
            /*supportsKeyWrap=*/true,
            /*supportsSign=*/false, // signing not scaffolded yet
            /*device_name=*/QLatin1String("TPM 2.0 (/dev/tpmrm0)")
        };
    }
    // No TPM accessible — report None and fall back to stub/password-only.
    return Capabilities{
        Backend::None,
        /*supportsKeyWrap=*/false,
        /*supportsSign=*/false,
        /*device_name=*/QLatin1String("None (no TPM found)")
    };
}

// ---------------------------------------------------------------------------
// wrapKey() — Linux implementation.
//   Scaffolding: delegates to stub until real tpm2-tss calls are in place.
// ---------------------------------------------------------------------------
QByteArray wrapKey(const QByteArray& dek, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with Esys_Create() seal operation.
    // For now: if TPM is present we still use the stub to keep the engine
    // functional. The backend field in detect() already tells callers that
    // LinuxTPM2 was found, so they can display an appropriate UI message.
    return Stub::wrapKey(dek, errorOut);
}

// ---------------------------------------------------------------------------
// unwrapKey() — Linux implementation.
//   Scaffolding: delegates to stub until real tpm2-tss calls are in place.
// ---------------------------------------------------------------------------
QByteArray unwrapKey(const QByteArray& wrappedBlob, QString* errorOut)
{
    // TODO(hwkey-real-impl): replace with Esys_Load() + Esys_Unseal().
    return Stub::unwrapKey(wrappedBlob, errorOut);
}

} // namespace HwKey

#endif // Q_OS_LINUX
