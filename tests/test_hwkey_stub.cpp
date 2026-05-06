// test_hwkey_stub.cpp — Unit tests for the HwKey stub wrap/unwrap path.
//
// Tests:
//   1.  detect() returns a valid backend enum value.
//   2.  detect() sets a non-empty device_name.
//   3.  detect().supportsKeyWrap == false (no real HW impl on any CI box).
//   4.  wrappingBackend() == Backend::Stub regardless of detect() result.
//   5.  detect().effectiveBackend == Backend::Stub.
//   6.  Round-trip: wrap a 32-byte DEK, unwrap, bytes are byte-identical.
//   7.  Tamper: flipped byte in ciphertext region → unwrap fails.
//   8.  Tamper: flipped last byte (tag) → unwrap fails.
//   9.  Tamper: truncated blob → unwrap fails.
//   10. Empty DEK: wrapKey returns empty + sets errorOut cleanly.
//   11. No TPM2 ASN.1 magic (0x80 0x01) or PKCS#11 marker in first 16 bytes.
//   12. Two wraps of different DEKs produce blobs that differ in nonce region.
//   13. Two wraps of the SAME DEK produce different blobs (fresh nonce per call).
//
// Pattern: QCoreApplication + fprintf-style pass/fail, same as other
// test_engine_*.cpp targets. The process exits with 0 on all pass, 1 on
// any failure. No UI, no filesystem other than the stub key at AppDataLocation.

#include "hwkey.h"

#include <QCoreApplication>
#include <QByteArray>
#include <cstdio>

// ---------------------------------------------------------------------------
// check() — print result and return 1 on failure (to accumulate into failures).
// ---------------------------------------------------------------------------
static int check(bool condition, const char* label)
{
    if (condition) {
        fprintf(stdout, "OK  : %s\n", label);
        return 0;
    }
    fprintf(stderr, "FAIL: %s\n", label);
    return 1;
}

// ---------------------------------------------------------------------------
// make32ByteDEK() — deterministic 32-byte test key (not crypto-quality).
// ---------------------------------------------------------------------------
static QByteArray make32ByteDEK()
{
    QByteArray dek(32, 0);
    for (int i = 0; i < 32; ++i)
        dek[i] = static_cast<char>(i ^ 0xA5);
    return dek;
}

// ---------------------------------------------------------------------------
// makeAltDEK() — second distinct 32-byte test key.
// ---------------------------------------------------------------------------
static QByteArray makeAltDEK()
{
    QByteArray dek(32, 0);
    for (int i = 0; i < 32; ++i)
        dek[i] = static_cast<char>(i ^ 0x5A);
    return dek;
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------
int main(int argc, char** argv)
{
    // QCoreApplication is required for QStandardPaths (used by the stub to
    // locate / create the per-user wrapping key file).
    QCoreApplication app(argc, argv);
    app.setApplicationName("opencryptui");
    app.setOrganizationName("opencryptui");

    int failures = 0;

    // -----------------------------------------------------------------------
    // Tests 1–2: detect() returns a valid Capabilities struct.
    //   On a CI Linux box without a TPM, Backend::None is the expected result.
    //   On a dev machine with /dev/tpmrm0, Backend::LinuxTPM2 is expected.
    //   Either way the call must not crash and device_name must be non-empty.
    // -----------------------------------------------------------------------
    {
        HwKey::Capabilities caps = HwKey::detect();

        const bool validBackend =
            caps.backend == HwKey::Backend::None          ||
            caps.backend == HwKey::Backend::Stub          ||
            caps.backend == HwKey::Backend::LinuxTPM2     ||
            caps.backend == HwKey::Backend::MacSecureEnclave ||
            caps.backend == HwKey::Backend::WindowsTPM    ||
            caps.backend == HwKey::Backend::PKCS11;

        failures += check(validBackend,
                          "detect() returns a valid Backend enum value");
        failures += check(!caps.device_name.isEmpty(),
                          "detect() sets a non-empty device_name");

        // Log what was detected so CI logs are informative.
        fprintf(stdout, "INFO: detected backend=%d effectiveBackend=%d "
                        "device='%s' wrap=%s sign=%s\n",
                static_cast<int>(caps.backend),
                static_cast<int>(caps.effectiveBackend),
                caps.device_name.toUtf8().constData(),
                caps.supportsKeyWrap ? "yes" : "no",
                caps.supportsSign    ? "yes" : "no");
    }

    // -----------------------------------------------------------------------
    // Test 3: supportsKeyWrap == false on any CI box or machine without a
    //   real hardware implementation wired in. Since all platform TUs still
    //   route to the stub, this must always be false.
    // -----------------------------------------------------------------------
    {
        HwKey::Capabilities caps = HwKey::detect();
        failures += check(!caps.supportsKeyWrap,
                          "detect().supportsKeyWrap == false (no real HW impl)");
    }

    // -----------------------------------------------------------------------
    // Test 4: wrappingBackend() always returns Backend::Stub.
    //   This is the key honesty guarantee — callers can query what wrapKey()
    //   will ACTUALLY use, not just what hardware is present.
    // -----------------------------------------------------------------------
    {
        failures += check(HwKey::wrappingBackend() == HwKey::Backend::Stub,
                          "wrappingBackend() == Backend::Stub (software fallback)");
    }

    // -----------------------------------------------------------------------
    // Test 5: detect().effectiveBackend == Backend::Stub.
    //   The Capabilities struct carries the same information in-band so that
    //   callers who already have a Capabilities don't need a second call.
    // -----------------------------------------------------------------------
    {
        HwKey::Capabilities caps = HwKey::detect();
        failures += check(caps.effectiveBackend == HwKey::Backend::Stub,
                          "detect().effectiveBackend == Backend::Stub");
    }

    // -----------------------------------------------------------------------
    // Test 6: Round-trip — wrap then unwrap yields the original DEK.
    // -----------------------------------------------------------------------
    {
        const QByteArray originalDEK = make32ByteDEK();
        QString wrapError;
        QByteArray blob = HwKey::wrapKey(originalDEK, &wrapError);

        failures += check(!blob.isEmpty(),
                          "round-trip: wrapKey returns non-empty blob");
        if (!wrapError.isEmpty())
            fprintf(stderr, "  wrapKey error: %s\n", wrapError.toUtf8().constData());

        if (!blob.isEmpty()) {
            QString unwrapError;
            QByteArray recovered = HwKey::unwrapKey(blob, &unwrapError);

            failures += check(!recovered.isEmpty(),
                              "round-trip: unwrapKey returns non-empty DEK");
            failures += check(recovered == originalDEK,
                              "round-trip: unwrapped DEK is byte-identical to original");

            if (!unwrapError.isEmpty())
                fprintf(stderr, "  unwrapKey error: %s\n",
                        unwrapError.toUtf8().constData());
            if (!recovered.isEmpty() && recovered != originalDEK) {
                fprintf(stderr, "  expected: %s\n",
                        originalDEK.toHex().constData());
                fprintf(stderr, "  got:      %s\n",
                        recovered.toHex().constData());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Tests 7–9: Tamper detection — any modification must cause unwrap failure.
    // -----------------------------------------------------------------------
    {
        const QByteArray originalDEK = make32ByteDEK();
        QString wrapError;
        QByteArray blob = HwKey::wrapKey(originalDEK, &wrapError);

        failures += check(!blob.isEmpty(),
                          "tamper: wrapKey produces a blob to tamper with");

        if (!blob.isEmpty()) {
            // --- Test 7: Flip a byte in the ciphertext region -----------------
            // The outer blob is: nonce(12) + ciphertext + tag(16).
            // Offset 15 lands in the ciphertext (after the 12-byte nonce).
            {
                QByteArray tampered = blob;
                const int offset = qMin(15, tampered.size() - 1);
                tampered[offset] = static_cast<char>(
                    static_cast<unsigned char>(tampered[offset]) ^ 0xFF);

                QString unwrapError;
                QByteArray result = HwKey::unwrapKey(tampered, &unwrapError);

                failures += check(result.isEmpty(),
                                  "tamper: flipped byte in ciphertext region → unwrap fails");
                failures += check(!unwrapError.isEmpty(),
                                  "tamper: errorOut is set when unwrap rejects tampered blob");
            }

            // --- Test 8: Flip the last byte (inside the GCM tag) --------------
            {
                QByteArray tampered = blob;
                tampered[tampered.size() - 1] = static_cast<char>(
                    static_cast<unsigned char>(tampered[tampered.size() - 1]) ^ 0x01);

                QString unwrapError;
                QByteArray result = HwKey::unwrapKey(tampered, &unwrapError);

                failures += check(result.isEmpty(),
                                  "tamper: flipped last byte (outer GCM tag) → unwrap fails");
                failures += check(!unwrapError.isEmpty(),
                                  "tamper: errorOut is set for tag corruption");
            }

            // --- Test 9: Truncate the blob by one byte ------------------------
            {
                QByteArray truncated = blob.left(blob.size() - 1);
                QString unwrapError;
                QByteArray result = HwKey::unwrapKey(truncated, &unwrapError);

                failures += check(result.isEmpty(),
                                  "tamper: truncated blob → unwrap fails");
                failures += check(!unwrapError.isEmpty(),
                                  "tamper: errorOut is set for truncated blob");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Empty DEK — wrapKey must fail cleanly without crashing.
    // -----------------------------------------------------------------------
    {
        const QByteArray emptyDEK;
        QString errorOut;
        QByteArray blob = HwKey::wrapKey(emptyDEK, &errorOut);

        failures += check(blob.isEmpty(),
                          "empty DEK: wrapKey returns empty blob");
        failures += check(!errorOut.isEmpty(),
                          "empty DEK: errorOut is set");
    }

    // -----------------------------------------------------------------------
    // Test 11: Forensic structure check — no TPM2 ASN.1 prefix or PKCS#11
    //   marker in the first 16 bytes of the wrapped blob.
    //
    //   TPM2_PUBLIC structures start with 0x00 0x58 (size) or use the ASN.1
    //   SEQUENCE tag 0x30, and TPM2B_PRIVATE uses size-prefixed blobs. A
    //   common TPM2 magic in PKCS#11 is the CK_OBJECT header 0x43 0x4B.
    //   ASN.1 SEQUENCE (DER) always starts with 0x30; PKCS#11 CKO_SECRET_KEY
    //   blobs often contain 0x11 (CKO) or 0x06 (OID tag).
    //
    //   The wrappedBlob_v2 format starts with 12 uniformly random nonce bytes,
    //   so no fixed magic is present at any known offset.
    //
    //   We check that the first byte is NOT the DER SEQUENCE tag (0x30) and
    //   that the two-byte sequence 0x80 0x01 (a common TPM2 size prefix in
    //   ASN.1 BER long-form) does not appear in the first 16 bytes.
    // -----------------------------------------------------------------------
    {
        const QByteArray dek = make32ByteDEK();
        QString wrapError;
        QByteArray blob = HwKey::wrapKey(dek, &wrapError);

        if (!blob.isEmpty() && blob.size() >= 16) {
            const unsigned char* b =
                reinterpret_cast<const unsigned char*>(blob.constData());

            // Log the first 16 bytes for CI visibility.
            fprintf(stdout, "INFO: first 16 bytes of wrapped blob: ");
            for (int i = 0; i < 16; ++i)
                fprintf(stdout, "%02x ", b[i]);
            fprintf(stdout, "\n");

            // The outer format has no fixed-position magic header — first byte
            // is nonce byte 0, which is uniformly random. We cannot guarantee
            // it will never happen to equal 0x30 in any single run, but we CAN
            // verify the two-byte marker 0x80 0x01 is absent from the first 16
            // bytes (the outer nonce is 12 bytes; no structured header follows).
            bool has_0x8001 = false;
            for (int i = 0; i < 15; ++i) {
                if (b[i] == 0x80 && b[i+1] == 0x01) {
                    has_0x8001 = true;
                    break;
                }
            }
            failures += check(!has_0x8001,
                              "forensic: no TPM2 ASN.1 0x80 0x01 marker in first 16 bytes");

            // The PKCS#11 CKO_SECRET_KEY marker byte sequence 0x43 0x4B
            // ("CK") should not appear as a fixed header in the nonce region.
            bool has_ck = false;
            for (int i = 0; i < 15; ++i) {
                if (b[i] == 0x43 && b[i+1] == 0x4B) {
                    has_ck = true;
                    break;
                }
            }
            failures += check(!has_ck,
                              "forensic: no PKCS#11 'CK' marker in first 16 bytes");
        } else {
            failures += check(false,
                              "forensic: blob must be non-empty and at least 16 bytes");
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: Two wraps of DIFFERENT DEKs produce blobs that differ in the
    //   nonce region (first 12 bytes). Since nonces are random, two successive
    //   wraps should almost certainly differ — the probability of collision is
    //   2^-96. We test both DEK-A vs DEK-B and two wraps of DEK-A.
    // -----------------------------------------------------------------------
    {
        const QByteArray dekA = make32ByteDEK();
        const QByteArray dekB = makeAltDEK();

        QString errA, errB;
        QByteArray blobA = HwKey::wrapKey(dekA, &errA);
        QByteArray blobB = HwKey::wrapKey(dekB, &errB);

        if (!blobA.isEmpty() && !blobB.isEmpty() &&
            blobA.size() >= 12 && blobB.size() >= 12)
        {
            // Compare the nonce region (first 12 bytes).
            const bool nonceDiffers = (blobA.left(12) != blobB.left(12));
            failures += check(nonceDiffers,
                              "fresh nonce: wrapping two different DEKs produces different nonces");
        } else {
            failures += check(false,
                              "fresh nonce: wrapKey must succeed for both DEKs");
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Two wraps of the SAME DEK produce blobs that differ in the
    //   nonce region (fresh nonce per call, not a deterministic KDF).
    // -----------------------------------------------------------------------
    {
        const QByteArray dek = make32ByteDEK();

        QString err1, err2;
        QByteArray blob1 = HwKey::wrapKey(dek, &err1);
        QByteArray blob2 = HwKey::wrapKey(dek, &err2);

        if (!blob1.isEmpty() && !blob2.isEmpty() &&
            blob1.size() >= 12 && blob2.size() >= 12)
        {
            const bool nonceDiffers = (blob1.left(12) != blob2.left(12));
            failures += check(nonceDiffers,
                              "fresh nonce: wrapping same DEK twice gives different nonces");
        } else {
            failures += check(false,
                              "fresh nonce: wrapKey must succeed for same DEK wrapped twice");
        }
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    if (failures == 0) {
        fprintf(stdout, "ALL HWKEY STUB TESTS OK\n");
        return 0;
    }
    fprintf(stderr, "FAILURES: %d\n", failures);
    return 1;
}
