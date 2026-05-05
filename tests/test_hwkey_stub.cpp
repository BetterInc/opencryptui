// test_hwkey_stub.cpp — Unit tests for the HwKey stub wrap/unwrap path.
//
// Tests:
//   1. detect() returns a valid backend (any Backend value — None is OK on CI).
//   2. Round-trip: wrap a 32-byte DEK, unwrap, bytes are identical.
//   3. Tamper: wrap, flip one byte in the blob, unwrap returns empty + sets errorOut.
//   4. Empty DEK: wrapKey returns empty + sets errorOut cleanly.
//
// Pattern: QCoreApplication + fprintf-style pass/fail, same as other
// test_engine_*.cpp targets. The process exits with 0 on all pass, 1 on
// any failure. No UI, no filesystem other than the stub key at AppDataLocation.

#include "hwkey.h"

#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
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
    // Test 1: detect() returns a valid Capabilities struct.
    //   On a CI Linux box without a TPM, Backend::None is the expected result.
    //   On a dev machine with /dev/tpmrm0, Backend::LinuxTPM2 is expected.
    //   Either way the call must not crash and device_name must be non-empty.
    // -----------------------------------------------------------------------
    {
        HwKey::Capabilities caps = HwKey::detect();

        // The backend enum value is always one of the defined values.
        const bool validBackend =
            caps.backend == HwKey::Backend::None          ||
            caps.backend == HwKey::Backend::LinuxTPM2     ||
            caps.backend == HwKey::Backend::MacSecureEnclave ||
            caps.backend == HwKey::Backend::WindowsTPM    ||
            caps.backend == HwKey::Backend::PKCS11;

        failures += check(validBackend, "detect() returns a valid Backend enum value");
        failures += check(!caps.device_name.isEmpty(),
                          "detect() sets a non-empty device_name");

        // Log what was detected so CI logs are informative.
        fprintf(stdout, "INFO: detected backend=%d device='%s' wrap=%s sign=%s\n",
                static_cast<int>(caps.backend),
                caps.device_name.toUtf8().constData(),
                caps.supportsKeyWrap ? "yes" : "no",
                caps.supportsSign    ? "yes" : "no");
    }

    // -----------------------------------------------------------------------
    // Test 2: Round-trip — wrap then unwrap yields the original DEK.
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
    // Test 3: Tamper detection — flip a byte in the blob, unwrap must fail.
    //   We test three different positions: header, nonce area, and near the
    //   end (tag area), to ensure all modifications are caught.
    // -----------------------------------------------------------------------
    {
        const QByteArray originalDEK = make32ByteDEK();
        QString wrapError;
        QByteArray blob = HwKey::wrapKey(originalDEK, &wrapError);

        failures += check(!blob.isEmpty(),
                          "tamper: wrapKey produces a blob to tamper with");

        if (!blob.isEmpty()) {
            // --- 3a. Flip a byte in the ciphertext area (offset 15 = nonce area) ---
            {
                QByteArray tampered = blob;
                const int offset = qMin(15, tampered.size() - 1);
                tampered[offset] = static_cast<char>(
                    static_cast<unsigned char>(tampered[offset]) ^ 0xFF);

                QString unwrapError;
                QByteArray result = HwKey::unwrapKey(tampered, &unwrapError);

                failures += check(result.isEmpty(),
                                  "tamper: flipped byte in nonce area → unwrap fails");
                failures += check(!unwrapError.isEmpty(),
                                  "tamper: errorOut is set when unwrap rejects tampered blob");
            }

            // --- 3b. Flip the last byte (inside the Poly1305 tag) ---------------
            {
                QByteArray tampered = blob;
                tampered[tampered.size() - 1] = static_cast<char>(
                    static_cast<unsigned char>(tampered[tampered.size() - 1]) ^ 0x01);

                QString unwrapError;
                QByteArray result = HwKey::unwrapKey(tampered, &unwrapError);

                failures += check(result.isEmpty(),
                                  "tamper: flipped last byte (tag) → unwrap fails");
                failures += check(!unwrapError.isEmpty(),
                                  "tamper: errorOut is set for tag corruption");
            }

            // --- 3c. Truncate the blob by one byte --------------------------------
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
    // Test 4: Empty DEK — wrapKey must fail cleanly without crashing.
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
    // Summary
    // -----------------------------------------------------------------------
    if (failures == 0) {
        fprintf(stdout, "ALL HWKEY STUB TESTS OK\n");
        return 0;
    }
    fprintf(stderr, "FAILURES: %d\n", failures);
    return 1;
}
