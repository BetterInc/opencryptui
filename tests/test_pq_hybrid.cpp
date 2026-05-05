// test_pq_hybrid.cpp — Integration tests for PqHybrid key-wrapping.
//
// Test plan:
//   1. If PqHybrid::isAvailable() returns false, print a skip message and
//      exit 0 — the project builds without liboqs by design.
//   2. generateKeyPair() returns correctly-sized fields.
//   3. Round-trip: wrap a 32-byte random DEK, unwrap it, verify byte equality.
//   4. Tampering with classicalBlob causes unwrap to fail gracefully.
//   5. Tampering with pqBlob causes unwrap to fail gracefully.
//   6. Wrong classicalSecret causes unwrap to fail gracefully.
//   7. Wrong pqSecret causes unwrap to fail gracefully.
//
// No UI, no filesystem I/O — pure unit test of the PqHybrid primitives.

#include "pq_hybrid.h"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QDebug>

// ---------------------------------------------------------------------------
// Minimal test harness (mirrors the style used in test_engine_kdf.cpp)
// ---------------------------------------------------------------------------
static int g_failures = 0;

static void check(bool condition, const char* label)
{
    if (condition) {
        qInfo() << "OK  :" << label;
    } else {
        qCritical() << "FAIL:" << label;
        ++g_failures;
    }
}

// ---------------------------------------------------------------------------
// Helper: generate a predictable but non-trivial 32-byte test DEK.
// ---------------------------------------------------------------------------
static QByteArray makeDek()
{
    QByteArray dek(32, '\0');
    for (int i = 0; i < 32; ++i)
        dek[i] = static_cast<char>(i * 7 + 3); // deterministic, non-zero pattern
    return dek;
}

// ---------------------------------------------------------------------------
// Helper: flip one bit in a QByteArray copy.
// ---------------------------------------------------------------------------
static QByteArray tamper(const QByteArray& src, int byteOffset = 0)
{
    QByteArray copy = src;
    copy[byteOffset] = static_cast<char>(copy[byteOffset] ^ 0xFF);
    return copy;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void testKeyPairSizes()
{
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();

    check(kp.classicalPublic.size() == 32,
          "KeyPair: classicalPublic is 32 bytes");
    check(kp.classicalSecret.size() == 32,
          "KeyPair: classicalSecret is 32 bytes");
    check(kp.pqPublic.size() == 1568,
          "KeyPair: pqPublic is 1568 bytes (ML-KEM-1024 encapsulation key)");
    check(kp.pqSecret.size() == 3168,
          "KeyPair: pqSecret is 3168 bytes (ML-KEM-1024 decapsulation key)");

    // Keys should not be all-zero (trivial sanity check)
    check(kp.classicalPublic != QByteArray(32, '\0'),
          "KeyPair: classicalPublic is not all-zero");
    check(kp.pqPublic != QByteArray(1568, '\0'),
          "KeyPair: pqPublic is not all-zero");
}

static void testRoundTrip()
{
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();

    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    check(!blob.classicalBlob.isEmpty(), "wrap: classicalBlob is non-empty");
    check(!blob.pqBlob.isEmpty(),        "wrap: pqBlob is non-empty");
    check(blob.fingerprint.size() == 32, "wrap: fingerprint is 32 bytes");

    QString err;
    QByteArray recovered = PqHybrid::unwrap(blob, kp.classicalSecret, kp.pqSecret, &err);

    check(!recovered.isEmpty(),  "unwrap: returns non-empty DEK");
    check(err.isEmpty(),         "unwrap: no error message on success");
    check(recovered == dek,      "unwrap: recovered DEK matches original");
}

static void testTwoDistinctRoundTrips()
{
    // Wrap the same DEK twice; blobs should differ (fresh randomness each time).
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();

    PqHybrid::HybridWrappedKey blob1 = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);
    PqHybrid::HybridWrappedKey blob2 = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    check(blob1.classicalBlob != blob2.classicalBlob,
          "wrap: two wraps of same DEK produce distinct classicalBlobs (ephemeral randomness)");
    check(blob1.pqBlob != blob2.pqBlob,
          "wrap: two wraps of same DEK produce distinct pqBlobs (encaps randomness)");

    // Both must still unwrap to the correct DEK.
    QString err1, err2;
    QByteArray r1 = PqHybrid::unwrap(blob1, kp.classicalSecret, kp.pqSecret, &err1);
    QByteArray r2 = PqHybrid::unwrap(blob2, kp.classicalSecret, kp.pqSecret, &err2);
    check(r1 == dek, "unwrap blob1: correct DEK");
    check(r2 == dek, "unwrap blob2: correct DEK");
}

static void testTamperClassicalBlob()
{
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();
    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    // Flip the last byte of the wrapped DEK portion (past the ephemeral pubkey + salt)
    PqHybrid::HybridWrappedKey tampered = blob;
    tampered.classicalBlob = tamper(blob.classicalBlob, blob.classicalBlob.size() - 1);

    QString err;
    QByteArray recovered = PqHybrid::unwrap(tampered, kp.classicalSecret, kp.pqSecret, &err);

    check(recovered.isEmpty(), "tamper classicalBlob: unwrap returns empty DEK");
    check(!err.isEmpty(),      "tamper classicalBlob: error message is populated");
}

static void testTamperPqBlob()
{
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();
    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    // Flip the last byte of pqBlob (inside the wrapped-DEK portion).
    PqHybrid::HybridWrappedKey tampered = blob;
    tampered.pqBlob = tamper(blob.pqBlob, blob.pqBlob.size() - 1);

    QString err;
    QByteArray recovered = PqHybrid::unwrap(tampered, kp.classicalSecret, kp.pqSecret, &err);

    check(recovered.isEmpty(), "tamper pqBlob: unwrap returns empty DEK");
    check(!err.isEmpty(),      "tamper pqBlob: error message is populated");
}

static void testWrongClassicalSecret()
{
    PqHybrid::KeyPair kp      = PqHybrid::generateKeyPair();
    PqHybrid::KeyPair wrongKp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();
    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    QString err;
    // Use wrong classical secret but correct pq secret — should fail.
    QByteArray recovered = PqHybrid::unwrap(blob,
                                             wrongKp.classicalSecret,
                                             kp.pqSecret,
                                             &err);

    check(recovered.isEmpty(), "wrong classicalSecret: unwrap returns empty DEK");
    // Note: error may or may not be populated depending on where the failure
    // manifests (AES-GCM auth failure or DEK mismatch) — we only check emptiness.
}

static void testWrongPqSecret()
{
    PqHybrid::KeyPair kp      = PqHybrid::generateKeyPair();
    PqHybrid::KeyPair wrongKp = PqHybrid::generateKeyPair();
    QByteArray dek = makeDek();
    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(dek, kp.classicalPublic, kp.pqPublic);

    QString err;
    // Use correct classical secret but wrong pq secret — should fail.
    QByteArray recovered = PqHybrid::unwrap(blob,
                                             kp.classicalSecret,
                                             wrongKp.pqSecret,
                                             &err);

    check(recovered.isEmpty(), "wrong pqSecret: unwrap returns empty DEK");
}

static void testWrapRejectsBadDekLength()
{
    PqHybrid::KeyPair kp = PqHybrid::generateKeyPair();

    // DEK that is not 32 bytes should be rejected immediately.
    QByteArray badDek(16, '\x42');
    PqHybrid::HybridWrappedKey blob = PqHybrid::wrap(badDek, kp.classicalPublic, kp.pqPublic);

    check(blob.classicalBlob.isEmpty() && blob.pqBlob.isEmpty(),
          "wrap: rejects DEK with wrong length");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    if (!PqHybrid::isAvailable()) {
        qInfo() << "SKIP: liboqs not available in this build.";
        qInfo() << "      See docs/PQ_README.md for installation instructions.";
        qInfo() << "      Build with OCUI_HAVE_LIBOQS defined to run these tests.";
        return 0;
    }

    qInfo() << "=== PqHybrid test suite ===";

    testKeyPairSizes();
    testRoundTrip();
    testTwoDistinctRoundTrips();
    testTamperClassicalBlob();
    testTamperPqBlob();
    testWrongClassicalSecret();
    testWrongPqSecret();
    testWrapRejectsBadDekLength();

    qInfo() << "===========================";
    if (g_failures == 0) {
        qInfo() << "All tests passed.";
        return 0;
    } else {
        qCritical() << g_failures << "test(s) FAILED.";
        return 1;
    }
}
