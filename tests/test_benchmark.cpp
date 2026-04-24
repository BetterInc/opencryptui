// Regression test for the benchmark segfault.
//
// Root cause: benchmarkCipher() had three bugs that caused a crash:
//   1. Salt was 16 bytes; libsodium's crypto_pwhash_scryptsalsa208sha256
//      reads exactly SALTBYTES (32) unconditionally — heap overread → segfault.
//   2. IV was hardcoded to 16 bytes for all ciphers.  GCM / ChaCha20-Poly1305
//      require a 12-byte nonce; passing 16 bytes without first calling
//      EVP_CTRL_GCM_SET_IVLEN corrupts the internal GCM GHASH state and
//      causes a segfault inside EVP_EncryptUpdate.
//   3. Argon2 iterations were passed as 10 with m_cost=1<<20 (1 GiB), so
//      each Argon2 key-derivation consumed 1 GiB — OOM on typical CI boxes.
//
// This test calls EncryptionWorker::runBenchmark() directly (same thread,
// no QThread) with a tiny payload via a one-shot QCoreApplication event
// loop flush.  It asserts:
//   - No crash.
//   - At least one benchmarkResultReady signal is emitted (results > 0).
//   - Every emitted result has sensible values (mbps > 0, ms > 0).
#include "encryptionworker.h"
#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QString>

static int check(bool ok, const char *label)
{
    if (!ok) { qCritical() << "FAIL:" << label; return 1; }
    qInfo()  << "OK  :" << label;
    return 0;
}

struct BenchResult {
    int    iterations;
    double mbps;
    double ms;
    QString cipher;
    QString kdf;
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    int failures = 0;

    // --- collect results via signal ------------------------------------------
    QList<BenchResult> results;

    EncryptionWorker worker;

    // Connect signal to a lambda accumulator.  runBenchmark() is called in
    // the same thread so slots fire synchronously during the call.
    QObject::connect(&worker,
                     &EncryptionWorker::benchmarkResultReady,
                     [&](int iter, double mbps, double ms,
                         const QString &cipher, const QString &kdf) {
                         results.append({iter, mbps, ms, cipher, kdf});
                     });

    // Use only two cheap ciphers (one GCM, one CBC) and PBKDF2 only so the
    // test finishes in well under 2 seconds even on a slow CI node.
    const QStringList algorithms = {"AES-256-GCM", "AES-256-CBC"};
    const QStringList kdfs       = {"PBKDF2"};

    worker.setBenchmarkParameters(algorithms, kdfs);

    // --- run benchmark — must not crash -------------------------------------
    QElapsedTimer wallClock;
    wallClock.start();

    worker.runBenchmark();  // synchronous call in this thread

    qint64 wallMs = wallClock.elapsed();
    qInfo() << "runBenchmark() returned in" << wallMs << "ms";

    // --- assertions ----------------------------------------------------------
    failures += check(!results.isEmpty(), "at least one result emitted");

    for (const BenchResult &r : results) {
        const QByteArray label =
            (r.cipher + " / " + r.kdf).toUtf8();

        failures += check(r.mbps > 0.0,
                          (label + " mbps > 0").constData());
        failures += check(r.ms > 0.0,
                          (label + " ms > 0").constData());
        failures += check(r.iterations > 0,
                          (label + " iterations > 0").constData());
    }

    // Sanity: AES-256-GCM with HW acceleration should appear (the benchmark
    // runs with useHardwareAcceleration=true first, then false for supported
    // ciphers).  We expect at least 2 results (one per cipher minimum).
    failures += check(results.size() >= 2, "at least 2 results (one per cipher)");

    if (failures) {
        qCritical() << "FAILURES:" << failures;
        return 1;
    }
    qInfo() << "ALL BENCHMARK CASES OK —" << results.size() << "results in" << wallMs << "ms";
    return 0;
}
