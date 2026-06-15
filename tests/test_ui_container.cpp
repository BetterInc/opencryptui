// UI-level test for the deniable-container GUI core (MainWindow::
// createContainerFromFiles / openContainerToFile). Drives the same code the
// File-menu dialogs call, but with explicit paths so it runs headlessly
// without native file dialogs. Covers: outer+hidden create with a live
// progress callback, outer-password extraction yields the decoy, hidden-
// password extraction yields the real secret, and a wrong password is rejected.
#include "test_ui_common.h"
#include <QTemporaryDir>

void TestOpenCryptUI::testContainerCreateOpen()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    const QString outerFile = dir.filePath("decoy.bin");
    const QString hiddenFile = dir.filePath("secret.bin");
    const QString container = dir.filePath("vault.ocui");
    const QByteArray outerContent  = QByteArray("DECOY-tax-returns-2024").repeated(500);
    const QByteArray hiddenContent = QByteArray("REAL-SECRET-exploit-notes").repeated(300);

    { QFile f(outerFile);  QVERIFY(f.open(QIODevice::WriteOnly)); f.write(outerContent); }
    { QFile f(hiddenFile); QVERIFY(f.open(QIODevice::WriteOnly)); f.write(hiddenContent); }

    const QString outerPw = "outer-decoy-pw";
    const QString hiddenPw = "hidden-real-pw";

    // --- create with a hidden volume; verify the progress callback fires ----
    int lastPct = -1; bool monotonic = true; bool reached100 = false;
    QString err;
    bool ok = mainWindow->createContainerFromFiles(
        container, /*sizeMiB*/ 8, outerFile, outerPw, hiddenFile, hiddenPw,
        "Argon2", 3, &err,
        [&](int p){ if (p < lastPct) monotonic = false; lastPct = p; if (p == 100) reached100 = true; });
    QVERIFY2(ok, err.toUtf8().constData());
    QVERIFY(monotonic);
    QVERIFY(reached100);
    QVERIFY(QFile::exists(container));

    // --- outer password extracts the decoy ----------------------------------
    const QString outOuter = dir.filePath("out_outer.bin");
    QString e1;
    int k1 = mainWindow->openContainerToFile(container, outerPw, outOuter, "Argon2", 3, &e1);
    QCOMPARE(k1, 1); // 1 = outer
    QFile fo(outOuter); QVERIFY(fo.open(QIODevice::ReadOnly));
    QCOMPARE(fo.readAll(), outerContent);
    fo.close();

    // --- hidden password extracts the real secret ---------------------------
    const QString outHidden = dir.filePath("out_hidden.bin");
    QString e2;
    int k2 = mainWindow->openContainerToFile(container, hiddenPw, outHidden, "Argon2", 3, &e2);
    QCOMPARE(k2, 2); // 2 = hidden
    QFile fh(outHidden); QVERIFY(fh.open(QIODevice::ReadOnly));
    QCOMPARE(fh.readAll(), hiddenContent);
    fh.close();

    // --- wrong password is rejected (no extraction) --------------------------
    const QString outBad = dir.filePath("out_bad.bin");
    QString e3;
    int k3 = mainWindow->openContainerToFile(container, "totally-wrong", outBad, "Argon2", 3, &e3);
    QCOMPARE(k3, 0);

    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Container create/open test passed");
}
