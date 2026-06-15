// Easy/Advanced mode UI test: the mode toggle flips the home vs the full tabs,
// and an Easy-mode encrypt/decrypt round-trips a file by driving the same
// engine path the Advanced tabs use (just with secure defaults).
#include "test_ui_common.h"
#include <QAction>
#include <QTabWidget>

void TestOpenCryptUI::testEasyModeToggleAndEncrypt()
{
    QWidget*  easyHome = mainWindow->findChild<QWidget*>("easyHome");
    QTabWidget* tabs   = mainWindow->findChild<QTabWidget*>("tabWidget");
    QAction*  advAct   = mainWindow->findChild<QAction*>("advancedModeAction");
    QVERIFY(easyHome);
    QVERIFY(tabs);
    QVERIFY(advAct);

    // Default is Easy: home visible, tabs hidden.
    QVERIFY(easyHome->isVisible());
    QVERIFY(!tabs->isVisible());

    // Toggle to Advanced: tabs appear, home hides.
    advAct->setChecked(true);
    QApplication::processEvents();
    QVERIFY(tabs->isVisible());
    QVERIFY(!easyHome->isVisible());

    // Back to Easy.
    advAct->setChecked(false);
    QApplication::processEvents();
    QVERIFY(easyHome->isVisible());
    QVERIFY(!tabs->isVisible());

    // Easy-mode encrypt/decrypt of a file (kind defaults to "File").
    QLineEdit* path = mainWindow->findChild<QLineEdit*>("easyPath");
    QLineEdit* pw   = mainWindow->findChild<QLineEdit*>("easyPassword");
    QLineEdit* conf = mainWindow->findChild<QLineEdit*>("easyConfirm");
    QPushButton* enc = mainWindow->findChild<QPushButton*>("easyEncryptButton");
    QPushButton* dec = mainWindow->findChild<QPushButton*>("easyDecryptButton");
    QVERIFY(path && pw && conf && enc && dec);

    const QString testFile = QDir::currentPath() + "/easy_test.txt";
    const QString encFile  = testFile + ".enc";
    QFile::remove(testFile); QFile::remove(encFile);
    { QFile f(testFile); QVERIFY(f.open(QIODevice::WriteOnly)); f.write("easy-mode-roundtrip"); }

    path->setText(testFile);
    pw->setText("easy-mode-password");
    conf->setText("easy-mode-password");
    QTest::qWait(WAIT_TIME_SHORT);
    QTest::mouseClick(enc, Qt::LeftButton);
    waitForAndCloseMessageBoxes(WAIT_TIME_LONG, "Success");
    QVERIFY2(waitForFileToExist(encFile), "Easy-mode encrypt did not produce a .enc file");

    // Decrypt it back via the Easy home.
    QFile::remove(testFile);
    path->setText(encFile);
    pw->setText("easy-mode-password");
    QTest::qWait(WAIT_TIME_SHORT);
    QTest::mouseClick(dec, Qt::LeftButton);
    waitForAndCloseMessageBoxes(WAIT_TIME_LONG, "Success");
    QVERIFY2(waitForFileToExist(testFile), "Easy-mode decrypt did not restore the file");

    QFile out(testFile);
    QVERIFY(out.open(QIODevice::ReadOnly));
    QCOMPARE(out.readAll(), QByteArray("easy-mode-roundtrip"));
    out.close();

    QFile::remove(testFile); QFile::remove(encFile);
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Easy-mode toggle + encrypt/decrypt test passed");
}
