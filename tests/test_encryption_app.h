#ifndef TEST_ENCRYPTION_APP_H
#define TEST_ENCRYPTION_APP_H

#include <QtTest>
#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QTest>
#include <QThread>
#include <QListWidget>
#include <QTimer>
#include <QElapsedTimer>

#include "mainwindow.h"
#include "logging/secure_logger.h"

// Define platform-specific parameters - longer timeouts and more wait cycles for Windows
#ifdef Q_OS_WIN
#define WAIT_TIME_SHORT 200
#define WAIT_TIME_MEDIUM 500
#define WAIT_TIME_LONG 1200
#define FILE_WAIT_CYCLES 120
#else
#define WAIT_TIME_SHORT 100
#define WAIT_TIME_MEDIUM 300
#define WAIT_TIME_LONG 1000
#define FILE_WAIT_CYCLES 60
#endif

// Forward declarations
class MainWindow;

class TestOpenCryptUI : public QObject
{
    Q_OBJECT

private:
    MainWindow* mainWindow;

private slots:
    void initTestCase();
    void cleanupTestCase();
    
    // Main test slots
    void testEncryptDecrypt();
    void testEncryptDecryptArgon2();
    void testAllCiphersAndKDFs();
    void testEncryptDecryptWithKeyfile();
    void testVirtualDiskEncryption();
    void testHiddenVolumeEncryption();
    void testSecureDiskWiping();
    void testFolderEncryptionDecryption();
    void testTabSwitching();
    void testCryptoProviderSwitching();
    void testTamperDetection();
    void testEntropyQuality();
    void testKeyDerivation();
    
    // Helper methods
    void cleanup();

    // Dialog handling helpers
    void closeMessageBoxes();
    bool waitForAndCloseMessageBoxes(int maxWaitMs, const QString& expectedTitleContains = QString());

private:
    QTimer *messageBoxTimer;
    QString createTestFile(const QString &content);
    QString createKeyfile(const QString &content);
    QString createVirtualDisk(qint64 sizeInBytes);
    bool encryptAndDecrypt(const QString &cipher, const QString &kdf, bool useKeyfile);
    void switchToTab(const QString &tabName);
    bool waitForFileToExist(const QString &filePath, int maxWaitCycles = FILE_WAIT_CYCLES);
    void setComboBoxValueAndClose(QComboBox* comboBox, const QString& value);
    QString generateTempFile(const QString &content = "test data for encryption");
};

#endif // TEST_ENCRYPTION_APP_H