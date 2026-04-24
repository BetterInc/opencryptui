// UI-driven tamper-detection test. Engine-level coverage is in
// tests/test_engine_tamper.cpp; this drives the same flow via widgets.
#include "test_ui_common.h"

void TestOpenCryptUI::testTamperDetection()
{
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Starting tamper detection test");

    // Create a test file with known content
    QString testContent = "This is a tamper detection test file";
    QString testFilePath = createTestFile(testContent);
    QVERIFY(!testFilePath.isEmpty());

    // Set up UI elements for encryption
    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit *>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow->findChild<QLineEdit *>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow->findChild<QPushButton *>("fileEncryptButton");
    QComboBox *algorithmComboBox = mainWindow->findChild<QComboBox *>("fileAlgorithmComboBox");
    QComboBox *kdfComboBox = mainWindow->findChild<QComboBox *>("kdfComboBox");
    QSpinBox *iterationsSpinBox = mainWindow->findChild<QSpinBox *>("iterationsSpinBox");
    QCheckBox *hmacCheckBox = mainWindow->findChild<QCheckBox *>("hmacCheckBox");

    // Set test parameters
    filePathInput->setText(testFilePath);
    passwordInput->setText("tampertest123");
    algorithmComboBox->setCurrentText("AES-256-GCM"); // Use GCM for authenticated encryption
    // Use Argon2 (PBKDF2 now has a 600k-iteration floor — Fix #1 / SECURITY.md).
    kdfComboBox->setCurrentText("Argon2");
    iterationsSpinBox->setValue(1);
    hmacCheckBox->setChecked(true); // Enable HMAC/integrity checking

    // Encrypt the file
    QTest::mouseClick(encryptButton, Qt::LeftButton);
    // QTest::qWait(WAIT_TIME_LONG); // Remove explicit wait
    // QApplication::processEvents(); // Remove explicit process events

    // Check that encrypted file exists (.enc extension)
    QString encryptedFilePath = testFilePath + ".enc";
    QVERIFY(waitForFileToExist(encryptedFilePath));
    waitForAndCloseMessageBoxes(WAIT_TIME_LONG, "Success"); // Add this call

    // Tamper with the encrypted file
    QFile encryptedFile(encryptedFilePath);
    QVERIFY(encryptedFile.open(QIODevice::ReadWrite));
    
    // Get the file size
    qint64 fileSize = encryptedFile.size();
    QVERIFY(fileSize > 100); // File should be large enough to tamper with

    // Seek to the middle portion of the file (avoiding header and signature)
    encryptedFile.seek(fileSize / 2);
    
    // Read 8 bytes
    QByteArray originalBytes = encryptedFile.read(8);
    QCOMPARE(originalBytes.size(), 8);
    
    // Tamper with the bytes (invert them)
    QByteArray tamperedBytes(8, 0);
    for (int i = 0; i < 8; i++) {
        tamperedBytes[i] = ~originalBytes[i]; // Invert the bits
    }
    
    // Write back the tampered bytes
    encryptedFile.seek(fileSize / 2);
    encryptedFile.write(tamperedBytes);
    encryptedFile.close();

    // Set up UI for decryption
    QPushButton *decryptButton = mainWindow->findChild<QPushButton *>("fileDecryptButton");
    filePathInput->setText(encryptedFilePath);
    
    // Attempt to decrypt the tampered file
    QTest::mouseClick(decryptButton, Qt::LeftButton);
    // QTest::qWait(WAIT_TIME_LONG); // Remove explicit wait
    // QApplication::processEvents(); // Remove explicit process events

    // Decrypt should fail due to tampering - verify decrypted file doesn't exist
    QString decryptedFilePath = encryptedFilePath.left(encryptedFilePath.lastIndexOf(".enc"));
    // Expect an error message box here
    waitForAndCloseMessageBoxes(WAIT_TIME_LONG, "Error"); // Add this call
    QVERIFY(!QFile::exists(decryptedFilePath));

    // Clean up
    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
    QFile::remove(decryptedFilePath);
    
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Tamper detection test completed");
}
