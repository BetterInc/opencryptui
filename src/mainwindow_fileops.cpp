// File encrypt & decrypt buttons + the shared worker dispatch.
// Extracted from mainwindow.cpp so the worker lifecycle (startWorker,
// updateProgress, workerFinished) and the browse-dialog glue live in a
// single place without dragging all the main-window boilerplate along.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "encryptionengine.h"
#include "encryptionworker.h"
#include "logging/secure_logger.h"
#include <QCoreApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QThread>
#include <QLabel>
#include <QProgressBar>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QListWidget>
#include <QStandardPaths>
#include <QSettings>

void MainWindow::on_fileEncryptButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "File Encrypt Button Clicked or Enter pressed");
    startWorker(true);
}

void MainWindow::on_fileDecryptButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "File Decrypt Button Clicked or Enter pressed");
    startWorker(false);
}

void MainWindow::startWorker(bool encrypt)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Start Worker: encrypt=%1").arg(encrypt));
    QString path = ui->filePathLineEdit->text();
    QString password = ui->filePasswordLineEdit->text();
    QString algorithm = ui->fileAlgorithmComboBox->currentText();
    QString kdf = ui->kdfComboBox->currentText();
    int iterations = ui->iterationsSpinBox->value();
    bool useHMAC = ui->hmacCheckBox->isChecked();
    QStringList keyfilePaths = ui->fileKeyfileListWidget->getAllItems();
    QString customHeader = ""; // or any specific header if needed

    if (path.isEmpty() || password.isEmpty())
    {
        QMessageBox::warning(this, "Error", "Please provide path and password.");
        return;
    }

    // Validate that the selected algorithm and KDF are supported by the current provider
    QStringList supportedCiphers = encryptionEngine.supportedCiphers();
    QStringList supportedKDFs = encryptionEngine.supportedKDFs();

    // Cascades use EVP directly (not the provider cipher list), so accept them
    // regardless of the current provider; only validate plain single ciphers.
    const bool isCascade = EncryptionEngine::cascadeIdForAlgorithm(algorithm) != 0;
    if (!isCascade && !supportedCiphers.contains(algorithm))
    {
        QMessageBox::warning(this, "Error",
                             QString("The selected cipher '%1' is not supported by the %2 provider.\n\n"
                                     "Please select from: %3")
                                 .arg(algorithm)
                                 .arg(encryptionEngine.currentProvider())
                                 .arg(supportedCiphers.join(", ")));
        return;
    }

    if (!supportedKDFs.contains(kdf))
    {
        QMessageBox::warning(this, "Error",
                             QString("The selected KDF '%1' is not supported by the %2 provider.\n\n"
                                     "Please select from: %3")
                                 .arg(kdf)
                                 .arg(encryptionEngine.currentProvider())
                                 .arg(supportedKDFs.join(", ")));
        return;
    }

    ui->fileProgressBar->setValue(0);
    ui->fileProgressBar->setVisible(true);
    ui->fileEstimatedTimeLabel->setText("Estimated time: Calculating...");
    ui->fileEstimatedTimeLabel->setVisible(true);

    // Disable all operation buttons while processing
    ui->fileEncryptButton->setEnabled(false);
    ui->fileDecryptButton->setEnabled(false);
    ui->diskEncryptButton->setEnabled(false);
    ui->diskDecryptButton->setEnabled(false);

    // Update status message
    ui->fileInfoLabel->setText(encrypt
        ? QString("Encrypting file: %1").arg(QFileInfo(path).fileName())
        : QString("Decrypting file: %1").arg(QFileInfo(path).fileName()));

    // Setup worker thread
    if (!worker) {
        worker = new EncryptionWorker();
        worker->moveToThread(&workerThread);
        
        if (!m_signalsConnected) {
            connectSignalsAndSlots();
        }
    }

    // Set parameters and start work. After this call the worker holds the
    // password in an mlocked SecureString - we drop the local QString and
    // clear the QLineEdit so Qt's internal buffer for the visible field is
    // also zeroed. The local QString and the QLineEdit's internal QString
    // are still implicit-shared copies we can't fully reach, but clearing
    // is the strongest signal we can send Qt to release its grip on those
    // bytes ASAP.
    worker->setParameters(path, password, algorithm, kdf, iterations, useHMAC, encrypt, true, customHeader, keyfilePaths);
    password.fill(QChar('\0'));
    password.clear();
    ui->filePasswordLineEdit->clear();
    emit worker->process();
}

void MainWindow::updateProgress(int value)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Update Progress: value=%1").arg(value));
    ui->fileProgressBar->setValue(value);
    ui->diskProgressBar->setValue(value);
}

void MainWindow::workerFinished(const QString &result, bool success, bool isFile)
{
    // Re-enable all operation buttons
    ui->fileEncryptButton->setEnabled(true);
    ui->fileDecryptButton->setEnabled(true);
    ui->diskEncryptButton->setEnabled(true);
    ui->diskDecryptButton->setEnabled(true);

    // Hide progress indicators (file and disk share this completion handler).
    Q_UNUSED(isFile);
    ui->fileProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->diskProgressBar->setVisible(false);
    ui->diskEstimatedTimeLabel->setVisible(false);

    if (success)
    {
        QString message = "Operation completed successfully!";
        if (result.contains("Output:")) {
            message += "\n\n" + result;
        }
        QMessageBox::information(this, "Success", message);

        // Update the info label with the result path.
        if (result.contains("Output:")) {
            QRegularExpression re("Output: (.+)");
            QRegularExpressionMatch match = re.match(result);
            ui->fileInfoLabel->setText(match.hasMatch()
                ? QString("Output: %1").arg(match.captured(1))
                : "Operation successful");
        } else {
            ui->fileInfoLabel->setText("Operation successful");
        }
    }
    else
    {
        QMessageBox::warning(this, "Error", result);
        ui->fileInfoLabel->setText(QString("Error: %1").arg(result.left(80) + (result.length() > 80 ? "..." : "")));
    }
}

void MainWindow::showEstimatedTime(const QString &timeStr)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Show Estimated Time: %1").arg(timeStr));

    ui->fileEstimatedTimeLabel->setText(timeStr);
    ui->diskEstimatedTimeLabel->setText(timeStr);
}

void MainWindow::on_fileBrowseButton_clicked()
{
    static int callCount = 0;
    SECURE_LOG(DEBUG, "MainWindow", QString("File Browse Button Clicked (Call #%1)").arg(++callCount));
    QString filePath = QFileDialog::getOpenFileName(this, "Select File");
    if (!filePath.isEmpty())
    {
        ui->filePathLineEdit->setText(filePath);
        updateSecurityStatus(filePath, fileSecurityStatusLabel);
    }
}

void MainWindow::on_fileKeyfileBrowseButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "File Keyfile Browse Button Clicked");
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty())
    {
        for (const QString &path : keyfilePaths)
        {
            ui->fileKeyfileListWidget->addItem(path);
        }
    }
}

