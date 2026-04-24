// File/folder encrypt & decrypt buttons + the shared worker dispatch.
// Extracted from mainwindow.cpp so the worker lifecycle (startWorker,
// updateProgress, workerFinished) and the browse-dialog glue live in a
// single place without dragging all the main-window boilerplate along.
// No behaviour change; declarations unchanged in include/mainwindow.h.
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
    startWorker(true, true);
}

void MainWindow::on_fileDecryptButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "File Decrypt Button Clicked or Enter pressed");
    startWorker(false, true);
}

void MainWindow::on_folderEncryptButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "Folder Encrypt Button Clicked or Enter pressed");
    startWorker(true, false);
}

void MainWindow::on_folderDecryptButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "Folder Decrypt Button Clicked or Enter pressed");
    startWorker(false, false);
}

void MainWindow::startWorker(bool encrypt, bool isFile)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Start Worker: encrypt=%1, isFile=%2").arg(encrypt).arg(isFile));
    QString path = isFile ? ui->filePathLineEdit->text() : ui->folderPathLineEdit->text();
    QString password = isFile ? ui->filePasswordLineEdit->text() : ui->folderPasswordLineEdit->text();
    QString algorithm = isFile ? ui->fileAlgorithmComboBox->currentText() : ui->folderAlgorithmComboBox->currentText();
    QString kdf = isFile ? ui->kdfComboBox->currentText() : ui->folderKdfComboBox->currentText();
    int iterations = isFile ? ui->iterationsSpinBox->value() : ui->folderIterationsSpinBox->value();
    bool useHMAC = isFile ? ui->hmacCheckBox->isChecked() : ui->folderHmacCheckBox->isChecked();
    QStringList keyfilePaths = isFile ? ui->fileKeyfileListWidget->getAllItems() : ui->folderKeyfileListWidget->getAllItems();
    QString customHeader = ""; // or any specific header if needed

    if (path.isEmpty() || password.isEmpty())
    {
        QMessageBox::warning(this, "Error", "Please provide path and password.");
        return;
    }

    // For folder decryption, special handling is needed
    if (!isFile && !encrypt) {
        // Check if the path is a directory for decryption, it should be a file with .enc extension
        QFileInfo fileInfo(path);
        if (fileInfo.isDir()) {
            // If it's a directory, try to find the encrypted file with .enc or .encrypted extension
            bool foundEncryptedFile = false;
            QString encFilePath;
            
            // Check if the folder has an associated encrypted file
            QStringList possibleExtensions = {".enc", ".encrypted"};
            for (const QString& ext : possibleExtensions) {
                QString testPath = path + ext;
                if (QFile::exists(testPath)) {
                    encFilePath = testPath;
                    foundEncryptedFile = true;
                    break;
                }
            }
            
            // If an encrypted file wasn't found, ask the user if they want to select it
            if (!foundEncryptedFile) {
                QMessageBox msgBox;
                msgBox.setIcon(QMessageBox::Question);
                msgBox.setText("Folder Decryption");
                msgBox.setInformativeText(
                    "The selected path is a directory, but for decryption, an encrypted file (.enc or .encrypted) is needed.\n\n"
                    "Would you like to select the encrypted file instead?");
                msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
                msgBox.setDefaultButton(QMessageBox::Yes);
                
                int ret = msgBox.exec();
                if (ret == QMessageBox::Yes) {
                    QString startPath = QFileInfo(path).dir().path();
                    encFilePath = QFileDialog::getOpenFileName(
                        this, 
                        "Select Encrypted Folder Archive", 
                        startPath, 
                        "Encrypted Files (*.enc *.encrypted);;All Files (*)");
                    
                    if (encFilePath.isEmpty()) {
                        return; // User canceled
                    }
                    
                    // Update the path
                    path = encFilePath;
                    ui->folderPathLineEdit->setText(path);
                } else {
                    // User chose not to select a file - we'll try to proceed with the folder path
                    // The encryption engine's decryptFolder will attempt to find the associated .enc file
                    QMessageBox::information(this, "Decryption Notice", 
                        "Will attempt to find an encrypted file associated with this folder path.");
                }
            } else {
                // Found an encrypted file - update the path
                path = encFilePath;
                ui->folderPathLineEdit->setText(path);
                QMessageBox::information(this, "Decryption Notice", 
                    QString("Found encrypted file: %1\nWill use this for decryption.").arg(encFilePath));
            }
        }
    }

    // Validate that the selected algorithm and KDF are supported by the current provider
    QStringList supportedCiphers = encryptionEngine.supportedCiphers();
    QStringList supportedKDFs = encryptionEngine.supportedKDFs();

    if (!supportedCiphers.contains(algorithm))
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

    // Check for tar command availability for folder operations
    if (!isFile) {
        QProcess process;
        process.start("which", QStringList() << "tar");
        process.waitForFinished();
        if (process.exitCode() != 0) {
            QMessageBox::critical(this, "Error", 
                "The 'tar' command is not available on your system. It is required for folder encryption/decryption operations.");
            return;
        }
    }

    QProgressBar *progressBar = isFile ? ui->fileProgressBar : ui->folderProgressBar;
    QLabel *estimatedTimeLabel = isFile ? ui->fileEstimatedTimeLabel : ui->folderEstimatedTimeLabel;

    progressBar->setValue(0);
    progressBar->setVisible(true);
    estimatedTimeLabel->setText("Estimated time: Calculating...");
    estimatedTimeLabel->setVisible(true);

    // Disable all operation buttons while processing
    ui->fileEncryptButton->setEnabled(false);
    ui->fileDecryptButton->setEnabled(false);
    ui->folderEncryptButton->setEnabled(false);
    ui->folderDecryptButton->setEnabled(false);
    ui->diskEncryptButton->setEnabled(false);
    ui->diskDecryptButton->setEnabled(false);

    // Update status message
    QString statusMessage;
    if (isFile) {
        statusMessage = encrypt ? 
            QString("Encrypting file: %1").arg(QFileInfo(path).fileName()) :
            QString("Decrypting file: %1").arg(QFileInfo(path).fileName());
        ui->fileInfoLabel->setText(statusMessage);
    } else {
        statusMessage = encrypt ? 
            QString("Encrypting folder: %1").arg(QFileInfo(path).fileName()) :
            QString("Decrypting folder: %1").arg(QFileInfo(path).fileName());
        ui->folderInfoLabel->setText(statusMessage);
    }

    // Setup worker thread
    if (!worker) {
        worker = new EncryptionWorker();
        worker->moveToThread(&workerThread);
        
        if (!m_signalsConnected) {
            connectSignalsAndSlots();
        }
    }

    // Set parameters and start work
    worker->setParameters(path, password, algorithm, kdf, iterations, useHMAC, encrypt, isFile, customHeader, keyfilePaths);
    emit worker->process();
}

void MainWindow::updateProgress(int value)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Update Progress: value=%1").arg(value));
    ui->fileProgressBar->setValue(value);
    ui->folderProgressBar->setValue(value);
    ui->diskProgressBar->setValue(value);
}

void MainWindow::workerFinished(const QString &result, bool success, bool isFile)
{
    // Re-enable all operation buttons
    ui->fileEncryptButton->setEnabled(true);
    ui->fileDecryptButton->setEnabled(true);
    ui->folderEncryptButton->setEnabled(true);
    ui->folderDecryptButton->setEnabled(true);
    ui->diskEncryptButton->setEnabled(true);
    ui->diskDecryptButton->setEnabled(true);

    // Hide progress indicators
    QProgressBar *progressBar = isFile ? ui->fileProgressBar : ui->folderProgressBar;
    QLabel *estimatedTimeLabel = isFile ? ui->fileEstimatedTimeLabel : ui->folderEstimatedTimeLabel;
    
    progressBar->setVisible(false);
    estimatedTimeLabel->setVisible(false);

    if (success)
    {
        QString message = isFile ? 
            "File operation completed successfully!" : 
            "Folder operation completed successfully!";
        
        if (result.contains("Output:")) {
            message += "\n\n" + result;
        }
        
        QMessageBox::information(this, "Success", message);
        
        // Update the info label with the result path
        QLabel *infoLabel = isFile ? ui->fileInfoLabel : ui->folderInfoLabel;
        
        if (result.contains("Output:")) {
            // Try to extract the output file path from the result
            QRegularExpression re("Output: (.+)");
            QRegularExpressionMatch match = re.match(result);
            if (match.hasMatch()) {
                QString outputPath = match.captured(1);
                infoLabel->setText(QString("Output: %1").arg(outputPath));
            } else {
                infoLabel->setText("Operation successful");
            }
        } else {
            infoLabel->setText("Operation successful");
        }
    }
    else
    {
        QMessageBox::warning(this, "Error", result);
        
        // Update the info label with the error
        QLabel *infoLabel = isFile ? ui->fileInfoLabel : ui->folderInfoLabel;
        infoLabel->setText(QString("Error: %1").arg(result.left(80) + (result.length() > 80 ? "..." : "")));
    }
}

void MainWindow::showEstimatedTime(const QString &timeStr)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Show Estimated Time: %1").arg(timeStr));
    
    ui->fileEstimatedTimeLabel->setText(timeStr);
    ui->folderEstimatedTimeLabel->setText(timeStr);
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

void MainWindow::on_folderBrowseButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "on_folderBrowseButton_clicked");
    
    // Ensure we have a valid starting path
    QString startPath = ui->folderPathLineEdit->text();
    if (startPath.isEmpty()) {
        startPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    }
    
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setOption(QFileDialog::ShowDirsOnly, true);
    dialog.setDirectory(startPath);
    
    // Add folder filtering
    QComboBox* typeCombo = new QComboBox(&dialog);
    typeCombo->addItem("All Folders");
    typeCombo->addItem("Document Folders");
    typeCombo->addItem("Images Folders");
    
    if (dialog.exec()) {
        QString folderPath = dialog.selectedFiles().first();
        
        // Check if we should continue with this path (user might have clicked Cancel)
        if (folderPath.isEmpty()) {
            return;
        }
        
        // For folder selection, we need to verify if this is a valid folder
        QFileInfo folderInfo(folderPath);
        if (!folderInfo.isDir()) {
            QMessageBox::warning(
                this,
                "Invalid Selection",
                "The selected path is not a directory. Please select a valid folder.");
            return;
        }
        
        // Show folder selection dialog for encryption/decryption
        bool isEncryption = false;
        
        if (sender() && (sender() == ui->folderBrowseButton)) {
            QWidget* focusWidget = QApplication::focusWidget();
            QAbstractButton* focusedButton = qobject_cast<QAbstractButton*>(focusWidget);
            
            if (focusedButton) {
                if (focusedButton == ui->folderEncryptButton) {
                    isEncryption = true;
                }
            }
        }
        
        if (isEncryption) {
            ui->folderPathLineEdit->setText(folderPath);
            updateSecurityStatus(folderPath, folderSecurityStatusLabel);
            
            // Update the folder info label with useful information
            QFileInfo fileInfo(folderPath);
            QString infoText;
            
            if (fileInfo.isDir()) {
                // If it's a directory, count files and show total size
                QDir dir(folderPath);
                QFileInfoList entries = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot, QDir::DirsFirst);
                
                // Count files and subdirectories
                int fileCount = 0;
                int dirCount = 0;
                qint64 totalSize = 0;
                
                for (const QFileInfo &entry : entries) {
                    if (entry.isDir()) {
                        dirCount++;
                    } else if (entry.isFile()) {
                        fileCount++;
                        totalSize += entry.size();
                    }
                }
                
                // Format the size in human-readable form
                QString sizeText;
                const qint64 KB = 1024;
                const qint64 MB = 1024 * KB;
                const qint64 GB = 1024 * MB;
                
                if (totalSize < KB) {
                    sizeText = QString("%1 bytes").arg(totalSize);
                } else if (totalSize < MB) {
                    sizeText = QString("%1 KB").arg(static_cast<double>(totalSize) / KB, 0, 'f', 2);
                } else if (totalSize < GB) {
                    sizeText = QString("%1 MB").arg(static_cast<double>(totalSize) / MB, 0, 'f', 2);
                } else {
                    sizeText = QString("%1 GB").arg(static_cast<double>(totalSize) / GB, 0, 'f', 2);
                }
                
                infoText = QString("Folder contains %1 files in %2 directories.\nTotal size: %3")
                               .arg(fileCount)
                               .arg(dirCount)
                               .arg(sizeText);
                
                // Note if the folder is empty
                if (fileCount == 0 && dirCount == 0) {
                    infoText = "Selected folder is empty.";
                }
                
                // Display a suggestion if it looks like a decompression folder
                if (fileInfo.fileName().endsWith(".enc") || fileInfo.fileName().endsWith(".encrypted")) {
                    infoText += "\n\nNOTE: The folder name suggests this might be an encrypted file, not a folder.";
                }
            } else if (fileInfo.isFile()) {
                // For files (when decrypting), show file details
                QString fileSize;
                qint64 size = fileInfo.size();
                const qint64 KB = 1024;
                const qint64 MB = 1024 * KB;
                const qint64 GB = 1024 * MB;
                
                if (size < KB) {
                    fileSize = QString("%1 bytes").arg(size);
                } else if (size < MB) {
                    fileSize = QString("%1 KB").arg(static_cast<double>(size) / KB, 0, 'f', 2);
                } else if (size < GB) {
                    fileSize = QString("%1 MB").arg(static_cast<double>(size) / MB, 0, 'f', 2);
                } else {
                    fileSize = QString("%1 GB").arg(static_cast<double>(size) / GB, 0, 'f', 2);
                }
                
                infoText = QString("Selected file: %1\nSize: %2\nLast modified: %3")
                               .arg(fileInfo.fileName())
                               .arg(fileSize)
                               .arg(fileInfo.lastModified().toString("yyyy-MM-dd hh:mm:ss"));
                
                // Check if it's likely an encrypted folder
                if (fileInfo.fileName().endsWith(".enc") || fileInfo.fileName().endsWith(".encrypted")) {
                    infoText += "\n\nThis appears to be an encrypted folder archive.";
                    
                    // Suggest output location
                    QString suggestedPath = fileInfo.path() + "/" + fileInfo.completeBaseName();
                    infoText += QString("\nIt will be decrypted to: %1").arg(suggestedPath);
                } else {
                    infoText += "\n\nThis file doesn't have a recognized encryption extension (.enc or .encrypted).";
                }
            } else {
                infoText = "Selected path is neither a file nor a directory.";
            }
            
            ui->folderInfoLabel->setText(infoText);
        }
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

void MainWindow::on_folderKeyfileBrowseButton_clicked()
{
    SECURE_LOG(DEBUG, "MainWindow", "Folder Keyfile Browse Button Clicked");
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty())
    {
        for (const QString &path : keyfilePaths)
        {
            ui->folderKeyfileListWidget->addItem(path);
        }
    }
}
