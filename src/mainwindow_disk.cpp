#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "logging/secure_logger.h"
#include "encryptionengine_diskops.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardItem>
#include <QDateTime>
#include <QStorageInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QDebug>
#include <QSettings>
#include <QListWidget>

#ifdef Q_OS_WIN
#  include <windows.h>
#  include <shellapi.h>
#else
#  include <unistd.h> // geteuid() on Linux/macOS
#endif

#ifdef Q_OS_MAC
#  include <Security/Authorization.h>
#  include <Security/AuthorizationTags.h>
#endif

// Define the disk header magic strings
#define DISK_HEADER_MAGIC "OPENCRYPT_DISK_HDR"
#define DISK_HEADER_MAGIC_V1 "OPENCRYPT_DISK_V1"

// Functions related to disk encryption in MainWindow class

// Helper function to check if we have admin privileges
bool MainWindow::hasAdminPrivileges() 
{
#ifdef Q_OS_WIN
    // On Windows, check for admin privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    // Create a SID for the Administrators group
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        // Check if this process token is in the admin group
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }
    return isAdmin ? true : false;
#elif defined(Q_OS_UNIX)
    // On Unix-like systems (Linux, macOS), check effective UID
    return (geteuid() == 0);
#else
    // On other platforms, assume we don't have admin privileges
    return false;
#endif
}

// Function to elevate privileges if needed
bool MainWindow::elevatePrivileges(const QString& diskPath)
{
    // If we already have admin privileges, no need to elevate
    if (hasAdminPrivileges()) {
        return true;
    }
    
    // Create a message explaining the need for privileges
    QString message = QString("Disk encryption requires administrator privileges to access the disk directly.\n"
                             "Would you like to elevate privileges now?\n\n"
                             "Disk path: %1").arg(diskPath);
    
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Elevation Required", 
                                                           message, QMessageBox::Yes | QMessageBox::No);
    
    if (reply != QMessageBox::Yes) {
        return false;
    }
    
    bool success = false;
    
#ifdef Q_OS_WIN
    // On Windows, use ShellExecute to run the same program with "runas" verb
    // Use the Unicode version (ShellExecuteExW) with SHELLEXECUTEINFOW
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.lpVerb = L"runas";  // This requests elevation
    sei.lpFile = reinterpret_cast<LPCWSTR>(qApp->applicationFilePath().utf16());
    sei.lpParameters = L"--elevated";  // Pass a parameter to indicate we're running elevated
    sei.nShow = SW_NORMAL;
    
    success = ShellExecuteExW(&sei);
    
    // If we successfully started the elevated process, we should close this instance
    if (success) {
        QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
    }
#elif defined(Q_OS_LINUX)
    // On Linux, we can use pkexec, gksudo, or sudo
    QStringList elevationCommands = {"pkexec", "gksudo", "kdesudo"};
    QString foundCommand;
    
    // Find which elevation command is available
    for (const QString& cmd : elevationCommands) {
        QProcess which;
        which.start("which", QStringList() << cmd);
        which.waitForFinished();
        if (which.exitCode() == 0) {
            foundCommand = cmd;
            break;
        }
    }
    
    if (foundCommand.isEmpty()) {
        // Fallback to sudo with terminal
        foundCommand = "x-terminal-emulator -e sudo";
    }
    
    // Create the command with the current application path and args
    QString command = QString("%1 %2 --elevated").arg(foundCommand, qApp->applicationFilePath());
    success = QProcess::startDetached(command, QStringList());
    
    // If we successfully started the elevated process, we should close this instance
    if (success) {
        QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
    }
#elif defined(Q_OS_MAC)
    // On macOS, use a more modern approach for recent macOS versions
    // Note: AuthorizationExecuteWithPrivileges is deprecated in macOS 10.7+
    
    // First, try to use a script approach with osascript
    QProcess osascript;
    QString scriptCmd = QString("do shell script \"\\\"%1\\\" --elevated\" with administrator privileges")
                        .arg(qApp->applicationFilePath().replace("\"", "\\\""));
    
    osascript.start("osascript", QStringList() << "-e" << scriptCmd);
    osascript.waitForFinished();
    
    if (osascript.exitCode() == 0) {
        success = true;
        // If we successfully started the elevated process, we should close this instance
        QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
    } else {
        // Fallback to the deprecated API for older macOS versions
        AuthorizationRef authRef;
        OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                          kAuthorizationFlagDefaults, &authRef);
        
        if (status == errAuthorizationSuccess) {
            const char *path = qApp->applicationFilePath().toUtf8().constData();
            const char *args[] = {"--elevated", NULL};
            
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            status = AuthorizationExecuteWithPrivileges(authRef, path, 
                                                    kAuthorizationFlagDefaults, 
                                                    (char **)args, NULL);
#pragma clang diagnostic pop
            
            if (status == errAuthorizationSuccess) {
                success = true;
                // If we successfully started the elevated process, we should close this instance
                QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
            }
            
            AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        }
    }
#endif

    return success;
}

void MainWindow::on_diskEncryptButton_clicked()
{
    // Get common parameters from the UI
    QString diskPath = ui->diskPathLineEdit->text();
    QString algorithm = ui->diskAlgorithmComboBox->currentText();
    QString kdf = ui->diskKdfComboBox->currentText();
    int iterations = ui->diskIterationsSpinBox->value();
    bool useHMAC = ui->diskHmacCheckBox->isChecked();
    
    // Get secure wiping parameters
    bool performSecureWipe = ui->diskSecureWipeCheckBox->isChecked();
    EncryptionEngine::WipePattern wipePattern = EncryptionEngine::WipePattern::DOD_SHORT;
    int wipePasses = 3;
    bool verifyWipe = ui->verifyWipeCheckBox->isChecked();
    
    if (performSecureWipe && ui->wipePatternComboBox->currentIndex() >= 0) {
        wipePattern = static_cast<EncryptionEngine::WipePattern>(
            ui->wipePatternComboBox->currentData().toInt());
        wipePasses = ui->wipePassesSpinBox->value();
    }
    
    // Get keyfiles
    QStringList keyfilePaths;
    for (int i = 0; i < ui->diskKeyfileListWidget->count(); ++i) {
        keyfilePaths << ui->diskKeyfileListWidget->item(i)->text();
    }
    
    // Check which volume type is selected
    bool isHiddenVolume = (ui->diskSecurityTabs->currentIndex() == 1);
    
    // Get the appropriate passwords based on volume type
    QString password, hiddenPassword;
    
    if (isHiddenVolume) {
        // Using hidden volume - get both passwords
        password = ui->outerPasswordLineEdit->text();
        hiddenPassword = ui->hiddenPasswordLineEdit->text();
        
        // Additional validation for hidden volumes
        if (password.isEmpty() || hiddenPassword.isEmpty()) {
            QMessageBox::warning(this, "Warning", "For a hidden volume, you must provide both the outer volume password and the hidden volume password.");
            return;
        }
        
        if (password == hiddenPassword) {
            QMessageBox::warning(this, "Warning", "The outer volume password and hidden volume password must be different for security reasons.");
            return;
        }
    } else {
        // Standard volume - get the password
        password = ui->diskPasswordLineEdit->text();
        
        // Validate password confirmation
        QString confirmPassword = ui->diskConfirmPasswordLineEdit->text();
        if (password != confirmPassword) {
            QMessageBox::warning(this, "Warning", "The password and confirmation do not match.");
            return;
        }
    }
    
    // Validate input
    if (diskPath.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select a disk or volume to encrypt.");
        return;
    }
    
    if (password.isEmpty() && keyfilePaths.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please enter a password or select at least one keyfile.");
        return;
    }
    
    // Verify the selected disk path is valid
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        QMessageBox::warning(this, "Warning", "The selected disk path is not valid for encryption.");
        return;
    }
    
    // Check if we need elevated privileges for disk encryption
    bool needsElevation = true;
    
#ifdef Q_OS_WIN
    // Check if it's a regular file (virtual disk) or a disk device
    QFileInfo fileInfo(diskPath);
    needsElevation = !fileInfo.isFile() || diskPath.startsWith("\\\\.\\");
#elif defined(Q_OS_UNIX)
    // On Unix, we need elevation for device files or system directories
    QFileInfo fileInfo(diskPath);
    needsElevation = diskPath.startsWith("/dev/") || 
                    (!fileInfo.isWritable() && fileInfo.isDir()) ||
                    (fileInfo.ownerId() != geteuid());
#endif

    // Check if we have admin privileges, and if not, elevate
    if (needsElevation && !hasAdminPrivileges()) {
        // Store parameters in settings for elevated instance
        QSettings settings;
        settings.setValue("elevated/diskPath", diskPath);
        settings.setValue("elevated/password", password); // This should be more secure in production
        if (isHiddenVolume) {
            settings.setValue("elevated/hiddenPassword", hiddenPassword);
            settings.setValue("elevated/hiddenVolumeSize", ui->hiddenVolumeSizeSpinBox->value());
        }
        settings.setValue("elevated/algorithm", algorithm);
        settings.setValue("elevated/kdf", kdf);
        settings.setValue("elevated/iterations", iterations);
        settings.setValue("elevated/useHMAC", useHMAC);
        settings.setValue("elevated/keyfilePaths", keyfilePaths);
        settings.setValue("elevated/isHiddenVolume", isHiddenVolume);
        
        // Store secure wipe settings
        settings.setValue("elevated/performSecureWipe", performSecureWipe);
        settings.setValue("elevated/wipePattern", static_cast<int>(wipePattern));
        settings.setValue("elevated/wipePasses", wipePasses);
        settings.setValue("elevated/verifyWipe", verifyWipe);
        
        settings.setValue("elevated/operation", "encrypt");
        
        if (!elevatePrivileges(diskPath)) {
            QMessageBox::critical(this, "Elevation Failed", 
                                "Could not elevate privileges. Disk encryption requires administrator rights.");
            return;
        }
        
        // If elevation was successful, this instance will be closed
        return;
    }
    
    // Check if we're running with elevated privileges from a previous instance
    QSettings settings;
    if (settings.contains("elevated/operation") && settings.value("elevated/operation").toString() == "encrypt") {
        // Restore parameters from the settings
        diskPath = settings.value("elevated/diskPath").toString();
        password = settings.value("elevated/password").toString();
        isHiddenVolume = settings.value("elevated/isHiddenVolume").toBool();
        if (isHiddenVolume) {
            hiddenPassword = settings.value("elevated/hiddenPassword").toString();
        }
        algorithm = settings.value("elevated/algorithm").toString();
        kdf = settings.value("elevated/kdf").toString();
        iterations = settings.value("elevated/iterations").toInt();
        useHMAC = settings.value("elevated/useHMAC").toBool();
        keyfilePaths = settings.value("elevated/keyfilePaths").toStringList();
        
        // Restore secure wipe parameters
        performSecureWipe = settings.value("elevated/performSecureWipe", false).toBool();
        wipePattern = static_cast<EncryptionEngine::WipePattern>(
            settings.value("elevated/wipePattern", 
                          static_cast<int>(EncryptionEngine::WipePattern::DOD_SHORT)).toInt());
        wipePasses = settings.value("elevated/wipePasses", 3).toInt();
        verifyWipe = settings.value("elevated/verifyWipe", true).toBool();
        
        // Clear the settings
        settings.remove("elevated/operation");
        settings.remove("elevated/diskPath");
        settings.remove("elevated/password");
        settings.remove("elevated/hiddenPassword");
        settings.remove("elevated/hiddenVolumeSize");
        settings.remove("elevated/algorithm");
        settings.remove("elevated/kdf");
        settings.remove("elevated/iterations");
        settings.remove("elevated/useHMAC");
        settings.remove("elevated/keyfilePaths");
        settings.remove("elevated/isHiddenVolume");
        
        // Clean up secure wipe settings
        settings.remove("elevated/performSecureWipe");
        settings.remove("elevated/wipePattern");
        settings.remove("elevated/wipePasses");
        settings.remove("elevated/verifyWipe");
    }
    
    // Build the confirmation message including information about hidden volumes and wiping
    QString confirmMessage = "WARNING: You are about to encrypt a disk or volume. This operation will modify the disk directly and may result in data loss if interrupted.\n\n";
    
    if (isHiddenVolume) {
        int hiddenVolumePercent = ui->hiddenVolumeSizeSpinBox->value();
        confirmMessage += QString("You are creating a hidden volume that uses %1% of the disk space.\n\n").arg(hiddenVolumePercent);
    }
    
    if (performSecureWipe) {
        // Add information about the wiping process
        QString patternName;
        switch (wipePattern) {
            case EncryptionEngine::WipePattern::ZEROS:
                patternName = "Zeros";
                break;
            case EncryptionEngine::WipePattern::ONES:
                patternName = "Ones";
                break;
            case EncryptionEngine::WipePattern::RANDOM:
                patternName = "Random Data";
                break;
            case EncryptionEngine::WipePattern::DOD_SHORT:
                patternName = "DoD 5220.22-M (3 passes)";
                break;
            case EncryptionEngine::WipePattern::DOD_FULL:
                patternName = "DoD 5220.22-M Full (7 passes)";
                break;
            case EncryptionEngine::WipePattern::GUTMANN:
                patternName = "Gutmann (35 passes)";
                break;
        }
        
        confirmMessage += QString("ATTENTION: The disk will first be securely wiped using the %1 pattern with %2 passes.\n")
                          .arg(patternName)
                          .arg(wipePasses);
        
        if (verifyWipe) {
            confirmMessage += "Verification will be performed after each pass which doubles the operation time.\n";
        }
        
        confirmMessage += "\nThis cannot be undone and all existing data will be permanently destroyed.\n\n";
    }
    
    confirmMessage += "Are you sure you want to continue?";
    
    // Confirm disk encryption operation
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Confirm Disk Encryption",
                                confirmMessage,
                                QMessageBox::Yes | QMessageBox::No);
    
    if (reply != QMessageBox::Yes)
        return;
    
    // Setup and start the worker thread
    SECURE_LOG(INFO, "MainWindow", QString("Starting disk encryption on %1").arg(diskPath));
    ui->diskProgressBar->setValue(0);
    ui->diskProgressBar->setVisible(true);
    ui->diskEstimatedTimeLabel->setText("Estimated time: Calculating...");
    ui->diskEstimatedTimeLabel->setVisible(true);
    ui->diskEncryptButton->setEnabled(false);
    ui->diskDecryptButton->setEnabled(false);
    
    // Setup worker thread
    if (!worker) {
        worker = new EncryptionWorker();
        worker->moveToThread(&workerThread);
        
        if (!m_signalsConnected) {
            connectSignalsAndSlots();
        }
    }
    
    // Perform secure wiping first if requested
    if (performSecureWipe) {
        SECURE_LOG(INFO, "MainWindow", QString("Starting secure disk wiping on %1 before encryption").arg(diskPath));
        ui->diskProgressBar->setValue(0);
        ui->diskProgressBar->setVisible(true);
        ui->diskEstimatedTimeLabel->setText("Estimated time for wiping: Calculating...");
        ui->diskEstimatedTimeLabel->setVisible(true);
        
        // Show additional information to the user
        QString statusMessage = QString("Securely wiping disk with %1 passes...\nThis might take a long time.").arg(wipePasses);
        ui->diskInfoLabel->setText(statusMessage);
        
        QApplication::processEvents(); // Ensure UI update
        
        // Perform the actual wiping operation
        bool wipeSuccess = encryptionEngine.secureWipeDisk(diskPath, wipePasses, verifyWipe);
        
        if (!wipeSuccess) {
            QMessageBox::critical(this, "Wiping Failed",
                                 "Secure wiping of the disk failed. Encryption process aborted.");
            ui->diskEncryptButton->setEnabled(true);
            ui->diskDecryptButton->setEnabled(true);
            ui->diskEstimatedTimeLabel->setVisible(false);
            ui->diskProgressBar->setVisible(false);
            return;
        }
        
        // Update UI after wiping
        ui->diskProgressBar->setValue(0);
        ui->diskEstimatedTimeLabel->setText("Wiping completed. Starting encryption...");
        SECURE_LOG(INFO, "MainWindow", "Secure wiping completed successfully. Proceeding with encryption.");
    }

    // Set parameters and start work
    if (isHiddenVolume) {
        // For hidden volumes, we need to add additional parameters
        int hiddenVolumePercent = settings.contains("elevated/hiddenVolumeSize") ? 
                                 settings.value("elevated/hiddenVolumeSize").toInt() : 
                                 ui->hiddenVolumeSizeSpinBox->value();
        
        // Calculate the hidden volume size
        qint64 hiddenVolumeSize = DiskOperations::calculateHiddenVolumeSize(diskPath, hiddenVolumePercent);
        
        // Set both main and hidden volume parameters
        worker->setDiskParametersWithHiddenVolume(
            diskPath, password, hiddenPassword, hiddenVolumeSize,
            algorithm, kdf, iterations, useHMAC, keyfilePaths);
    } else {
        // Set regular disk parameters for standard volume
        worker->setDiskParameters(diskPath, password, algorithm, kdf, iterations, useHMAC, true, keyfilePaths);
    }
    
    emit worker->process();
}

void MainWindow::on_diskDecryptButton_clicked()
{
    QString diskPath = ui->diskPathLineEdit->text();
    QString password = ui->diskPasswordLineEdit->text();
    QString algorithm = ui->diskAlgorithmComboBox->currentText();
    QString kdf = ui->diskKdfComboBox->currentText();
    int iterations = ui->diskIterationsSpinBox->value();
    bool useHMAC = ui->diskHmacCheckBox->isChecked();
    
    // Get keyfiles
    QStringList keyfilePaths;
    for (int i = 0; i < ui->diskKeyfileListWidget->count(); ++i) {
        keyfilePaths << ui->diskKeyfileListWidget->item(i)->text();
    }
    
    // Validate input
    if (diskPath.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select a disk or volume to decrypt.");
        return;
    }
    
    if (password.isEmpty() && keyfilePaths.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please enter a password or select at least one keyfile.");
        return;
    }
    
    // Verify the selected disk path is valid
    if (!DiskOperations::isValidDiskPath(diskPath)) {
        QMessageBox::warning(this, "Warning", "The selected disk path is not valid for decryption.");
        return;
    }
    
    // Check if we need elevated privileges for disk decryption
    bool needsElevation = true;
    
#ifdef Q_OS_WIN
    // Check if it's a regular file (virtual disk) or a disk device
    QFileInfo fileInfo(diskPath);
    needsElevation = !fileInfo.isFile() || diskPath.startsWith("\\\\.\\");
#elif defined(Q_OS_UNIX)
    // On Unix, we need elevation for device files or system directories
    QFileInfo fileInfo(diskPath);
    needsElevation = diskPath.startsWith("/dev/") || 
                   (!fileInfo.isWritable() && fileInfo.isDir()) ||
                   (fileInfo.ownerId() != geteuid());
#endif

    // Check if we have admin privileges, and if not, elevate
    if (needsElevation && !hasAdminPrivileges()) {
        // Store parameters in settings for elevated instance
        QSettings settings;
        settings.setValue("elevated/diskPath", diskPath);
        settings.setValue("elevated/password", password); // This should be more secure in production
        settings.setValue("elevated/algorithm", algorithm);
        settings.setValue("elevated/kdf", kdf);
        settings.setValue("elevated/iterations", iterations);
        settings.setValue("elevated/useHMAC", useHMAC);
        settings.setValue("elevated/keyfilePaths", keyfilePaths);
        settings.setValue("elevated/operation", "decrypt");
        
        if (!elevatePrivileges(diskPath)) {
            QMessageBox::critical(this, "Elevation Failed", 
                               "Could not elevate privileges. Disk decryption requires administrator rights.");
            return;
        }
        
        // If elevation was successful, this instance will be closed
        return;
    }
    
    // Check if we're running with elevated privileges from a previous instance
    QSettings settings;
    if (settings.contains("elevated/operation") && settings.value("elevated/operation").toString() == "decrypt") {
        // Restore parameters from the settings
        diskPath = settings.value("elevated/diskPath").toString();
        password = settings.value("elevated/password").toString();
        algorithm = settings.value("elevated/algorithm").toString();
        kdf = settings.value("elevated/kdf").toString();
        iterations = settings.value("elevated/iterations").toInt();
        useHMAC = settings.value("elevated/useHMAC").toBool();
        keyfilePaths = settings.value("elevated/keyfilePaths").toStringList();
        
        // Clear the settings
        settings.remove("elevated/operation");
        settings.remove("elevated/diskPath");
        settings.remove("elevated/password");
        settings.remove("elevated/algorithm");
        settings.remove("elevated/kdf");
        settings.remove("elevated/iterations");
        settings.remove("elevated/useHMAC");
        settings.remove("elevated/keyfilePaths");
    }
    
    // Confirm disk decryption operation
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Confirm Disk Decryption",
        "WARNING: You are about to decrypt a disk or volume. This operation will modify the disk directly and may result in data loss if interrupted.\n\n"
        "Are you sure you want to continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply != QMessageBox::Yes)
        return;
    
    // Setup and start the worker thread
    SECURE_LOG(INFO, "MainWindow", QString("Starting disk decryption on %1").arg(diskPath));
    ui->diskProgressBar->setValue(0);
    ui->diskProgressBar->setVisible(true);
    ui->diskEstimatedTimeLabel->setText("Estimated time: Calculating...");
    ui->diskEstimatedTimeLabel->setVisible(true);
    ui->diskEncryptButton->setEnabled(false);
    ui->diskDecryptButton->setEnabled(false);
    
    // Setup worker thread
    if (!worker) {
        worker = new EncryptionWorker();
        worker->moveToThread(&workerThread);
        
        if (!m_signalsConnected) {
            connectSignalsAndSlots();
        }
    }
    
    // Set parameters and start work
    worker->setDiskParameters(diskPath, password, algorithm, kdf, iterations, useHMAC, false, keyfilePaths);
    emit worker->process();
}

void MainWindow::on_diskBrowseButton_clicked()
{
    QString path;
#ifdef Q_OS_LINUX
    // On Linux, use /dev/ path browser
    path = QFileDialog::getOpenFileName(this, "Select Disk Device", "/dev/", "Block Devices (*)");
#else
    // On other platforms, use directory browser
    path = QFileDialog::getExistingDirectory(this, "Select Volume or Directory", "/");
#endif
    
    if (!path.isEmpty()) {
        ui->diskPathLineEdit->setText(path);
        
        // Show detailed information about the selected disk
        bool found = false;
        DiskInfoList disks = DiskOperations::getAvailableDisks();
        for (const DiskInfo &disk : disks) {
            if (disk.path == path) {
                // Display formatted disk info in the info label
                ui->diskInfoLabel->setText(DiskOperations::getDiskDetails(disk));
                found = true;
                break;
            }
        }
        
        if (!found) {
            // Create a basic disk info object from the path
            DiskInfo diskInfo;
            diskInfo.path = path;
            diskInfo.name = QFileInfo(path).fileName();
            if (diskInfo.name.isEmpty()) {
                diskInfo.name = path;
            }
            
            // Try to get the size
            QFileInfo fileInfo(path);
            if (fileInfo.isFile()) {
                diskInfo.size = fileInfo.size();
                diskInfo.type = "file";
            } else if (fileInfo.isDir()) {
                QStorageInfo storage(path);
                if (storage.isValid()) {
                    diskInfo.size = storage.bytesTotal();
                    diskInfo.type = "directory";
                }
            }
            
            // Check if it's encrypted
            if (QFile::exists(path) && QFileInfo(path).isReadable()) {
                QFile file(path);
                if (file.open(QIODevice::ReadOnly)) {
                    // Read enough bytes to check for the header
                    QByteArray header = file.read(128);
                    file.close();
                    
                    // Look for the magic string
                    if (header.contains(DISK_HEADER_MAGIC) || header.contains(DISK_HEADER_MAGIC_V1)) {
                        diskInfo.isEncrypted = true;
                        diskInfo.hasHiddenVolume = header.contains("\"hasHiddenVolume\":true");
                    }
                }
            }
            
            // Display formatted disk info
            ui->diskInfoLabel->setText(DiskOperations::getDiskDetails(diskInfo));
        }
    }
    
    // Verify the selected path is valid for disk encryption
    if (!path.isEmpty() && !DiskOperations::isValidDiskPath(path)) {
        QMessageBox::warning(this, "Warning", "The selected path may not be valid for disk encryption. Please select a removable disk, volume, or supported disk device.");
    }
}

void MainWindow::on_diskKeyfileBrowseButton_clicked()
{
    QStringList paths = QFileDialog::getOpenFileNames(this, "Select Keyfiles", QDir::homePath(), "All Files (*)");
    
    if (!paths.isEmpty()) {
        for (const QString &path : paths) {
            if (!containsKeyfile(ui->diskKeyfileListWidget, path)) {
                ui->diskKeyfileListWidget->addItem(path);
            }
        }
    }
}

void MainWindow::on_refreshDisksButton_clicked()
{
    // Clear current disks
    ui->diskComboBox->clear();
    
    // Get list of available disks
    DiskInfoList disks = DiskOperations::getAvailableDisks();
    
    // Sort disks by type (removable first) and then by name
    std::sort(disks.begin(), disks.end(), [](const DiskInfo &a, const DiskInfo &b) {
        if (a.isRemovable != b.isRemovable) {
            return a.isRemovable; // Removable disks first
        }
        return a.name < b.name; // Then sort by name
    });
    
    // Add disks to combo box
    for (const DiskInfo &disk : disks) {
        QString displayText = disk.name;
        
        // Add human-readable size
        displayText += QString(" (%1").arg(DiskOperations::formatDiskSize(disk.size));
        
        // Add type
        displayText += QString(", %1").arg(disk.type);
        
        // Indicate if removable
        if (disk.isRemovable) {
            displayText += ", Removable";
        }
        
        // Indicate if already encrypted
        if (disk.isEncrypted) {
            displayText += ", Encrypted";
            
            // Check for hidden volume
            if (disk.hasHiddenVolume) {
                displayText += ", Hidden Vol";
            }
        }
        
        displayText += ")";
        
        // Add to combo box with full path as data
        ui->diskComboBox->addItem(displayText, disk.path);
    }
    
    // Connect combo box change signal if not already connected
    connect(ui->diskComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (index >= 0) {
            QString path = ui->diskComboBox->itemData(index).toString();
            ui->diskPathLineEdit->setText(path);
            
            // Find the disk info to display detailed information
            DiskInfoList disks = DiskOperations::getAvailableDisks();
            for (const DiskInfo &disk : disks) {
                if (disk.path == path) {
                    // Display formatted disk info in the info label
                    ui->diskInfoLabel->setText(DiskOperations::getDiskDetails(disk));
                    break;
                }
            }
        }
    });
    
    // Update disk path field with first disk
    if (ui->diskComboBox->count() > 0) {
        ui->diskComboBox->setCurrentIndex(0);
    }
}

// Helper function to check if a keyfile is already in the list
bool MainWindow::containsKeyfile(QListWidget *listWidget, const QString &path)
{
    for (int i = 0; i < listWidget->count(); ++i) {
        if (listWidget->item(i)->text() == path) {
            return true;
        }
    }
    return false;
}

// Handler for the secure wipe checkbox
void MainWindow::on_diskSecureWipeCheckBox_toggled(bool checked)
{
    // Enable or disable all wiping related controls based on the checkbox state
    ui->wipePatternLabel->setEnabled(checked);
    ui->wipePatternComboBox->setEnabled(checked);
    ui->wipePassesLabel->setEnabled(checked);
    ui->wipePassesSpinBox->setEnabled(checked);
    ui->verifyWipeCheckBox->setEnabled(checked);
    
    // If first time enabling, populate the wipe pattern combobox
    if (checked && ui->wipePatternComboBox->count() == 0) {
        ui->wipePatternComboBox->addItem("Random Data", static_cast<int>(EncryptionEngine::WipePattern::RANDOM));
        ui->wipePatternComboBox->addItem("Zeros", static_cast<int>(EncryptionEngine::WipePattern::ZEROS));
        ui->wipePatternComboBox->addItem("Ones", static_cast<int>(EncryptionEngine::WipePattern::ONES));
        ui->wipePatternComboBox->addItem("DoD 5220.22-M (3 passes)", static_cast<int>(EncryptionEngine::WipePattern::DOD_SHORT));
        ui->wipePatternComboBox->addItem("DoD 5220.22-M Full (7 passes)", static_cast<int>(EncryptionEngine::WipePattern::DOD_FULL));
        ui->wipePatternComboBox->addItem("Gutmann (35 passes)", static_cast<int>(EncryptionEngine::WipePattern::GUTMANN));
        
        // Set DoD short as default
        ui->wipePatternComboBox->setCurrentIndex(3);
    }
    
    if (checked) {
        // Show a warning about wiping
        QMessageBox::warning(this, "Secure Wiping Warning",
            "Secure wiping permanently destroys all data on the disk and cannot be undone.\n\n"
            "The wiping process may take a long time depending on the disk size and the number of passes selected.\n\n"
            "Do NOT interrupt the wiping process once it has started.");
    }
}

// Handler for the wipe pattern combobox
void MainWindow::on_wipePatternComboBox_currentIndexChanged(int index)
{
    if (index < 0)
        return;
    
    // Get the selected wipe pattern
    EncryptionEngine::WipePattern pattern = 
        static_cast<EncryptionEngine::WipePattern>(ui->wipePatternComboBox->currentData().toInt());
    
    // Update passes spinbox based on the selected pattern
    switch (pattern) {
        case EncryptionEngine::WipePattern::ZEROS:
        case EncryptionEngine::WipePattern::ONES:
        case EncryptionEngine::WipePattern::RANDOM:
            ui->wipePassesSpinBox->setValue(3);
            ui->wipePassesSpinBox->setEnabled(true);
            break;
            
        case EncryptionEngine::WipePattern::DOD_SHORT:
            ui->wipePassesSpinBox->setValue(3);
            ui->wipePassesSpinBox->setEnabled(false);
            break;
            
        case EncryptionEngine::WipePattern::DOD_FULL:
            ui->wipePassesSpinBox->setValue(7);
            ui->wipePassesSpinBox->setEnabled(false);
            break;
            
        case EncryptionEngine::WipePattern::GUTMANN:
            ui->wipePassesSpinBox->setValue(35);
            ui->wipePassesSpinBox->setEnabled(false);
            break;
    }
}