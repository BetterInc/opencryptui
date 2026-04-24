#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QBuffer>
#include <QThread>
#include "logging/secure_logger.h"
#include <QTextStream>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QKeyEvent>
#include <QInputDialog>
#include <QCoreApplication>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QTimer>
#include <QProgressBar>
#include <QLabel>
#include <QCheckBox>
#include "encryptionengine.h"
#include <QDirIterator>
#include <QProcess>
#include "version.h"
#include "encryptionworker.h"
#include <QStatusBar>
#include <QStandardPaths>
#include <QRegularExpression>

// Add the static member initialization here
QTextStream *MainWindow::s_logStream = nullptr;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), worker(new EncryptionWorker), m_signalsConnected(false) // Initialize the flag
{
    SECURE_LOG(DEBUG, "MainWindow", "MainWindow Constructor");
    ui->setupUi(this);
    setupUI();

    // Load theme preference
    loadPreferences();

    // Set default values for iterations
    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);

    // Ensure connectSignalsAndSlots is called only once
    static bool connectionsSet = false;
    if (!connectionsSet)
    {
        connectSignalsAndSlots();
        connectionsSet = true;
    }

    checkHardwareAcceleration();

    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(worker, &EncryptionWorker::progress, this, &MainWindow::updateProgress);
    connect(worker, &EncryptionWorker::finished, this, &MainWindow::workerFinished);
    connect(worker, &EncryptionWorker::estimatedTime, this, &MainWindow::showEstimatedTime);
    connect(worker, &EncryptionWorker::benchmarkResultReady, this, &MainWindow::updateBenchmarkTable);

    workerThread.start();

    // Initialize the benchmark table
    ui->benchmarkTable->setColumnCount(5);
    QStringList headers = {"Iterations", "MB/s", "ms", "Cipher", "KDF"};
    ui->benchmarkTable->setHorizontalHeaderLabels(headers);
    ui->benchmarkTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // Enable sorting
    ui->benchmarkTable->setSortingEnabled(true);
}

void MainWindow::setupUI()
{
    setupComboBoxes();
    ui->fileProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->folderProgressBar->setVisible(false);
    ui->folderEstimatedTimeLabel->setVisible(false);
    ui->diskProgressBar->setVisible(false);
    ui->diskEstimatedTimeLabel->setVisible(false);
    
    // Create and set up security status labels
    fileSecurityStatusLabel = new QLabel(this);
    folderSecurityStatusLabel = new QLabel(this);
    diskSecurityStatusLabel = new QLabel(this);
    
    // Style the labels
    QString baseStyle = "font-weight: bold; padding: 5px; border-radius: 3px;";
    fileSecurityStatusLabel->setStyleSheet(baseStyle);
    folderSecurityStatusLabel->setStyleSheet(baseStyle);
    diskSecurityStatusLabel->setStyleSheet(baseStyle);
    
    // Add labels to layout near path fields
    ui->fileSelectionLayout->addWidget(fileSecurityStatusLabel);
    ui->folderSelectionLayout->addWidget(folderSecurityStatusLabel);
    ui->diskSelectionLayout->addWidget(diskSecurityStatusLabel);

    // Add crypto provider items
    QStringList providers = encryptionEngine.availableProviders();
    ui->m_cryptoProviderComboBox->addItems(providers);
    if (!providers.isEmpty())
    {
        ui->m_cryptoProviderComboBox->setCurrentText(encryptionEngine.currentProvider());
    }

    // Update the connection for crypto provider selection
    connect(ui->m_cryptoProviderComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [this](int index)
            {
                QString providerName = ui->m_cryptoProviderComboBox->itemText(index);
                on_m_cryptoProviderComboBox_currentIndexChanged(providerName);
            });

    connect(ui->m_providerInfoButton, &QPushButton::clicked, this, &MainWindow::showProviderCapabilities);

    // Install event filter on all relevant widgets
    ui->filePasswordLineEdit->installEventFilter(this);
    ui->folderPasswordLineEdit->installEventFilter(this);
    ui->diskPasswordLineEdit->installEventFilter(this);
    ui->fileEncryptButton->installEventFilter(this);
    ui->fileDecryptButton->installEventFilter(this);
    ui->folderEncryptButton->installEventFilter(this);
    ui->folderDecryptButton->installEventFilter(this);
    ui->diskEncryptButton->installEventFilter(this);
    ui->diskDecryptButton->installEventFilter(this);
    
    // Initialize disk encryption tab
    ui->diskIterationsSpinBox->setValue(10);
    ui->diskHmacCheckBox->setChecked(true);
    
    // Populate disk selection dropdown
    on_refreshDisksButton_clicked();
}

MainWindow::~MainWindow()
{
    // Save preferences before closing
    savePreferences();

    workerThread.quit();
    workerThread.wait();
    SECURE_LOG(DEBUG, "MainWindow", "MainWindow Destructor");
    delete ui;
}

void MainWindow::setupComboBoxes()
{
    QStringList algorithms = {// Add this slot implementation:
                              "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
                              "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
                              "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"};
    ui->fileAlgorithmComboBox->addItems(algorithms);
    ui->folderAlgorithmComboBox->addItems(algorithms);
    ui->diskAlgorithmComboBox->addItems(algorithms);

    QStringList kdfs = {"Scrypt", "PBKDF2"};

    ui->kdfComboBox->addItems(kdfs);
    ui->folderKdfComboBox->addItems(kdfs);
    ui->diskKdfComboBox->addItems(kdfs);

    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);
    ui->diskIterationsSpinBox->setValue(10);

    ui->hmacCheckBox->setChecked(true);
    ui->folderHmacCheckBox->setChecked(true);
    ui->diskHmacCheckBox->setChecked(true);
}

void MainWindow::updateSecurityStatus(const QString &path, QLabel *statusLabel)
{
    if (!statusLabel || path.isEmpty()) return;
    
    QFileInfo fileInfo(path);
    bool isSecure = true;
    QString statusText;
    QString styleSheet = "font-weight: bold; padding: 5px; border-radius: 3px;";
    
    // Check if in standard temp directory
    if (path.startsWith("/tmp/") || path.startsWith(QDir::tempPath())) {
        isSecure = false;
        statusText = "⚠️ INSECURE: File in temporary directory";
    }
    
    // Check if in user's home directory with proper permissions
    else if (fileInfo.exists()) {
        QFile file(path);
        QFileDevice::Permissions perms = file.permissions();
        
        // Check if world-readable
        if (perms & QFileDevice::ReadOther) {
            isSecure = false;
            statusText = "⚠️ INSECURE: File readable by others";
        }
        
        // Check if world-writable
        else if (perms & QFileDevice::WriteOther) {
            isSecure = false;
            statusText = "⚠️ INSECURE: File writable by others";
        }
        
        // Check if in a world-readable directory
        else {
            QString parentDir = fileInfo.absolutePath();
            QFileInfo dirInfo(parentDir);
            if (QFile(parentDir).permissions() & QFileDevice::ReadOther) {
                isSecure = false;
                statusText = "⚠️ WARNING: Parent directory accessible by others";
            }
        }
    }
    
    // Default secure status
    if (isSecure) {
        statusText = "✅ SECURE: Location has proper permissions";
        styleSheet += "background-color: #d4edda; color: #155724;";
    } else {
        styleSheet += "background-color: #f8d7da; color: #721c24;";
    }
    
    statusLabel->setText(statusText);
    statusLabel->setStyleSheet(styleSheet);
    statusLabel->setVisible(true);
}

void MainWindow::showSecurityTips(const QString &context)
{
    QString tips;
    
    if (context == "file") {
        tips = "File Encryption Security Tips:\n\n"
               "• Store encrypted files in private locations only you can access\n"
               "• Use both a strong password AND keyfile for critical files\n"
               "• Enable HMAC for file integrity verification\n"
               "• For maximum security, use AES-256-GCM or ChaCha20-Poly1305\n"
               "• Verify file permissions before and after encryption\n"
               "• Create encrypted backups stored in separate locations";
    }
    else if (context == "folder") {
        tips = "Folder Encryption Security Tips:\n\n"
               "• Choose a secure location for your encrypted folder\n"
               "• Use a different password than for individual files\n"
               "• Consider encrypted containers instead of folder encryption\n"
               "• Keep an inventory of encrypted folder contents\n"
               "• Test decryption regularly to ensure accessibility";
    }
    else if (context == "disk") {
        tips = "Disk Encryption Security Tips:\n\n"
               "• Always use full disk encryption for portable devices\n"
               "• Create a secure rescue key and store it separately\n"
               "• Remember that disk encryption doesn't protect mounted volumes\n"
               "• Consider hidden volumes for plausible deniability\n"
               "• Keep firmware and encryption software updated\n"
               "• Combine with strong boot password for maximum security";
    }
    else {
        tips = "General Encryption Security Tips:\n\n"
               "• Use unique strong passwords (16+ characters)\n"
               "• Store keyfiles on separate physical devices\n"
               "• Never share encryption passwords electronically\n"
               "• Choose secure storage locations with proper permissions\n"
               "• Regular backup your encrypted data and keys\n"
               "• Be aware of physical security (shoulder surfing)";
    }
    
    QMessageBox tipBox;
    tipBox.setWindowTitle("Security Tips");
    tipBox.setText(tips);
    tipBox.setIcon(QMessageBox::Information);
    
    // Add button to view comprehensive security guide
    tipBox.addButton("Close", QMessageBox::RejectRole);
    QPushButton *guideButton = tipBox.addButton("Full Security Guide", QMessageBox::ActionRole);
    
    tipBox.exec();
    
    if (tipBox.clickedButton() == guideButton) {
        on_actionSecurityGuide_triggered();
    }
}

void MainWindow::connectSignalsAndSlots()
{
    if (m_signalsConnected)
    {
        SECURE_LOG(DEBUG, "MainWindow", "Signals already connected, skipping...");
        return;
    }

    SECURE_LOG(DEBUG, "MainWindow", "Connecting signals and slots");

    // File encryption/decryption
    safeConnect(ui->fileEncryptButton, SIGNAL(clicked()), this, SLOT(on_fileEncryptButton_clicked()));
    safeConnect(ui->fileDecryptButton, SIGNAL(clicked()), this, SLOT(on_fileDecryptButton_clicked()));

    // Folder encryption/decryption
    safeConnect(ui->folderEncryptButton, SIGNAL(clicked()), this, SLOT(on_folderEncryptButton_clicked()));
    safeConnect(ui->folderDecryptButton, SIGNAL(clicked()), this, SLOT(on_folderDecryptButton_clicked()));

    // Disk encryption/decryption
    safeConnect(ui->diskEncryptButton, SIGNAL(clicked()), this, SLOT(on_diskEncryptButton_clicked()));
    safeConnect(ui->diskDecryptButton, SIGNAL(clicked()), this, SLOT(on_diskDecryptButton_clicked()));
    safeConnect(ui->diskBrowseButton, SIGNAL(clicked()), this, SLOT(on_diskBrowseButton_clicked()));
    safeConnect(ui->diskKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_diskKeyfileBrowseButton_clicked()));
    safeConnect(ui->refreshDisksButton, SIGNAL(clicked()), this, SLOT(on_refreshDisksButton_clicked()));

    // Other button connections
    safeConnect(ui->fileBrowseButton, SIGNAL(clicked()), this, SLOT(on_fileBrowseButton_clicked()));
    safeConnect(ui->fileKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_fileKeyfileBrowseButton_clicked()));
    safeConnect(ui->folderBrowseButton, SIGNAL(clicked()), this, SLOT(on_folderBrowseButton_clicked()));
    safeConnect(ui->folderKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_folderKeyfileBrowseButton_clicked()));
    safeConnect(ui->benchmarkButton, SIGNAL(clicked()), this, SLOT(on_benchmarkButton_clicked()));

    // Menu actions
    safeConnect(ui->actionExit, SIGNAL(triggered()), this, SLOT(on_actionExit_triggered()));
    safeConnect(ui->actionPreferences, SIGNAL(triggered()), this, SLOT(on_actionPreferences_triggered()));
    safeConnect(ui->actionAbout, SIGNAL(triggered()), this, SLOT(on_actionAbout_triggered()));
    safeConnect(ui->actionAboutCiphers, SIGNAL(triggered()), this, SLOT(on_actionAboutCiphers_triggered()));
    safeConnect(ui->actionAboutKDFs, SIGNAL(triggered()), this, SLOT(on_actionAboutKDFs_triggered()));
    safeConnect(ui->actionAboutIterations, SIGNAL(triggered()), this, SLOT(on_actionAboutIterations_triggered()));
    safeConnect(ui->actionSecurityGuide, SIGNAL(triggered()), this, SLOT(on_actionSecurityGuide_triggered()));
    
    // Connect path changes to security status updates
    connect(ui->filePathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, fileSecurityStatusLabel);
    });
    connect(ui->folderPathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, folderSecurityStatusLabel);
    });
    connect(ui->diskPathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, diskSecurityStatusLabel);
    });
    
    // Add security tip buttons
    QPushButton* fileHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    QPushButton* folderHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    QPushButton* diskHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    
    ui->fileEncryptionGroup->layout()->addWidget(fileHelpBtn);
    ui->folderEncryptionGroup->layout()->addWidget(folderHelpBtn);
    ui->diskEncryptionGroup->layout()->addWidget(diskHelpBtn);
    
    connect(fileHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("file"); });
    connect(folderHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("folder"); });
    connect(diskHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("disk"); });

    m_signalsConnected = true;
}

// ------------------------------------------------------------------
// File/folder encrypt/decrypt buttons, worker dispatch, and browse
// dialogs moved to src/mainwindow_fileops.cpp.
// ------------------------------------------------------------------


void MainWindow::checkHardwareAcceleration()
{
    bool supported = encryptionEngine.isHardwareAccelerationSupported();
    QString status = supported ? "Supported" : "Not supported";
    SECURE_LOG(DEBUG, "MainWindow", QString("Hardware Acceleration: %1").arg(status));
}

void MainWindow::on_benchmarkButton_clicked()
{
    ui->benchmarkTable->setRowCount(0); // Clear previous results
    SECURE_LOG(DEBUG, "MainWindow", "Running benchmark...");

    QStringList algorithms = {
        "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
        "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"};

    QStringList kdfs = {"Argon2", "Scrypt", "PBKDF2"};

    worker->setBenchmarkParameters(algorithms, kdfs);
    QMetaObject::invokeMethod(worker, "runBenchmark", Qt::QueuedConnection);
}

void MainWindow::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    if (s_logStream)
    {
        *s_logStream << msg << Qt::endl;
        QTextStream(stdout) << msg << Qt::endl;
    }
}

void MainWindow::updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf)
{
    SECURE_LOG(DEBUG, "MainWindow", QString("Update Benchmark Table: iterations=%1, mbps=%2, ms=%3, cipher=%4, kdf=%5")
             .arg(iterations).arg(mbps).arg(ms).arg(cipher).arg(kdf));
    int row = ui->benchmarkTable->rowCount();
    ui->benchmarkTable->insertRow(row);

    ui->benchmarkTable->setItem(row, 0, new QTableWidgetItem(QString::number(iterations)));
    ui->benchmarkTable->setItem(row, 1, new QTableWidgetItem(QString::number(mbps, 'f', 2)));
    ui->benchmarkTable->setItem(row, 2, new QTableWidgetItem(QString::number(ms, 'f', 2)));
    ui->benchmarkTable->setItem(row, 3, new QTableWidgetItem(cipher));
    ui->benchmarkTable->setItem(row, 4, new QTableWidgetItem(kdf));
}

void MainWindow::safeConnect(const QObject *sender, const char *signal, const QObject *receiver, const char *method)
{
    disconnect(sender, signal, receiver, method);                    // First disconnect any existing connection
    connect(sender, signal, receiver, method, Qt::UniqueConnection); // Then connect with UniqueConnection
}

bool MainWindow::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
        {
            if (obj == ui->filePasswordLineEdit || obj == ui->fileEncryptButton)
            {
                SECURE_LOG(DEBUG, "MainWindow", "Enter pressed for file encryption");
                ui->fileEncryptButton->click();
                return true;
            }
            else if (obj == ui->fileDecryptButton)
            {
                SECURE_LOG(DEBUG, "MainWindow", "Enter pressed for file decryption");
                ui->fileDecryptButton->click();
                return true;
            }
            else if (obj == ui->folderPasswordLineEdit || obj == ui->folderEncryptButton)
            {
                SECURE_LOG(DEBUG, "MainWindow", "Enter pressed for folder encryption");
                ui->folderEncryptButton->click();
                return true;
            }
            else if (obj == ui->folderDecryptButton)
            {
                SECURE_LOG(DEBUG, "MainWindow", "Enter pressed for folder decryption");
                ui->folderDecryptButton->click();
                return true;
            }
        }
    }
    return QObject::eventFilter(obj, event);
}

// ------------------------------------------------------------------
// Menu action slots moved to src/mainwindow_menu.cpp.
// applyTheme / loadPreferences / savePreferences moved to
//   src/mainwindow_preferences.cpp.
// ------------------------------------------------------------------


void MainWindow::setupSecurePasswordFields()
{
    // Configure password fields for security
    ui->filePasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->folderPasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->diskPasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->diskConfirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
    
    // Create password strength indicator labels
    QLabel* fileStrengthLabel = new QLabel(this);
    QLabel* folderStrengthLabel = new QLabel(this);
    QLabel* diskStrengthLabel = new QLabel(this);
    
    // Add labels to layouts
    ui->filePasswordLayout->addWidget(fileStrengthLabel);
    ui->folderPasswordLayout->addWidget(folderStrengthLabel);
    ui->standardVolumeLayout->addWidget(diskStrengthLabel);
    
    // Store references as member variables for later use
    filePasswordStrengthLabel = fileStrengthLabel;
    folderPasswordStrengthLabel = folderStrengthLabel;
    diskPasswordStrengthLabel = diskStrengthLabel;
    
    // Enable password strength indicators
    connect(ui->filePasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    connect(ui->folderPasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    connect(ui->diskPasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    
    // Set placeholder text with password recommendations
    QString pwdHint = "Enter strong password (min. 12 chars, mix of letters/numbers/symbols)";
    ui->filePasswordLineEdit->setPlaceholderText(pwdHint);
    ui->folderPasswordLineEdit->setPlaceholderText(pwdHint);
    ui->diskPasswordLineEdit->setPlaceholderText(pwdHint);
    ui->diskConfirmPasswordLineEdit->setPlaceholderText("Re-enter password to confirm");
    
    // Disable auto-completion for password fields
    ui->filePasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->folderPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->diskPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->diskConfirmPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    
    // Add "Show Password" checkboxes
    QCheckBox* showFilePassword = new QCheckBox("Show Password", this);
    ui->filePasswordLayout->addWidget(showFilePassword);
    connect(showFilePassword, &QCheckBox::toggled, [this](bool checked) {
        ui->filePasswordLineEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });
    
    QCheckBox* showFolderPassword = new QCheckBox("Show Password", this);
    ui->folderPasswordLayout->addWidget(showFolderPassword);
    connect(showFolderPassword, &QCheckBox::toggled, [this](bool checked) {
        ui->folderPasswordLineEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });
}

void MainWindow::checkPasswordStrength(const QString &password)
{
    // Get the sender object to determine which password field was updated
    QObject* sender = QObject::sender();
    if (!sender) return;
    
    QLabel* strengthLabel = nullptr;
    
    if (sender == ui->filePasswordLineEdit) {
        strengthLabel = filePasswordStrengthLabel;
    } else if (sender == ui->folderPasswordLineEdit) {
        strengthLabel = folderPasswordStrengthLabel;
    } else if (sender == ui->diskPasswordLineEdit) {
        strengthLabel = diskPasswordStrengthLabel;
    }
    
    if (!strengthLabel) return;
    
    // Calculate password strength
    int score = 0;
    
    // Length check (up to 5 points)
    score += qMin(5, password.length() / 2);
    
    // Complexity checks
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    
    for (const QChar &c : password) {
        if (c.isUpper()) hasUppercase = true;
        else if (c.isLower()) hasLowercase = true;
        else if (c.isDigit()) hasDigit = true;
        else if (c.isPunct() || c.isSymbol()) hasSpecial = true;
    }
    
    if (hasUppercase) score += 1;
    if (hasLowercase) score += 1;
    if (hasDigit) score += 2;
    if (hasSpecial) score += 3;
    
    // Set color and text based on score
    QString strengthText;
    QString colorStyle;
    
    if (password.isEmpty()) {
        strengthText = "";
        colorStyle = "";
    } else if (score < 6) {
        strengthText = "Very Weak";
        colorStyle = "color: #e74c3c;"; // Red
    } else if (score < 8) {
        strengthText = "Weak";
        colorStyle = "color: #e67e22;"; // Orange
    } else if (score < 10) {
        strengthText = "Moderate";
        colorStyle = "color: #f1c40f;"; // Yellow
    } else if (score < 12) {
        strengthText = "Strong";
        colorStyle = "color: #2ecc71;"; // Green
    } else {
        strengthText = "Very Strong";
        colorStyle = "color: #27ae60;"; // Dark Green
    }
    
    strengthLabel->setText(strengthText);
    strengthLabel->setStyleSheet(colorStyle);
}

void MainWindow::on_m_cryptoProviderComboBox_currentIndexChanged(const QString &providerName)
{
    if (!providerName.isEmpty())
    {
        encryptionEngine.setProvider(providerName);

        // Store current selections if possible
        QString currentFileAlgo = ui->fileAlgorithmComboBox->currentText();
        QString currentFolderAlgo = ui->folderAlgorithmComboBox->currentText();
        QString currentDiskAlgo = ui->diskAlgorithmComboBox->currentText();
        QString currentFileKDF = ui->kdfComboBox->currentText();
        QString currentFolderKDF = ui->folderKdfComboBox->currentText();
        QString currentDiskKDF = ui->diskKdfComboBox->currentText();

        // Update available algorithms and KDFs based on the selected provider
        QStringList algorithms = encryptionEngine.supportedCiphers();
        ui->fileAlgorithmComboBox->clear();
        ui->folderAlgorithmComboBox->clear();
        ui->diskAlgorithmComboBox->clear();
        ui->fileAlgorithmComboBox->addItems(algorithms);
        ui->folderAlgorithmComboBox->addItems(algorithms);
        ui->diskAlgorithmComboBox->addItems(algorithms);

        QStringList kdfs = encryptionEngine.supportedKDFs();
        ui->kdfComboBox->clear();
        ui->folderKdfComboBox->clear();
        ui->diskKdfComboBox->clear();
        ui->kdfComboBox->addItems(kdfs);
        ui->folderKdfComboBox->addItems(kdfs);
        ui->diskKdfComboBox->addItems(kdfs);

        // Try to restore previous selections if they're available in the new provider
        if (algorithms.contains(currentFileAlgo))
            ui->fileAlgorithmComboBox->setCurrentText(currentFileAlgo);

        if (algorithms.contains(currentFolderAlgo))
            ui->folderAlgorithmComboBox->setCurrentText(currentFolderAlgo);
            
        if (algorithms.contains(currentDiskAlgo))
            ui->diskAlgorithmComboBox->setCurrentText(currentDiskAlgo);

        if (kdfs.contains(currentFileKDF))
            ui->kdfComboBox->setCurrentText(currentFileKDF);

        if (kdfs.contains(currentFolderKDF))
            ui->folderKdfComboBox->setCurrentText(currentFolderKDF);
            
        if (kdfs.contains(currentDiskKDF))
            ui->diskKdfComboBox->setCurrentText(currentDiskKDF);

        // Update hardware acceleration status
        checkHardwareAcceleration();

        // Show provider capabilities in the status bar
        QString capabilitiesMessage = QString("Provider: %1 | Ciphers: %2 | KDFs: %3")
                                          .arg(providerName)
                                          .arg(algorithms.join(", "))
                                          .arg(kdfs.join(", "));

        statusBar()->showMessage(capabilitiesMessage, 5000);
    }
}

void MainWindow::showProviderCapabilities()
{
    QString providerName = encryptionEngine.currentProvider();
    if (providerName.isEmpty())
    {
        return;
    }

    QStringList algorithms = encryptionEngine.supportedCiphers();
    QStringList kdfs = encryptionEngine.supportedKDFs();

    QString message = QString(
                          "Current Crypto Provider: %1\n\n"
                          "Supported Ciphers:\n%2\n\n"
                          "Supported KDFs:\n%3\n\n"
                          "Hardware Acceleration: %4")
                          .arg(providerName)
                          .arg(algorithms.join(", "))
                          .arg(kdfs.join(", "))
                          .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::information(this, "Provider Capabilities", message);
}
