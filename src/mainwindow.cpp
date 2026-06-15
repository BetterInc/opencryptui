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
#include <QColor>
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
    connect(worker, &EncryptionWorker::benchmarkFinished, this, &MainWindow::onBenchmarkComplete);

    workerThread.start();

    // Initialize the benchmark table.
    // Column order reflects the tool's priorities: SECURITY first, then which
    // primitives, then speed last. Speed is a tiebreaker, never the headline —
    // and for KDFs a faster result is actively worse (lower attacker cost).
    ui->benchmarkTable->setColumnCount(6);
    // Columns separate the two things a user actually cares about:
    //   Speed  = bulk cipher throughput (KDF excluded) — higher is better
    //   Unlock = one-time KDF cost when opening a file
    //   Crack/s = attacker guess rate, CPU·GPU — lower is better (the security
    //             signal; GPU column reflects memory-hardness)
    QStringList headers = {"Security", "Cipher", "KDF", "Speed", "Unlock", "Crack/s (CPU·GPU)"};
    ui->benchmarkTable->setHorizontalHeaderLabels(headers);
    ui->benchmarkTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    if (auto* hdr = ui->benchmarkTable->horizontalHeaderItem(0)) {
        hdr->setToolTip(
            "Security tier (weakest link of cipher + KDF). This tool ranks by "
            "security, not speed:\n"
            "  • Cipher: AEAD 256-bit (AES-256-GCM, ChaCha20-Poly1305) is "
            "strongest; unauthenticated modes (CTR/CBC) and smaller keys rank "
            "lower; Camellia lowest.\n"
            "  • KDF: Argon2id (memory-hard) > Scrypt (memory-hard) > PBKDF2.\n"
            "Speed only breaks ties between equally-secure rows.");
    }
    if (auto* hdr = ui->benchmarkTable->horizontalHeaderItem(3)) {
        hdr->setToolTip("Bulk encryption throughput of the cipher (key "
                        "derivation excluded). Higher is better. This is the "
                        "'fast' that matters for big files.");
    }
    if (auto* hdr = ui->benchmarkTable->horizontalHeaderItem(4)) {
        hdr->setToolTip("One-time cost to derive the key when opening a file "
                        "(the KDF time). A fraction of a second for you, but "
                        "paid by an attacker on EVERY password guess.");
    }
    if (auto* hdr = ui->benchmarkTable->horizontalHeaderItem(5)) {
        hdr->setToolTip(
            "Password guesses per second an attacker gets — LOWER IS BETTER.\n"
            "  • CPU: one core (≈ 1000 / unlock-ms).\n"
            "  • GPU: rough estimate with a GPU/ASIC farm. Memory-hard KDFs "
            "(Argon2, Scrypt) barely speed up; PBKDF2 parallelizes almost for "
            "free, which is why its GPU rate explodes and it ranks Weak.");
    }

    // Enable sorting, then default to Security descending so the strongest
    // configuration sits at the top.
    ui->benchmarkTable->setSortingEnabled(true);
    ui->benchmarkTable->sortByColumn(0, Qt::DescendingOrder);
}

double MainWindow::gpuParallelismFactor(const QString &kdf)
{
    // Order-of-magnitude estimates of how many parallel guesses a GPU/ASIC
    // farm runs vs one CPU core, set by the KDF's per-guess memory cost.
    // These are deliberately rough (shown with "~") — the point is the gap
    // between memory-hard and non-memory-hard, not a precise figure.
    if (kdf.compare("Argon2", Qt::CaseInsensitive) == 0) return 4.0;        // 1 GiB/guess
    if (kdf.compare("Scrypt", Qt::CaseInsensitive) == 0) return 1000.0;     // ~16 MiB/guess
    return 10000000.0; // PBKDF2 / unknown: no memory cost → massively parallel
}

MainWindow::SecurityRating MainWindow::securityRatingFor(const QString &cipher, const QString &kdf)
{
    // Cipher tier — AEAD + key size + cipher maturity.
    //   3: 256-bit AEAD (authenticated, full key) — AES-256-GCM, ChaCha20-Poly1305
    //   2: smaller-key AEAD, OR 256-bit unauthenticated mode (relies on our
    //      Ed25519 tamper-evidence layer, not the cipher itself)
    //   1: smaller-key unauthenticated, or Camellia (far less cryptanalysis)
    int cipherTier;
    const bool isAead = cipher.contains("GCM") || cipher.compare("ChaCha20-Poly1305", Qt::CaseInsensitive) == 0;
    const bool is256  = cipher.contains("256") || cipher.compare("ChaCha20-Poly1305", Qt::CaseInsensitive) == 0;
    const bool isCamellia = cipher.startsWith("Camellia", Qt::CaseInsensitive);

    if (isCamellia) {
        cipherTier = 1;
    } else if (isAead && is256) {
        cipherTier = 3;
    } else if (isAead || is256) {
        cipherTier = 2;
    } else {
        cipherTier = 1;
    }

    // KDF tier — memory-hardness is what matters; speed is irrelevant here.
    int kdfTier;
    if (kdf.compare("Argon2", Qt::CaseInsensitive) == 0)      kdfTier = 3;
    else if (kdf.compare("Scrypt", Qt::CaseInsensitive) == 0) kdfTier = 2;
    else                                                       kdfTier = 1; // PBKDF2 / unknown

    // Weakest link: a strong cipher with a weak KDF is only as safe as the KDF.
    const int tier = qMin(cipherTier, kdfTier);

    QString label;
    QString stars;
    switch (tier) {
        case 3: label = "Strong"; stars = QString::fromUtf8("★★★"); break;
        case 2: label = "Good";   stars = QString::fromUtf8("★★☆"); break;
        default: label = "Weak";  stars = QString::fromUtf8("★☆☆"); break;
    }
    return { tier, label, stars };
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

    QStringList kdfs = {"Argon2", "Scrypt", "PBKDF2"};

    ui->kdfComboBox->addItems(kdfs);
    ui->folderKdfComboBox->addItems(kdfs);
    ui->diskKdfComboBox->addItems(kdfs);

    // Default to Argon2 (memory-hard, recommended)
    ui->kdfComboBox->setCurrentText("Argon2");
    ui->folderKdfComboBox->setCurrentText("Argon2");
    ui->diskKdfComboBox->setCurrentText("Argon2");

    // Wire each KDF combo to its iteration spinbox so the spinbox minimum
    // tracks the engine's per-KDF floor (Argon2=3, Scrypt=16384, PBKDF2=600000).
    // Without this the spinbox would let users type a sub-floor value the
    // engine refuses — the user-visible behavior would be a confusing error
    // dialog rather than a UI guard. With it: switching KDF instantly bumps
    // (or relaxes) the spinbox minimum, and Qt auto-clamps the current value
    // if it falls below the new minimum (visible jump — honest).
    connect(ui->kdfComboBox, &QComboBox::currentTextChanged, this,
            [this](const QString &k) { applyKdfIterationFloor(k, ui->iterationsSpinBox); });
    connect(ui->folderKdfComboBox, &QComboBox::currentTextChanged, this,
            [this](const QString &k) { applyKdfIterationFloor(k, ui->folderIterationsSpinBox); });
    connect(ui->diskKdfComboBox, &QComboBox::currentTextChanged, this,
            [this](const QString &k) { applyKdfIterationFloor(k, ui->diskIterationsSpinBox); });

    // Apply the floor immediately for the Argon2 default just selected above
    // (currentTextChanged may not have fired if Argon2 was already the index).
    applyKdfIterationFloor("Argon2", ui->iterationsSpinBox);
    applyKdfIterationFloor("Argon2", ui->folderIterationsSpinBox);
    applyKdfIterationFloor("Argon2", ui->diskIterationsSpinBox);

    ui->hmacCheckBox->setChecked(true);
    ui->folderHmacCheckBox->setChecked(true);
    ui->diskHmacCheckBox->setChecked(true);
}

void MainWindow::applyKdfIterationFloor(const QString &kdf, QSpinBox *spinBox)
{
    if (!spinBox) return;
    const int floor = EncryptionEngine::iterationFloorForKdf(kdf);

    // setMinimum auto-clamps current value if below the new minimum — that
    // shows the user the visible bump rather than silently changing it
    // behind their back at encrypt time.
    if (spinBox->maximum() < floor) {
        spinBox->setMaximum(floor);
    }
    spinBox->setMinimum(floor);

    QString tip;
    if (kdf == QLatin1String("Argon2")) {
        tip = QStringLiteral(
            "Argon2 time-cost (t parameter). Minimum 3 — Argon2 is memory-hard, "
            "so its security comes mostly from memory cost (1 GiB by default), "
            "not iteration count. 3 is the OWASP-recommended baseline.");
    } else if (kdf == QLatin1String("Scrypt")) {
        tip = QStringLiteral(
            "Scrypt opslimit (work factor). Minimum 2,097,152 — lands ~100 ms "
            "of real work; lower values (the old 16,384 floor computed in ~1 ms) "
            "offer no meaningful protection against GPU/ASIC brute-forcing.");
    } else if (kdf == QLatin1String("PBKDF2")) {
        tip = QStringLiteral(
            "PBKDF2 iteration count. Minimum 600,000 (OWASP 2023 for SHA-256/512). "
            "PBKDF2 has no memory-hardness, so a high iteration count is the only "
            "defence against brute-force.");
    } else {
        tip = QStringLiteral("Iteration count for the selected KDF.");
    }
    spinBox->setToolTip(tip);
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

    // Reset the recommendation banner for this run. No recommendation is
    // shown until benchmarkFinished fires (onBenchmarkComplete) — until then
    // only a provisional "best so far" line.
    m_benchRunning = true;
    m_benchRecTier = -1;
    m_benchRecMbps = -1.0;
    ui->benchmarkRecommendationLabel->setText(
        QStringLiteral("Benchmarking… finding the most secure + fast "
                       "configuration for this machine."));

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

namespace {
// QTableWidgetItem aliases Qt::EditRole onto Qt::DisplayRole — setData(EditRole,
// number) clobbers the visible text (that's the "3e+06" bug). So a hidden
// numeric sort key has to live in Qt::UserRole, which is NOT aliased, and we
// sort on it via a custom operator<. DisplayRole keeps the human-facing text.
class SortKeyItem : public QTableWidgetItem {
public:
    SortKeyItem(const QString& displayText, double sortKey) {
        setData(Qt::DisplayRole, displayText);
        setData(Qt::UserRole, sortKey);
    }
    bool operator<(const QTableWidgetItem& other) const override {
        return data(Qt::UserRole).toDouble() < other.data(Qt::UserRole).toDouble();
    }
};
// Human-friendly formatters for the benchmark cells.
static QString fmtSpeed(double mbps) {
    if (mbps >= 1024.0) return QString::number(mbps / 1024.0, 'f', 2) + " GB/s";
    if (mbps >= 10.0)   return QString::number(mbps, 'f', 0) + " MB/s";
    return QString::number(mbps, 'f', 1) + " MB/s";
}
static QString fmtUnlock(double ms) {
    if (ms >= 1000.0) return QString::number(ms / 1000.0, 'f', 2) + " s";
    return QString::number(ms, 'f', 0) + " ms";
}
static QString fmtRate(double r) {
    if (r >= 1.0e9) return "~" + QString::number(r / 1.0e9, 'f', 0) + "B";
    if (r >= 1.0e6) return "~" + QString::number(r / 1.0e6, 'f', 0) + "M";
    if (r >= 1.0e3) return "~" + QString::number(r / 1.0e3, 'f', 0) + "k";
    if (r >= 100.0) return QString::number(r, 'f', 0);
    return QString::number(r, 'f', 1);
}
} // namespace

void MainWindow::updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf)
{
    Q_UNUSED(iterations);
    SECURE_LOG(DEBUG, "MainWindow", QString("Update Benchmark Table: mbps=%1, kdfMs=%2, cipher=%3, kdf=%4")
             .arg(mbps).arg(ms).arg(cipher).arg(kdf));

    // Disable sorting while inserting: with sorting live, each setItem can
    // re-sort and move the partially-filled row out from under us, leaving
    // empty cells in the originally-targeted row.
    const bool wasSorting = ui->benchmarkTable->isSortingEnabled();
    ui->benchmarkTable->setSortingEnabled(false);

    int row = ui->benchmarkTable->rowCount();
    ui->benchmarkTable->insertRow(row);

    const SecurityRating rating = securityRatingFor(cipher, kdf);

    // Security cell. DisplayRole shows "★★★ Strong"; the sort key in UserRole
    // is composite (tier major, throughput minor) so the default sort orders
    // by security tier first and uses cipher speed only to break ties.
    auto* secItem = new SortKeyItem(QString("%1 %2").arg(rating.stars, rating.label),
                                    rating.tier * 1000000.0 + mbps);
    secItem->setToolTip(QString("Tier %1 of 3 — %2. Speed only breaks ties "
                                "between equally-secure rows.")
                            .arg(rating.tier).arg(rating.label));
    QColor tierColor = (rating.tier == 3) ? QColor(0x1b, 0x8a, 0x3a)
                     : (rating.tier == 2) ? QColor(0xb8, 0x7d, 0x00)
                                          : QColor(0xc0, 0x39, 0x2b);
    secItem->setForeground(tierColor);

    // Attacker rates (lower = better). CPU = one core; GPU = rough farm
    // estimate that folds in memory-hardness, so it orders the same way as the
    // security tier (Argon2 lowest → PBKDF2 highest).
    const double cpuRate = (ms > 0.0) ? (1000.0 / ms) : 0.0;
    const double gpuRate = cpuRate * gpuParallelismFactor(kdf);
    const QString crackText = QString("%1 · %2").arg(fmtRate(cpuRate), fmtRate(gpuRate));

    ui->benchmarkTable->setItem(row, 0, secItem);
    ui->benchmarkTable->setItem(row, 1, new QTableWidgetItem(cipher));
    ui->benchmarkTable->setItem(row, 2, new QTableWidgetItem(kdf));
    ui->benchmarkTable->setItem(row, 3, new SortKeyItem(fmtSpeed(mbps), mbps));
    ui->benchmarkTable->setItem(row, 4, new SortKeyItem(fmtUnlock(ms), ms));
    // Sort the crack column by the GPU rate — the real-world attacker number.
    ui->benchmarkTable->setItem(row, 5, new SortKeyItem(crackText, gpuRate));

    ui->benchmarkTable->setSortingEnabled(wasSorting);
    if (wasSorting) {
        ui->benchmarkTable->sortByColumn(0, Qt::DescendingOrder);
    }

    // ---- Track the best config so far: most secure, then fastest ---------
    // Pick the highest security tier seen; within it, the highest cipher speed.
    // We do NOT declare a final recommendation here — the run is still in
    // progress and a later combo could win. Only show a provisional
    // "best so far" line; onBenchmarkComplete() promotes it once every combo
    // has actually been measured.
    if (rating.tier > m_benchRecTier ||
        (rating.tier == m_benchRecTier && mbps > m_benchRecMbps)) {
        m_benchRecTier      = rating.tier;
        m_benchRecMbps      = mbps;
        m_benchRecCipher    = cipher;
        m_benchRecKdf       = kdf;
        m_benchRecTierLabel = rating.label;
        m_benchRecUnlockMs  = ms;
        m_benchRecGpuRate   = gpuRate;
    }

    if (m_benchRunning && m_benchRecTier > 0) {
        ui->benchmarkRecommendationLabel->setText(
            QString("Benchmarking… best so far: <b>%1 + %2</b> (%3). "
                    "Final recommendation when the run completes.")
                .arg(m_benchRecCipher, m_benchRecKdf, m_benchRecTierLabel));
    }
}

void MainWindow::onBenchmarkComplete()
{
    m_benchRunning = false;

    if (m_benchRecTier < 0) {
        ui->benchmarkRecommendationLabel->setText(
            QStringLiteral("Benchmark finished, but no configuration could be "
                           "measured on this machine."));
        return;
    }

    // Now that every combo has been measured, promote the winner to a real
    // recommendation: highest security tier, fastest cipher within it.
    ui->benchmarkRecommendationLabel->setText(
        QString("<b>✓ Recommended for this machine: %1 + %2</b><br/>"
                "%3 security · encrypts at <b>%4</b> · unlocks in %5 · "
                "attacker ≈ %6 guesses/s even with a GPU")
            .arg(m_benchRecCipher, m_benchRecKdf, m_benchRecTierLabel,
                 fmtSpeed(m_benchRecMbps), fmtUnlock(m_benchRecUnlockMs),
                 fmtRate(m_benchRecGpuRate)));
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

        // Re-apply the iteration floors after the KDF combos repopulated.
        // The currentTextChanged signals above may not fire if the resolved
        // selection happens to equal what the combo already showed.
        applyKdfIterationFloor(ui->kdfComboBox->currentText(), ui->iterationsSpinBox);
        applyKdfIterationFloor(ui->folderKdfComboBox->currentText(), ui->folderIterationsSpinBox);
        applyKdfIterationFloor(ui->diskKdfComboBox->currentText(), ui->diskIterationsSpinBox);

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
