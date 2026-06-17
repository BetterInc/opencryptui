// Easy/Advanced UI: a simple "home" for everyday users plus a toggle to the
// full tabbed interface. The Easy home does not duplicate any crypto logic --
// it fills in the existing (advanced) tab widgets with secure defaults and
// calls the same tested encrypt/decrypt slots, so behaviour is identical.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "logging/secure_logger.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QButtonGroup>
#include <QFileDialog>
#include <QMessageBox>
#include <QAction>
#include <QMenu>
#include <QFont>
#include <QStatusBar>
#include <QScrollArea>
#include <QTabWidget>

// Wrap a tab page's existing content in a scroll area so its stacked group
// boxes get their natural height (and scroll if the window is short) instead
// of collapsing into overlapping slivers. Moves the page's current layout into
// a content widget held by the scroll area.
static void wrapTabInScrollArea(QWidget* page)
{
    if (!page || !page->layout()) return;
    QLayout* inner = page->layout();
    QWidget* content = new QWidget();
    content->setLayout(inner);                 // reparents inner + its children
    QScrollArea* sa = new QScrollArea(page);
    sa->setWidgetResizable(true);
    sa->setFrameShape(QFrame::NoFrame);
    sa->setWidget(content);
    QVBoxLayout* pl = new QVBoxLayout(page);    // page now has no layout; set new
    pl->setContentsMargins(0, 0, 0, 0);
    pl->addWidget(sa);
}

// Secure defaults chosen for Easy mode (shown to the user, never hidden).
static const char* kEasyCipher = "AES-256-GCM";
static const char* kEasyKdf    = "Argon2";

// Accent style for the primary action (Encrypt / Create Vault), used app-wide
// so the main action is visually obvious. Decrypt/Open keep the neutral default.
static const char* kAccentButtonQss =
    "QPushButton{background:#1b8a3a;color:white;border:none;border-radius:4px;"
    "font-weight:bold;padding:8px;} QPushButton:hover{background:#16732f;}";

void MainWindow::buildEasyHome()
{
    if (m_easyHome) return;
    m_easyHome = new QWidget(this);
    m_easyHome->setObjectName("easyHome");
    QVBoxLayout* root = new QVBoxLayout(m_easyHome);
    root->setSpacing(12);
    root->setContentsMargins(24, 20, 24, 20);

    QLabel* title = new QLabel("What do you want to protect?", m_easyHome);
    QFont tf = title->font(); tf.setPointSize(tf.pointSize() + 4); tf.setBold(true);
    title->setFont(tf);
    root->addWidget(title);

    // Segmented choice: File / Vault / Disk.
    QHBoxLayout* seg = new QHBoxLayout();
    QButtonGroup* group = new QButtonGroup(m_easyHome);
    group->setExclusive(true);
    const QStringList kinds = {"File", "Vault", "Disk"};
    for (const QString& kind : kinds) {
        QPushButton* b = new QPushButton(kind, m_easyHome);
        b->setCheckable(true);
        b->setMinimumHeight(40);
        if (kind == "File") b->setChecked(true);
        group->addButton(b);
        seg->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, kind]{ m_easyKind = kind; applyUiMode(false); });
    }
    root->addLayout(seg);

    // Path row (used by File and Vault; Disk drives its own tab).
    QHBoxLayout* pathRow = new QHBoxLayout();
    QLabel* pathLabel = new QLabel("File:", m_easyHome);
    pathLabel->setObjectName("easyPathLabel");
    m_easyPath = new QLineEdit(m_easyHome);
    m_easyPath->setObjectName("easyPath");
    m_easyPath->setPlaceholderText("Choose a file to protect");
    QPushButton* browse = new QPushButton("Browse...", m_easyHome);
    browse->setObjectName("easyBrowse");
    pathRow->addWidget(pathLabel); pathRow->addWidget(m_easyPath); pathRow->addWidget(browse);
    root->addLayout(pathRow);
    connect(browse, &QPushButton::clicked, this, [this]{
        // For a vault the path is where to *save* the new file; for a plain file
        // it is the existing file to protect.
        QString p = (m_easyKind == "Vault")
            ? QFileDialog::getSaveFileName(this, "Save vault as")
            : QFileDialog::getOpenFileName(this, "Choose a file");
        if (!p.isEmpty()) m_easyPath->setText(p);
    });

    // Vault size picker (Easy mode shows it only for the Vault kind).
    QLabel* sizeLabel = new QLabel("Vault size:", m_easyHome);
    sizeLabel->setObjectName("easySizeLabel");
    QWidget* sizeRow = makeSizeRow(m_easyHome, &m_easySizeVal, &m_easySizeUnit);
    sizeRow->setObjectName("easySizeRow");
    root->addWidget(sizeLabel);
    root->addWidget(sizeRow);

    // Password + confirm.
    m_easyPassword = new QLineEdit(m_easyHome); m_easyPassword->setEchoMode(QLineEdit::Password);
    m_easyPassword->setObjectName("easyPassword");
    m_easyPassword->setPlaceholderText("Password (16+ characters recommended)");
    m_easyConfirm = new QLineEdit(m_easyHome); m_easyConfirm->setEchoMode(QLineEdit::Password);
    m_easyConfirm->setPlaceholderText("Confirm password");
    m_easyConfirm->setObjectName("easyConfirm");
    root->addWidget(m_easyPassword);
    root->addWidget(m_easyConfirm);

    // Action buttons.
    QHBoxLayout* actions = new QHBoxLayout();
    QPushButton* enc = new QPushButton("Encrypt", m_easyHome);
    QPushButton* dec = new QPushButton("Decrypt", m_easyHome);
    enc->setMinimumHeight(44); dec->setMinimumHeight(44);
    enc->setObjectName("easyEncryptButton"); dec->setObjectName("easyDecryptButton");
    // Primary action (Encrypt) gets an accent so the hierarchy is obvious;
    // Decrypt stays the default style.
    enc->setStyleSheet(kAccentButtonQss);
    actions->addWidget(enc); actions->addWidget(dec);
    root->addLayout(actions);
    connect(enc, &QPushButton::clicked, this, &MainWindow::onEasyEncrypt);
    connect(dec, &QPushButton::clicked, this, &MainWindow::onEasyDecrypt);

    // Plain-language status of what protection is applied.
    QLabel* note = new QLabel(m_easyHome);
    note->setObjectName("easyNote");
    note->setWordWrap(true);
    note->setText("Your data is locked with strong, tamper-proof encryption "
                  "(AES-256 + Argon2). Only your password can open it. "
                  "Switch to Advanced mode (Edit menu) to change ciphers, add a "
                  "key file, or split your password into shares.");
    note->setStyleSheet("color: #888; padding-top: 6px;");
    root->addWidget(note);
    root->addStretch(1);

    // Insert the Easy home at the top of the central layout, above the tabs.
    ui->verticalLayout->insertWidget(0, m_easyHome);

    // ---- Persistent header bar with an always-visible mode switch ----------
    // The switch used to live only in the Edit menu (undiscoverable). Now it's
    // a labeled segmented toggle at the top-right, visible in both modes, so a
    // user can move between Easy and Advanced in one obvious click.
    QWidget* header = new QWidget(this);
    header->setObjectName("appHeader");
    QHBoxLayout* hb = new QHBoxLayout(header);
    hb->setContentsMargins(12, 6, 12, 6);

    QLabel* appName = new QLabel("OpenCryptUI", header);
    QFont nf = appName->font(); nf.setBold(true); appName->setFont(nf);
    hb->addWidget(appName);
    hb->addStretch(1);

    QLabel* modeLabel = new QLabel("Mode:", header);
    hb->addWidget(modeLabel);
    QPushButton* easyBtn = new QPushButton("Easy", header);
    QPushButton* advBtn  = new QPushButton("Advanced", header);
    easyBtn->setObjectName("modeEasyButton");
    advBtn->setObjectName("modeAdvancedButton");
    easyBtn->setCheckable(true); advBtn->setCheckable(true);
    easyBtn->setChecked(true);
    QButtonGroup* modeGroup = new QButtonGroup(header);
    modeGroup->setExclusive(true);
    modeGroup->addButton(easyBtn); modeGroup->addButton(advBtn);
    // Joined segmented look.
    easyBtn->setStyleSheet("QPushButton{border:1px solid #888;border-right:none;border-top-left-radius:4px;border-bottom-left-radius:4px;padding:4px 14px;} QPushButton:checked{background:#3a76d8;color:white;}");
    advBtn->setStyleSheet("QPushButton{border:1px solid #888;border-top-right-radius:4px;border-bottom-right-radius:4px;padding:4px 14px;} QPushButton:checked{background:#3a76d8;color:white;}");
    hb->addWidget(easyBtn); hb->addWidget(advBtn);
    connect(easyBtn, &QPushButton::clicked, this, [this]{ applyUiMode(false); savePreferences(); });
    connect(advBtn,  &QPushButton::clicked, this, [this]{ applyUiMode(true);  savePreferences(); });

    // Help button with a discoverable menu of the key actions.
    QPushButton* helpBtn = new QPushButton("Help", header);
    helpBtn->setObjectName("helpButton");
    QMenu* helpMenu = new QMenu(helpBtn);
    // (Vault create/open live in the Vault tab now, not here.)
    helpMenu->addAction("Security Guide",  this, &MainWindow::on_actionSecurityGuide_triggered);
    helpMenu->addAction("About",           this, &MainWindow::on_actionAbout_triggered);
    helpBtn->setMenu(helpMenu);
    hb->addSpacing(12);
    hb->addWidget(helpBtn);

    ui->verticalLayout->insertWidget(0, header); // very top, above Easy home + tabs

    // ---- Hide the crypto-provider row (advanced, rarely needed) -------------
    // Folder encryption was removed entirely; Vaults supersede it. The
    // provider combobox stays in the widget tree (tests drive it) but is hidden.
    if (ui->providerLayout) {
        for (int i = 0; i < ui->providerLayout->count(); ++i)
            if (QWidget* w = ui->providerLayout->itemAt(i)->widget())
                w->setVisible(false);
    }

    // Fix the Disk/File settings tabs collapsing: give them scroll areas so the
    // stacked group boxes get full height at any window size.
    wrapTabInScrollArea(ui->diskTab);
    wrapTabInScrollArea(ui->fileTab);

    // Make the Advanced primary actions match the Easy "Encrypt" accent so the
    // primary action is obvious app-wide; Decrypt stays neutral.
    if (ui->diskEncryptButton) ui->diskEncryptButton->setStyleSheet(kAccentButtonQss);
    if (ui->fileEncryptButton) ui->fileEncryptButton->setStyleSheet(kAccentButtonQss);

    // ---- Vault tab in Advanced mode: full inline Create/Open form ----------
    {
        QWidget* vaultTab = buildVaultTab();
        const int benchIdx = ui->tabWidget->indexOf(ui->benchmarkTab);
        if (benchIdx >= 0) ui->tabWidget->insertTab(benchIdx, vaultTab, "Vault");
        else               ui->tabWidget->addTab(vaultTab, "Vault");
    }

    // Keep a checkable Edit-menu entry too (muscle memory / accessibility),
    // synced with the header toggle.
    m_advancedModeAction = new QAction("Advanced mode", this);
    m_advancedModeAction->setObjectName("advancedModeAction");
    m_advancedModeAction->setCheckable(true);
    if (ui->menuEdit) ui->menuEdit->addAction(m_advancedModeAction);
    connect(m_advancedModeAction, &QAction::toggled, this, [this](bool on){
        applyUiMode(on);
        savePreferences();
    });
}

void MainWindow::applyUiMode(bool advanced)
{
    m_advancedMode = advanced;

    if (m_easyHome) m_easyHome->setVisible(!advanced);
    if (ui->tabWidget) ui->tabWidget->setVisible(advanced);

    // The bottom status bar shows the provider/cipher line - advanced info that
    // just clutters the Easy home. Show it only in Advanced mode.
    if (statusBar()) statusBar()->setVisible(advanced);

    // (The crypto-provider row is removed entirely in buildEasyHome.)

    // Easy-home path/password fields are shown for File and Vault; the size
    // picker only for Vault. Disk just hands off to the Advanced disk tab.
    const bool isVault       = m_easyKind == "Vault";
    const bool inlineFields  = !advanced && (m_easyKind == "File" || isVault);
    const bool showSize      = !advanced && isVault;
    if (m_easyHome) {
        if (auto* pl = m_easyHome->findChild<QLabel*>("easyPathLabel")) {
            pl->setVisible(inlineFields);
            pl->setText(isVault ? "Save vault as:" : "File:");
        }
        if (m_easyPath) {
            m_easyPath->setVisible(inlineFields);
            m_easyPath->setPlaceholderText(isVault ? "Where to save the new vault"
                                                   : "Choose a file to protect");
        }
        if (auto* b = m_easyHome->findChild<QPushButton*>("easyBrowse")) b->setVisible(inlineFields);
        if (auto* sl = m_easyHome->findChild<QLabel*>("easySizeLabel")) sl->setVisible(showSize);
        if (auto* sr = m_easyHome->findChild<QWidget*>("easySizeRow"))   sr->setVisible(showSize);
        if (m_easyPassword) m_easyPassword->setVisible(inlineFields);
        if (m_easyConfirm)  m_easyConfirm->setVisible(inlineFields);
        if (auto* enc = m_easyHome->findChild<QPushButton*>("easyEncryptButton"))
            enc->setText(isVault ? "Create vault"
                       : m_easyKind == "Disk" ? "Open Disk Tools" : "Encrypt");
        if (auto* dec = m_easyHome->findChild<QPushButton*>("easyDecryptButton")) {
            dec->setVisible(m_easyKind != "Disk");
            dec->setText(isVault ? "Open a vault" : "Decrypt");
        }
        if (auto* note = m_easyHome->findChild<QLabel*>("easyNote")) {
            if (isVault)
                note->setText("A vault is a single encrypted file that can hold a "
                              "hidden second volume for deniability. Pick a size and "
                              "password to create one, or open an existing vault. "
                              "Switch to Advanced mode for decoy files and key shares.");
            else if (m_easyKind == "Disk")
                note->setText("Whole-disk and USB encryption are advanced and can "
                              "erase data. This opens the Advanced disk tools.");
            else
                note->setText("Your data is locked with strong, tamper-proof "
                              "encryption (AES-256 + Argon2). Only your password can "
                              "open it. Switch to Advanced mode for more options.");
        }
    }

    if (m_advancedModeAction && m_advancedModeAction->isChecked() != advanced) {
        QSignalBlocker block(m_advancedModeAction);
        m_advancedModeAction->setChecked(advanced);
    }
    // Keep the header segmented toggle in sync (e.g. when mode is set from the
    // menu, from preferences load, or programmatically).
    if (auto* eb = findChild<QPushButton*>("modeEasyButton")) {
        QSignalBlocker b(eb); eb->setChecked(!advanced);
    }
    if (auto* ab = findChild<QPushButton*>("modeAdvancedButton")) {
        QSignalBlocker b(ab); ab->setChecked(advanced);
    }
}

void MainWindow::onEasyEncrypt()
{
    if (m_easyKind == "Vault") {
        // Easy vault = save location + size + password. The full options
        // (decoy file, hidden volume, key shares) live in the Advanced tab.
        if (m_easyPath->text().isEmpty()) { QMessageBox::warning(this, "Save vault", "Choose where to save the vault."); return; }
        if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter a password."); return; }
        if (m_easyPassword->text() != m_easyConfirm->text()) { QMessageBox::warning(this, "Password", "The two passwords do not match."); return; }
        QString err;
        const bool ok = createVaultWithProgress(m_easyPath->text(),
                                                sizeRowToMiB(m_easySizeVal, m_easySizeUnit),
                                                QString(), m_easyPassword->text(),
                                                QString(), QString(), &err);
        if (!ok) { QMessageBox::critical(this, "Create failed", err); return; }
        QMessageBox::information(this, "Vault created",
            "Vault created. Open it with your password to read or add files.");
        return;
    }
    if (m_easyKind == "Disk")  { applyUiMode(true); savePreferences();
        if (ui->tabWidget) ui->tabWidget->setCurrentIndex(0); return; }

    if (m_easyPath->text().isEmpty()) { QMessageBox::warning(this, "Choose a file", "Please choose a file first."); return; }
    if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter a password."); return; }
    if (m_easyPassword->text() != m_easyConfirm->text()) { QMessageBox::warning(this, "Password", "The two passwords do not match."); return; }

    // Feed the existing (advanced) File widgets with secure defaults, then call
    // the same tested slot the Advanced UI uses.
    ui->filePathLineEdit->setText(m_easyPath->text());
    ui->filePasswordLineEdit->setText(m_easyPassword->text());
    ui->fileAlgorithmComboBox->setCurrentText(kEasyCipher);
    ui->kdfComboBox->setCurrentText(kEasyKdf);
    on_fileEncryptButton_clicked();
}

void MainWindow::onEasyDecrypt()
{
    if (m_easyKind == "Vault") {
        // Open: pick the vault, use the typed password, pick where to extract.
        const QString vault = QFileDialog::getOpenFileName(this, "Open vault");
        if (vault.isEmpty()) return;
        if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter your password."); return; }
        const QString dest = QFileDialog::getSaveFileName(this, "Extract vault contents to");
        if (dest.isEmpty()) return;
        QString err;
        const int kind = openContainerToFile(vault, m_easyPassword->text(), dest, "Argon2", 3, &err);
        if (kind == 0) { QMessageBox::critical(this, "Open failed", err); return; }
        QMessageBox::information(this, "Vault opened",
            QString("%1 volume extracted to:\n%2").arg(kind == 2 ? "Hidden" : "Outer").arg(dest));
        return;
    }
    if (m_easyKind == "Disk")  return; // no decrypt button shown for Disk

    if (m_easyPath->text().isEmpty()) { QMessageBox::warning(this, "Choose a file", "Please choose the encrypted file first."); return; }
    if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter your password."); return; }

    ui->filePathLineEdit->setText(m_easyPath->text());
    ui->filePasswordLineEdit->setText(m_easyPassword->text());
    ui->fileAlgorithmComboBox->setCurrentText(kEasyCipher);
    ui->kdfComboBox->setCurrentText(kEasyKdf);
    on_fileDecryptButton_clicked();
}
