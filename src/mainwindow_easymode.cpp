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

    // Segmented choice: File / Folder / Vault / Disk.
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

    // Path row (File/Folder only).
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
        QString p = (m_easyKind == "Folder")
            ? QFileDialog::getExistingDirectory(this, "Choose a folder")
            : QFileDialog::getOpenFileName(this, "Choose a file");
        if (!p.isEmpty()) m_easyPath->setText(p);
    });

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
    enc->setStyleSheet("QPushButton{background:#1b8a3a;color:white;border:none;border-radius:4px;font-weight:bold;}"
                       " QPushButton:hover{background:#16732f;}");
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

    // ---- Remove features we no longer expose --------------------------------
    // Folder encryption (superseded by Vaults) and the crypto-provider row
    // (advanced, rarely needed). Engine paths remain for tests/compatibility.
    if (ui->folderTab) {
        const int fi = ui->tabWidget->indexOf(ui->folderTab);
        if (fi >= 0) ui->tabWidget->removeTab(fi);
    }
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
    const QString accent =
        "QPushButton{background:#1b8a3a;color:white;border:none;border-radius:4px;"
        "font-weight:bold;padding:8px;} QPushButton:hover{background:#16732f;}";
    if (ui->diskEncryptButton) ui->diskEncryptButton->setStyleSheet(accent);
    if (ui->fileEncryptButton) ui->fileEncryptButton->setStyleSheet(accent);

    // ---- Vault tab in Advanced mode (first-class, not just a menu item) -----
    {
        QWidget* vaultTab = new QWidget(ui->tabWidget);
        QVBoxLayout* v = new QVBoxLayout(vaultTab);
        v->setContentsMargins(16, 16, 16, 16); v->setSpacing(12);
        QLabel* vh = new QLabel("Encrypted Vaults", vaultTab);
        QFont vf = vh->font(); vf.setBold(true); vf.setPointSize(vf.pointSize() + 2); vh->setFont(vf);
        QLabel* vd = new QLabel(
            "A vault is a single encrypted container file you can keep anywhere, "
            "including on a USB stick. It can hold a hidden second volume for "
            "deniability, and its password can be split into key shares. Unlike "
            "encrypting a folder (which makes one .enc you must fully decrypt), a "
            "vault is fixed-size and can be mounted as a drive.", vaultTab);
        vd->setWordWrap(true);
        vd->setStyleSheet("color:#888;");
        QPushButton* createV = new QPushButton("Create Vault...", vaultTab);
        QPushButton* openV   = new QPushButton("Open Vault...", vaultTab);
        createV->setMinimumHeight(40); openV->setMinimumHeight(40);
        createV->setStyleSheet("QPushButton{background:#1b8a3a;color:white;border:none;border-radius:4px;font-weight:bold;}"
                               " QPushButton:hover{background:#16732f;}");
        connect(createV, &QPushButton::clicked, this, &MainWindow::on_actionCreateContainer_triggered);
        connect(openV,   &QPushButton::clicked, this, &MainWindow::on_actionOpenContainer_triggered);
        v->addWidget(vh); v->addWidget(vd); v->addSpacing(8);
        v->addWidget(createV); v->addWidget(openV); v->addStretch(1);

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

    // Easy-home widgets that only apply to File/Folder.
    const bool inlineFields = !advanced && (m_easyKind == "File" || m_easyKind == "Folder");
    const bool vaultOrDisk  = !advanced && (m_easyKind == "Vault" || m_easyKind == "Disk");
    if (m_easyHome) {
        if (auto* pl = m_easyHome->findChild<QLabel*>("easyPathLabel")) {
            pl->setVisible(inlineFields);
            pl->setText(m_easyKind == "Folder" ? "Folder:" : "File:");
        }
        if (m_easyPath)     m_easyPath->setVisible(inlineFields);
        if (auto* b = m_easyHome->findChild<QPushButton*>("easyBrowse")) b->setVisible(inlineFields);
        if (m_easyPassword) m_easyPassword->setVisible(inlineFields);
        if (m_easyConfirm)  m_easyConfirm->setVisible(inlineFields);
        if (auto* enc = m_easyHome->findChild<QPushButton*>("easyEncryptButton"))
            enc->setText(m_easyKind == "Vault" ? "Create Vault..."
                       : m_easyKind == "Disk"  ? "Open Disk Tools" : "Encrypt");
        if (auto* dec = m_easyHome->findChild<QPushButton*>("easyDecryptButton"))
            dec->setVisible(m_easyKind != "Disk"),
            dec->setText(m_easyKind == "Vault" ? "Open Vault..." : "Decrypt");
        if (auto* note = m_easyHome->findChild<QLabel*>("easyNote")) {
            if (m_easyKind == "Vault")
                note->setText("A vault is an encrypted container that can hold a "
                              "hidden second volume for deniability. Create one, or "
                              "open an existing vault.");
            else if (m_easyKind == "Disk")
                note->setText("Whole-disk and USB encryption are advanced and can "
                              "erase data. This opens the Advanced disk tools.");
            else
                note->setText("Your data is locked with strong, tamper-proof "
                              "encryption (AES-256 + Argon2). Only your password can "
                              "open it. Switch to Advanced mode for more options.");
        }
        Q_UNUSED(vaultOrDisk);
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
    if (m_easyKind == "Vault") { on_actionCreateContainer_triggered(); return; }
    if (m_easyKind == "Disk")  { applyUiMode(true); savePreferences();
        if (ui->tabWidget) ui->tabWidget->setCurrentIndex(0); return; }

    if (m_easyPath->text().isEmpty()) { QMessageBox::warning(this, "Choose a file", "Please choose a file or folder first."); return; }
    if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter a password."); return; }
    if (m_easyPassword->text() != m_easyConfirm->text()) { QMessageBox::warning(this, "Password", "The two passwords do not match."); return; }

    const bool isFile = (m_easyKind == "File");
    // Feed the existing (advanced) widgets with secure defaults, then call the
    // same tested slot the Advanced UI uses.
    if (isFile) {
        ui->filePathLineEdit->setText(m_easyPath->text());
        ui->filePasswordLineEdit->setText(m_easyPassword->text());
        ui->fileAlgorithmComboBox->setCurrentText(kEasyCipher);
        ui->kdfComboBox->setCurrentText(kEasyKdf);
        on_fileEncryptButton_clicked();
    } else {
        ui->folderPathLineEdit->setText(m_easyPath->text());
        ui->folderPasswordLineEdit->setText(m_easyPassword->text());
        ui->folderAlgorithmComboBox->setCurrentText(kEasyCipher);
        ui->folderKdfComboBox->setCurrentText(kEasyKdf);
        on_folderEncryptButton_clicked();
    }
}

void MainWindow::onEasyDecrypt()
{
    if (m_easyKind == "Vault") { on_actionOpenContainer_triggered(); return; }
    if (m_easyKind == "Disk")  return; // no decrypt button shown for Disk

    if (m_easyPath->text().isEmpty()) { QMessageBox::warning(this, "Choose a file", "Please choose the encrypted file or folder first."); return; }
    if (m_easyPassword->text().isEmpty()) { QMessageBox::warning(this, "Password", "Please enter your password."); return; }

    const bool isFile = (m_easyKind == "File");
    if (isFile) {
        ui->filePathLineEdit->setText(m_easyPath->text());
        ui->filePasswordLineEdit->setText(m_easyPassword->text());
        ui->fileAlgorithmComboBox->setCurrentText(kEasyCipher);
        ui->kdfComboBox->setCurrentText(kEasyKdf);
        on_fileDecryptButton_clicked();
    } else {
        ui->folderPathLineEdit->setText(m_easyPath->text());
        ui->folderPasswordLineEdit->setText(m_easyPassword->text());
        ui->folderAlgorithmComboBox->setCurrentText(kEasyCipher);
        ui->folderKdfComboBox->setCurrentText(kEasyKdf);
        on_folderDecryptButton_clicked();
    }
}
