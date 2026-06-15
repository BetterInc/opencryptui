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
    const QStringList kinds = {"File", "Folder", "Vault", "Disk"};
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
    note->setStyleSheet("color: #555; padding-top: 6px;");
    root->addWidget(note);
    root->addStretch(1);

    // Insert the Easy home at the top of the central layout, above the tabs.
    ui->verticalLayout->insertWidget(0, m_easyHome);

    // Advanced-mode toggle in the Edit menu (checkable).
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

    // Hide the crypto-provider row in Easy mode (advanced concept).
    if (ui->providerLayout) {
        for (int i = 0; i < ui->providerLayout->count(); ++i) {
            if (QWidget* w = ui->providerLayout->itemAt(i)->widget())
                w->setVisible(advanced);
        }
    }

    // Easy-home widgets that only apply to File/Folder.
    const bool inlineFields = !advanced && (m_easyKind == "File" || m_easyKind == "Folder");
    const bool vaultOrDisk  = !advanced && (m_easyKind == "Vault" || m_easyKind == "Disk");
    if (m_easyHome) {
        if (auto* pl = m_easyHome->findChild<QLabel*>("easyPathLabel")) {
            pl->setVisible(inlineFields);
            pl->setText(m_easyKind == "Folder" ? "Folder:" : "File:");
        }
        if (m_easyPath)     m_easyPath->setVisible(inlineFields);
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
