// Vault (deniable encrypted container) GUI: create / open, reached from the
// Vault tab and the Easy-home "Vault" choice.
//
// The core logic (createContainerFromFiles / openContainerToFile) is factored
// out of the dialog handlers so it can be unit-tested without driving native
// file dialogs. The handlers just gather parameters from QDialogs and call the
// core, showing a live progress bar during the (slow) random-fill on create.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "deniable_container.h"
#include "encryptionengine.h"
#include "shamir.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressDialog>
#include <QApplication>
#include <QDialog>
#include <QFormLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QLabel>
#include <QVector>
#include <cmath>
#include <sodium.h>

static void wipe(QByteArray& b) { if (!b.isEmpty()) sodium_memzero(b.data(), b.size()); }

// ---------------------------------------------------------------------------
// Core (testable) logic - no dialogs, so a UI test can call it directly.
// ---------------------------------------------------------------------------
bool MainWindow::createContainerFromFiles(const QString& containerPath, qint64 sizeMiB,
                                          const QString& outerFile, const QString& outerPassword,
                                          const QString& hiddenFile, const QString& hiddenPassword,
                                          const QString& kdf, int iterations,
                                          QString* error,
                                          const std::function<void(int)>& progress)
{
    auto setErr = [&](const QString& m){ if (error) *error = m; return false; };

    auto readFile = [&](const QString& p, QByteArray& out) -> bool {
        if (p.isEmpty()) { out = QByteArray(); return true; } // empty volume allowed
        QFile f(p);
        if (!f.open(QIODevice::ReadOnly)) { if (error) *error = "Cannot read " + p; return false; }
        out = f.readAll();
        return true;
    };

    QByteArray outerData, hiddenData;
    if (!readFile(outerFile, outerData)) return false;
    const bool hasHidden = !hiddenPassword.isEmpty();
    if (hasHidden && !readFile(hiddenFile, hiddenData)) { wipe(outerData); return false; }

    const qint64 sizeBytes = sizeMiB * 1024 * 1024;
    const qint64 need = DeniableContainer::minSize(outerData.size(),
                                                   hasHidden ? hiddenData.size() : 0);
    if (sizeBytes < need) {
        wipe(outerData); wipe(hiddenData);
        return setErr(QString("Container too small: need at least %1 MiB for this data.")
                          .arg((need + 1024*1024 - 1) / (1024*1024)));
    }

    QString err;
    bool ok = DeniableContainer::create(encryptionEngine, containerPath, sizeBytes,
                                        outerPassword, outerData, kdf, iterations,
                                        hiddenPassword, hiddenData, &err, progress);
    wipe(outerData); wipe(hiddenData);
    if (!ok) return setErr(err);
    return true;
}

int MainWindow::openContainerToFile(const QString& containerPath, const QString& password,
                                    const QString& extractTo, const QString& kdf, int iterations,
                                    QString* error)
{
    auto r = DeniableContainer::open(encryptionEngine, containerPath, password, kdf, iterations);
    if (!r.ok) { if (error) *error = r.error; return 0; }

    QFile out(extractTo);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = "Cannot write " + extractTo;
        wipe(r.data);
        return 0;
    }
    out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner); // 0600
    bool wok = out.write(r.data) == r.data.size();
    out.close();
    const bool hidden = (r.kind == DeniableContainer::VolumeKind::Hidden);
    wipe(r.data);
    if (!wok) { if (error) *error = "Write failed."; return 0; }
    return hidden ? 2 : 1;
}

// ---------------------------------------------------------------------------
// Shamir password-share files
// ---------------------------------------------------------------------------
bool MainWindow::splitPasswordToShares(const QString& password, int n, int k,
                                       const QString& baseFilePath,
                                       QStringList* writtenFiles, QString* error)
{
    auto setErr = [&](const QString& m){ if (error) *error = m; return false; };
    QByteArray secret = password.toUtf8();
    Shamir::SplitResult sr = Shamir::split(secret, n, k);
    sodium_memzero(secret.data(), secret.size());
    if (!sr.ok) return setErr(sr.error);

    QStringList out;
    for (int i = 0; i < sr.shares.size(); ++i) {
        const QString path = QString("%1.%2.share").arg(baseFilePath).arg(i + 1);
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            for (const QString& w : out) QFile::remove(w); // roll back
            return setErr("Cannot write share file: " + path);
        }
        f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner); // 0600
        // Human-readable header + base64 share. The threshold is advisory text;
        // recovery succeeds once enough valid shares are supplied (checksum-verified).
        f.write(QString("# OpenCryptUI key share %1 of %2 (need %3 to recover)\n")
                    .arg(i + 1).arg(n).arg(k).toUtf8());
        f.write(sr.shares[i].toBase64());
        f.write("\n");
        f.close();
        out << path;
    }
    if (writtenFiles) *writtenFiles = out;
    return true;
}

bool MainWindow::recoverPasswordFromShares(const QStringList& shareFiles,
                                           QString* password, QString* error)
{
    auto setErr = [&](const QString& m){ if (error) *error = m; return false; };
    QVector<QByteArray> shares;
    for (const QString& path : shareFiles) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return setErr("Cannot read share file: " + path);
        // Take the last non-comment, non-empty line as the base64 share.
        QByteArray b64;
        for (const QByteArray& line : f.readAll().split('\n')) {
            const QByteArray t = line.trimmed();
            if (t.isEmpty() || t.startsWith('#')) continue;
            b64 = t;
        }
        f.close();
        QByteArray share = QByteArray::fromBase64(b64);
        if (share.isEmpty()) return setErr("Share file is empty or malformed: " + path);
        shares.append(share);
    }
    Shamir::CombineResult cr = Shamir::combine(shares);
    if (!cr.ok) return setErr(cr.error);
    if (password) *password = QString::fromUtf8(cr.secret);
    sodium_memzero(cr.secret.data(), cr.secret.size());
    return true;
}

// ---------------------------------------------------------------------------
// Helpers for the dialogs
// ---------------------------------------------------------------------------
// Build a "[lineedit] [Browse...]" row; returns the container widget and writes
// the QLineEdit* to *outEdit (avoids structured bindings, which can't be
// captured in lambdas under C++17).
static QWidget* makePathRow(QWidget* parent, MainWindow* win,
                            const QString& caption, bool save, QLineEdit** outEdit)
{
    QWidget* w = new QWidget(parent);
    QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
    QLineEdit* edit = new QLineEdit(w);
    QPushButton* btn = new QPushButton("Browse...", w);
    h->addWidget(edit); h->addWidget(btn);
    QObject::connect(btn, &QPushButton::clicked, w, [win, edit, caption, save]{
        QString f = save ? QFileDialog::getSaveFileName(win, caption)
                          : QFileDialog::getOpenFileName(win, caption);
        if (!f.isEmpty()) edit->setText(f);
    });
    *outEdit = edit;
    return w;
}


// ---------------------------------------------------------------------------
// Vault UI: capacity picker + inline Create/Open tab
// ---------------------------------------------------------------------------

// Friendly capacity picker: a value + unit (MB/GB/TB) plus one-tap presets, so
// 16 MB and 100 GB are equally quick to set. Writes the value spin and unit
// combo to *outVal / *outUnit; read the chosen size with sizeRowToMiB().
QWidget* MainWindow::makeSizeRow(QWidget* parent, QDoubleSpinBox** outVal, QComboBox** outUnit)
{
    QWidget* w = new QWidget(parent);
    QVBoxLayout* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(6);

    QHBoxLayout* row = new QHBoxLayout();
    QDoubleSpinBox* val = new QDoubleSpinBox(w);
    val->setObjectName("vaultSizeValue");
    val->setDecimals(0);
    val->setRange(1, 999999);
    val->setValue(16);
    QComboBox* unit = new QComboBox(w);
    unit->setObjectName("vaultSizeUnit");
    unit->addItems({"MB", "GB", "TB"});
    row->addWidget(val, 1);
    row->addWidget(unit);
    col->addLayout(row);

    // One-tap presets - the whole point is that you never count megabytes.
    QHBoxLayout* presets = new QHBoxLayout();
    presets->setSpacing(6);
    struct Preset { const char* label; double value; int unitIndex; };
    const QVector<Preset> chips = {
        {"16 MB", 16, 0}, {"256 MB", 256, 0}, {"1 GB", 1, 1}, {"10 GB", 10, 1}, {"100 GB", 100, 1}
    };
    for (const Preset& p : chips) {
        QPushButton* chip = new QPushButton(QString::fromLatin1(p.label), w);
        chip->setCursor(Qt::PointingHandCursor);
        chip->setStyleSheet("QPushButton{border:1px solid #888;border-radius:11px;padding:3px 12px;}"
                            " QPushButton:hover{background:#3a76d8;color:white;border-color:#3a76d8;}");
        QObject::connect(chip, &QPushButton::clicked, w, [val, unit, p]{
            val->setValue(p.value);
            unit->setCurrentIndex(p.unitIndex);
        });
        presets->addWidget(chip);
    }
    presets->addStretch(1);
    col->addLayout(presets);

    *outVal = val;
    *outUnit = unit;
    return w;
}

qint64 MainWindow::sizeRowToMiB(const QDoubleSpinBox* val, const QComboBox* unit)
{
    const double v = val->value();
    switch (unit->currentIndex()) {
        case 1:  return static_cast<qint64>(std::llround(v * 1024.0));          // GB
        case 2:  return static_cast<qint64>(std::llround(v * 1024.0 * 1024.0)); // TB
        default: return static_cast<qint64>(std::llround(v));                   // MB
    }
}

bool MainWindow::createVaultWithProgress(const QString& path, qint64 sizeMiB,
                                         const QString& outerFile, const QString& outerPw,
                                         const QString& hiddenFile, const QString& hiddenPw,
                                         QString* err)
{
    QProgressDialog prog("Creating vault...", QString(), 0, 100, this);
    prog.setWindowModality(Qt::WindowModal);
    prog.setMinimumDuration(0);
    prog.setValue(0);
    const bool ok = createContainerFromFiles(
        path, sizeMiB, outerFile, outerPw, hiddenFile, hiddenPw, "Argon2", 3, err,
        [&prog](int pct){ prog.setValue(pct); QApplication::processEvents(); });
    prog.setValue(100);
    return ok;
}

// The Advanced "Vault" tab: a full inline form (Create + Open), mirroring the
// File/Disk tabs instead of hiding everything behind a modal dialog.
QWidget* MainWindow::buildVaultTab()
{
    QWidget* page = new QWidget(ui->tabWidget);
    QVBoxLayout* outer = new QVBoxLayout(page);
    outer->setContentsMargins(16, 16, 16, 16);
    outer->setSpacing(12);

    QLabel* intro = new QLabel(
        "A vault is a single encrypted file you can keep anywhere, including on a "
        "USB stick. It can hold a hidden second volume for deniability, and its "
        "password can be split into key shares.", page);
    intro->setWordWrap(true);
    intro->setStyleSheet("color:#888;");
    outer->addWidget(intro);

    // ---- Create a vault ----------------------------------------------------
    QGroupBox* createBox = new QGroupBox("Create a vault", page);
    QFormLayout* cf = new QFormLayout(createBox);

    QLineEdit* cPath = nullptr;
    cf->addRow("Save vault as:", makePathRow(createBox, this, "Save vault as", true, &cPath));

    QDoubleSpinBox* sizeVal = nullptr; QComboBox* sizeUnit = nullptr;
    cf->addRow("Size:", makeSizeRow(createBox, &sizeVal, &sizeUnit));

    QLineEdit* outerFile = nullptr;
    cf->addRow("Store file (optional):", makePathRow(createBox, this, "File to store in the vault", false, &outerFile));

    QLineEdit* outerPw  = new QLineEdit(createBox); outerPw->setEchoMode(QLineEdit::Password);
    QLineEdit* outerPw2 = new QLineEdit(createBox); outerPw2->setEchoMode(QLineEdit::Password);
    cf->addRow("Password:", outerPw);
    cf->addRow("Confirm:", outerPw2);

    QCheckBox* useHidden = new QCheckBox("Add a hidden volume (deniable)", createBox);
    cf->addRow(useHidden);
    QLineEdit* hiddenFile = nullptr;
    QWidget* hiddenFileRow = makePathRow(createBox, this, "File to store in the hidden volume", false, &hiddenFile);
    QLineEdit* hiddenPw  = new QLineEdit(createBox); hiddenPw->setEchoMode(QLineEdit::Password);
    QLineEdit* hiddenPw2 = new QLineEdit(createBox); hiddenPw2->setEchoMode(QLineEdit::Password);
    QLabel* hfLabel = new QLabel("Hidden file:"); QLabel* hpLabel = new QLabel("Hidden password:"); QLabel* hp2Label = new QLabel("Confirm:");
    cf->addRow(hfLabel, hiddenFileRow);
    cf->addRow(hpLabel, hiddenPw);
    cf->addRow(hp2Label, hiddenPw2);
    auto setHiddenVisible = [=](bool v){
        hiddenFileRow->setVisible(v); hiddenPw->setVisible(v); hiddenPw2->setVisible(v);
        hfLabel->setVisible(v); hpLabel->setVisible(v); hp2Label->setVisible(v);
    };
    setHiddenVisible(false);
    connect(useHidden, &QCheckBox::toggled, this, setHiddenVisible);

    QCheckBox* useShares = new QCheckBox("Split the password into key shares (k of n)", createBox);
    cf->addRow(useShares);
    QSpinBox* nSpin = new QSpinBox(createBox); nSpin->setRange(2, 255); nSpin->setValue(5);
    QSpinBox* kSpin = new QSpinBox(createBox); kSpin->setRange(2, 255); kSpin->setValue(3);
    QLabel* nLabel = new QLabel("Total shares (n):"); QLabel* kLabel = new QLabel("Needed to recover (k):");
    cf->addRow(nLabel, nSpin); cf->addRow(kLabel, kSpin);
    auto setSharesVisible = [=](bool v){ nSpin->setVisible(v); kSpin->setVisible(v); nLabel->setVisible(v); kLabel->setVisible(v); };
    setSharesVisible(false);
    connect(useShares, &QCheckBox::toggled, this, setSharesVisible);

    QPushButton* createBtn = new QPushButton("Create vault", createBox);
    createBtn->setMinimumHeight(40);
    createBtn->setStyleSheet(
        "QPushButton{background:#1b8a3a;color:white;border:none;border-radius:4px;"
        "font-weight:bold;padding:8px;} QPushButton:hover{background:#16732f;}");
    cf->addRow(createBtn);

    connect(createBtn, &QPushButton::clicked, this, [=]{
        if (cPath->text().isEmpty()) { QMessageBox::warning(this, "Error", "Choose where to save the vault."); return; }
        if (outerPw->text() != outerPw2->text()) { QMessageBox::warning(this, "Error", "Outer passwords do not match."); return; }
        if (outerPw->text().isEmpty()) { QMessageBox::warning(this, "Error", "Enter an outer password."); return; }
        if (useHidden->isChecked()) {
            if (hiddenPw->text() != hiddenPw2->text()) { QMessageBox::warning(this, "Error", "Hidden passwords do not match."); return; }
            if (hiddenPw->text().isEmpty()) { QMessageBox::warning(this, "Error", "Enter a hidden password."); return; }
            if (hiddenPw->text() == outerPw->text()) { QMessageBox::warning(this, "Error", "Outer and hidden passwords must differ."); return; }
        }
        if (useShares->isChecked() && kSpin->value() > nSpin->value()) {
            QMessageBox::warning(this, "Error", "Key shares: k cannot exceed n."); return;
        }

        QString err;
        const bool ok = createVaultWithProgress(
            cPath->text(), sizeRowToMiB(sizeVal, sizeUnit),
            outerFile->text(), outerPw->text(),
            useHidden->isChecked() ? hiddenFile->text() : QString(),
            useHidden->isChecked() ? hiddenPw->text() : QString(), &err);
        if (!ok) { QMessageBox::critical(this, "Create failed", err); return; }

        QString shareMsg;
        if (useShares->isChecked()) {
            QStringList written; QString serr;
            if (splitPasswordToShares(outerPw->text(), nSpin->value(), kSpin->value(),
                                      cPath->text(), &written, &serr)) {
                shareMsg = QString("\n\nOuter password split into %1 share files (any %2 recover it):\n%3")
                               .arg(written.size()).arg(kSpin->value()).arg(written.join("\n"));
            } else {
                QMessageBox::warning(this, "Shares", "Could not write key shares: " + serr);
            }
        }
        QMessageBox::information(this, "Vault created",
            "Vault created.\n\nThe outer password opens the decoy volume; "
            "the hidden password (if set) opens the real one. The two are "
            "indistinguishable without the hidden password." + shareMsg);
    });

    outer->addWidget(createBox);

    // ---- Open a vault ------------------------------------------------------
    QGroupBox* openBox = new QGroupBox("Open a vault", page);
    QFormLayout* of = new QFormLayout(openBox);

    QLineEdit* oPath = nullptr;
    of->addRow("Vault file:", makePathRow(openBox, this, "Open vault", false, &oPath));

    QLineEdit* openPw = new QLineEdit(openBox); openPw->setEchoMode(QLineEdit::Password);
    QWidget* pwRow = new QWidget(openBox); QHBoxLayout* pwh = new QHBoxLayout(pwRow); pwh->setContentsMargins(0,0,0,0);
    QPushButton* fromShares = new QPushButton("From shares...", pwRow);
    pwh->addWidget(openPw); pwh->addWidget(fromShares);
    of->addRow("Password:", pwRow);
    connect(fromShares, &QPushButton::clicked, this, [this, openPw]{
        QStringList files = QFileDialog::getOpenFileNames(this, "Select key share files (need k)",
                                                          QString(), "Key shares (*.share);;All files (*)");
        if (files.isEmpty()) return;
        QString recovered, rerr;
        if (recoverPasswordFromShares(files, &recovered, &rerr)) {
            openPw->setText(recovered);
            QMessageBox::information(this, "Shares", QString("Recovered the password from %1 shares.").arg(files.size()));
        } else {
            QMessageBox::warning(this, "Shares", "Could not recover: " + rerr);
        }
    });

    QLineEdit* extractEdit = nullptr;
    of->addRow("Extract to:", makePathRow(openBox, this, "Extract contents to", true, &extractEdit));

    QPushButton* openBtn = new QPushButton("Open vault", openBox);
    openBtn->setMinimumHeight(40);
    of->addRow(openBtn);
    connect(openBtn, &QPushButton::clicked, this, [=]{
        if (oPath->text().isEmpty()) { QMessageBox::warning(this, "Error", "Choose the vault file to open."); return; }
        if (openPw->text().isEmpty() || extractEdit->text().isEmpty()) {
            QMessageBox::warning(this, "Error", "Enter a password and an extract path."); return;
        }
        QString err;
        const int kind = openContainerToFile(oPath->text(), openPw->text(), extractEdit->text(), "Argon2", 3, &err);
        if (kind == 0) { QMessageBox::critical(this, "Open failed", err); return; }
        QMessageBox::information(this, "Vault opened",
            QString("%1 volume extracted to:\n%2").arg(kind == 2 ? "Hidden" : "Outer").arg(extractEdit->text()));
    });

    outer->addWidget(openBox);
    outer->addStretch(1);

    // Scroll so the stacked group boxes get full height on short windows.
    QScrollArea* sa = new QScrollArea(ui->tabWidget);
    sa->setWidgetResizable(true);
    sa->setFrameShape(QFrame::NoFrame);
    sa->setWidget(page);
    return sa;
}
