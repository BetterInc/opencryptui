// Deniable encrypted container GUI: create / open from the File menu.
//
// The core logic (createContainerFromFiles / openContainerToFile) is factored
// out of the dialog slots so it can be unit-tested without driving native file
// dialogs. The slots just gather parameters from QDialogs and call the core,
// showing a live progress bar during the (slow) random-fill on create.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "deniable_container.h"
#include "encryptionengine.h"
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
#include <QCheckBox>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <sodium.h>

static void wipe(QByteArray& b) { if (!b.isEmpty()) sodium_memzero(b.data(), b.size()); }

// ---------------------------------------------------------------------------
// Core (testable) logic — no dialogs, so a UI test can call it directly.
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
// Helpers for the dialogs
// ---------------------------------------------------------------------------
// Build a "[lineedit] [Browse…]" row; returns the container widget and writes
// the QLineEdit* to *outEdit (avoids structured bindings, which can't be
// captured in lambdas under C++17).
static QWidget* makePathRow(QWidget* parent, MainWindow* win,
                            const QString& caption, bool save, QLineEdit** outEdit)
{
    QWidget* w = new QWidget(parent);
    QHBoxLayout* h = new QHBoxLayout(w); h->setContentsMargins(0,0,0,0);
    QLineEdit* edit = new QLineEdit(w);
    QPushButton* btn = new QPushButton("Browse…", w);
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
// Dialog slots
// ---------------------------------------------------------------------------
void MainWindow::on_actionCreateContainer_triggered()
{
    QDialog dlg(this);
    dlg.setWindowTitle("Create Encrypted Container");
    QFormLayout* form = new QFormLayout(&dlg);

    QLineEdit* containerEdit = nullptr;
    form->addRow("Container file:", makePathRow(&dlg, this, "Container file", true, &containerEdit));

    QSpinBox* sizeSpin = new QSpinBox(&dlg);
    sizeSpin->setRange(1, 1024*1024); sizeSpin->setValue(16); sizeSpin->setSuffix(" MiB");
    form->addRow("Size:", sizeSpin);

    QLineEdit* outerFileEdit = nullptr;
    form->addRow("Outer (decoy) file:", makePathRow(&dlg, this, "Outer file to store", false, &outerFileEdit));
    QLineEdit* outerPw  = new QLineEdit(&dlg); outerPw->setEchoMode(QLineEdit::Password);
    QLineEdit* outerPw2 = new QLineEdit(&dlg); outerPw2->setEchoMode(QLineEdit::Password);
    form->addRow("Outer password:", outerPw);
    form->addRow("Confirm:", outerPw2);

    QCheckBox* useHidden = new QCheckBox("Add a hidden volume (deniable)", &dlg);
    form->addRow(useHidden);
    QLineEdit* hiddenFileEdit = nullptr;
    QWidget* hiddenFileRow = makePathRow(&dlg, this, "Hidden file to store", false, &hiddenFileEdit);
    QLineEdit* hiddenPw  = new QLineEdit(&dlg); hiddenPw->setEchoMode(QLineEdit::Password);
    QLineEdit* hiddenPw2 = new QLineEdit(&dlg); hiddenPw2->setEchoMode(QLineEdit::Password);
    QLabel* hfLabel = new QLabel("Hidden file:");
    QLabel* hpLabel = new QLabel("Hidden password:");
    QLabel* hp2Label = new QLabel("Confirm:");
    form->addRow(hfLabel, hiddenFileRow);
    form->addRow(hpLabel, hiddenPw);
    form->addRow(hp2Label, hiddenPw2);
    auto setHiddenVisible = [=](bool v){
        hiddenFileRow->setVisible(v); hiddenPw->setVisible(v); hiddenPw2->setVisible(v);
        hfLabel->setVisible(v); hpLabel->setVisible(v); hp2Label->setVisible(v);
    };
    setHiddenVisible(false);
    connect(useHidden, &QCheckBox::toggled, &dlg, [=, &dlg](bool v){ setHiddenVisible(v); dlg.adjustSize(); });

    QDialogButtonBox* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(bb);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) return;

    if (containerEdit->text().isEmpty()) { QMessageBox::warning(this, "Error", "Choose a container file."); return; }
    if (outerPw->text() != outerPw2->text()) { QMessageBox::warning(this, "Error", "Outer passwords do not match."); return; }
    if (outerPw->text().isEmpty()) { QMessageBox::warning(this, "Error", "Enter an outer password."); return; }
    if (useHidden->isChecked()) {
        if (hiddenPw->text() != hiddenPw2->text()) { QMessageBox::warning(this, "Error", "Hidden passwords do not match."); return; }
        if (hiddenPw->text().isEmpty()) { QMessageBox::warning(this, "Error", "Enter a hidden password."); return; }
        if (hiddenPw->text() == outerPw->text()) { QMessageBox::warning(this, "Error", "Outer and hidden passwords must differ."); return; }
    }

    QProgressDialog prog("Creating encrypted container…", QString(), 0, 100, this);
    prog.setWindowModality(Qt::WindowModal); prog.setMinimumDuration(0); prog.setValue(0);

    QString err;
    bool ok = createContainerFromFiles(
        containerEdit->text(), sizeSpin->value(),
        outerFileEdit->text(), outerPw->text(),
        useHidden->isChecked() ? hiddenFileEdit->text() : QString(),
        useHidden->isChecked() ? hiddenPw->text() : QString(),
        "Argon2", 3, &err,
        [&prog](int pct){ prog.setValue(pct); QApplication::processEvents(); });

    prog.setValue(100);
    if (ok) QMessageBox::information(this, "Container created",
        "Encrypted container created.\n\nThe outer password opens the decoy volume; "
        "the hidden password (if set) opens the real one. The two are "
        "indistinguishable without the hidden password.");
    else    QMessageBox::critical(this, "Create failed", err);
}

void MainWindow::on_actionOpenContainer_triggered()
{
    QString cpath = QFileDialog::getOpenFileName(this, "Open Encrypted Container");
    if (cpath.isEmpty()) return;

    QDialog dlg(this);
    dlg.setWindowTitle("Open Encrypted Container");
    QFormLayout* form = new QFormLayout(&dlg);
    QLineEdit* pw = new QLineEdit(&dlg); pw->setEchoMode(QLineEdit::Password);
    form->addRow("Password:", pw);
    QLineEdit* extractEdit = nullptr;
    form->addRow("Extract to:", makePathRow(&dlg, this, "Extract contents to", true, &extractEdit));
    QDialogButtonBox* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(bb);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted) return;
    if (pw->text().isEmpty() || extractEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Error", "Enter a password and an extract path."); return;
    }

    QString err;
    int kind = openContainerToFile(cpath, pw->text(), extractEdit->text(), "Argon2", 3, &err);
    if (kind == 0) { QMessageBox::critical(this, "Open failed", err); return; }
    QMessageBox::information(this, "Container opened",
        QString("%1 volume extracted to:\n%2")
            .arg(kind == 2 ? "Hidden" : "Outer").arg(extractEdit->text()));
}
