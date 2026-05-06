// One-shot UI screenshotting tool for OpenCryptUI.
//
// Builds an offscreen QApplication, instantiates MainWindow, walks the
// top-level QTabWidget and any nested QTabWidgets, and saves a PNG of
// each state into /tmp/ui_screenshots/.
//
// Also captures:
//   - The benchmark tab AFTER pre-populating it with synthetic rows via
//     MainWindow::updateBenchmarkTable() (proves the empty-rows bug is
//     gone without paying the cost of running an actual benchmark).
//   - The window resized to 800x600 to surface layout regressions.
//   - The static help/about QMessageBox dialogs (About, About Ciphers,
//     About KDFs, About Iterations, Security Guide, Preferences). These
//     are modal — we screenshot them via a one-shot QTimer that finds
//     the active modal widget and grabs+closes it.
//
// Not part of CTest — compile and run ad-hoc.

#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QPixmap>
#include <QString>
#include <QStringList>
#include <QTabWidget>
#include <QTimer>
#include <QWidget>
#include <QDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QAction>
#include <QDebug>

namespace {

const QString kOutDir = "/tmp/ui_screenshots";

// Names captured for the final report.
QStringList g_saved;
QStringList g_warnings;

void pumpEvents(int rounds = 8)
{
    for (int i = 0; i < rounds; ++i) {
        QApplication::processEvents(QEventLoop::AllEvents, 25);
    }
}

bool savePng(QWidget *w, const QString &name)
{
    if (!w) {
        g_warnings << QString("widget null for %1").arg(name);
        return false;
    }
    pumpEvents();
    QPixmap pm = w->grab();
    if (pm.isNull() || pm.size().isEmpty()) {
        // On the offscreen platform a freshly-shown widget can grab to an
        // empty pixmap. Try one more pump-and-grab before giving up.
        pumpEvents(16);
        pm = w->grab();
    }
    if (pm.isNull() || pm.size().isEmpty()) {
        g_warnings << QString("empty pixmap for %1").arg(name);
        return false;
    }
    const QString path = kOutDir + "/" + name + ".png";
    if (!pm.save(path, "PNG")) {
        g_warnings << QString("save failed for %1").arg(path);
        return false;
    }
    g_saved << path;
    qInfo().noquote() << "saved" << path << pm.size();
    return true;
}

QString slugify(const QString &s)
{
    QString out;
    out.reserve(s.size());
    for (QChar c : s) {
        if (c.isLetterOrNumber()) out.append(c.toLower());
        else if (!out.isEmpty() && out[out.size() - 1] != '_') out.append('_');
    }
    while (out.endsWith('_')) out.chop(1);
    return out;
}

// Walk the visible tab pane for nested QTabWidgets and screenshot each
// of THEIR sub-tabs as well. We only descend one level — the UI doesn't
// nest deeper than that.
void captureNestedTabs(QWidget *pane, const QString &topPrefix)
{
    if (!pane) return;
    QList<QTabWidget *> nested = pane->findChildren<QTabWidget *>();
    for (QTabWidget *nt : nested) {
        // Skip the top-level one if findChildren returned it.
        if (nt->objectName() == "tabWidget") continue;
        const int nstart = nt->currentIndex();
        for (int j = 0; j < nt->count(); ++j) {
            nt->setCurrentIndex(j);
            pumpEvents();
            const QString sub = slugify(nt->tabText(j));
            const QString name = QString("%1__%2__%3")
                                     .arg(topPrefix, slugify(nt->objectName()), sub);
            savePng(pane->window(), name);
        }
        nt->setCurrentIndex(nstart);
    }
}

// Trigger an action, then on a single-shot timer grab whatever modal
// widget is active and close it. Works for QMessageBox::about/information
// (which are blocking) and for QInputDialog::getItem (Preferences).
void captureModalFromAction(QAction *act, const QString &name)
{
    if (!act) {
        g_warnings << QString("missing action for %1").arg(name);
        return;
    }
    // Schedule the screenshot+close for after the modal dialog is up.
    QTimer::singleShot(120, [name]() {
        // Pump a couple of times so the dialog has fully laid out.
        pumpEvents(4);
        QWidget *modal = QApplication::activeModalWidget();
        if (!modal) {
            g_warnings << QString("no modal widget for %1").arg(name);
            return;
        }
        savePng(modal, name);
        // Close the dialog so trigger() returns.
        if (auto *mb = qobject_cast<QMessageBox *>(modal)) {
            mb->done(QMessageBox::Ok);
        } else if (auto *dlg = qobject_cast<QDialog *>(modal)) {
            dlg->reject();
        } else {
            modal->close();
        }
    });
    act->trigger(); // blocks inside exec() until the timer above closes it
}

} // namespace

int main(int argc, char **argv)
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    QDir().mkpath(kOutDir);

    MainWindow w;
    w.resize(1200, 850); // generous default — tab content is busy
    w.show();
    pumpEvents(16);

    QTabWidget *top = w.findChild<QTabWidget *>("tabWidget");
    if (!top) {
        qCritical() << "FATAL: top-level tabWidget not found";
        return 1;
    }

    qInfo() << "top tab count:" << top->count();
    QStringList topNames;
    for (int i = 0; i < top->count(); ++i) topNames << top->tabText(i);
    qInfo() << "tabs:" << topNames;

    // 1. Each top-level tab in default size.
    for (int i = 0; i < top->count(); ++i) {
        top->setCurrentIndex(i);
        pumpEvents(8);
        const QString prefix = QString("tab%1_%2").arg(i).arg(slugify(top->tabText(i)));
        savePng(&w, prefix + "_default");
        // 2. Nested sub-tabs inside this pane (Standard/Hidden Volume,
        //    Password sub-tab on file/folder).
        captureNestedTabs(top->currentWidget(), prefix);
    }

    // 3. Benchmark tab populated with synthetic rows — this is the visual
    //    proof the empty-rows bug is fixed. updateBenchmarkTable is a
    //    public-ish slot exposed via the header.
    {
        // Switch to the benchmark tab.
        for (int i = 0; i < top->count(); ++i) {
            if (top->tabText(i).contains("Benchmark", Qt::CaseInsensitive)) {
                top->setCurrentIndex(i);
                break;
            }
        }
        pumpEvents();

        // Realistic numbers across a few cipher/KDF combos.
        struct Row { int it; double mbps; double ms; const char *cipher; const char *kdf; };
        const Row rows[] = {
            {10,  812.34,  12.31, "AES-256-GCM",        "Argon2"},
            {10,  742.10,  13.46, "AES-256-GCM",        "Scrypt"},
            {10, 1083.72,   9.23, "ChaCha20-Poly1305",  "Argon2"},
            {10,  697.55,  14.34, "AES-256-CBC",        "PBKDF2"},
            {10,  655.22,  15.27, "AES-256-CTR",        "PBKDF2"},
            {10,  931.40,  10.74, "AES-256-GCM",        "PBKDF2"},
        };
        for (const Row &r : rows) {
            // updateBenchmarkTable is a private Q_SLOT. Invoke via the
            // meta-object system so we don't need to befriend the class.
            QMetaObject::invokeMethod(
                &w, "updateBenchmarkTable",
                Qt::DirectConnection,
                Q_ARG(int, r.it),
                Q_ARG(double, r.mbps),
                Q_ARG(double, r.ms),
                Q_ARG(QString, QString::fromLatin1(r.cipher)),
                Q_ARG(QString, QString::fromLatin1(r.kdf)));
        }
        pumpEvents();
        savePng(&w, "tab3_benchmark_populated");
    }

    // 4. Resized small (800x600) — check layout doesn't break.
    {
        // Reset to first tab so the screenshot is comparable.
        top->setCurrentIndex(0);
        pumpEvents();
        w.resize(800, 600);
        pumpEvents(16);
        savePng(&w, "mainwindow_800x600_disk");
        // Also small-shot the file tab — the file tab is the most cramped.
        for (int i = 0; i < top->count(); ++i) {
            if (top->tabText(i).contains("File", Qt::CaseInsensitive)
                && !top->tabText(i).contains("Folder", Qt::CaseInsensitive))
            {
                top->setCurrentIndex(i);
                break;
            }
        }
        pumpEvents();
        savePng(&w, "mainwindow_800x600_file");
        // Restore default size for dialog screenshots.
        w.resize(1200, 850);
        pumpEvents();
    }

    // 5. Modal dialogs reachable from the menu without user input.
    captureModalFromAction(w.findChild<QAction *>("actionAbout"),
                           "dialog_about");
    captureModalFromAction(w.findChild<QAction *>("actionAboutCiphers"),
                           "dialog_about_ciphers");
    captureModalFromAction(w.findChild<QAction *>("actionAboutKDFs"),
                           "dialog_about_kdfs");
    captureModalFromAction(w.findChild<QAction *>("actionAboutIterations"),
                           "dialog_about_iterations");
    captureModalFromAction(w.findChild<QAction *>("actionSecurityGuide"),
                           "dialog_security_guide");
    captureModalFromAction(w.findChild<QAction *>("actionPreferences"),
                           "dialog_preferences");

    qInfo() << "===== SUMMARY =====";
    qInfo() << "saved:" << g_saved.size() << "PNGs";
    for (const QString &p : g_saved) qInfo().noquote() << "  " << p;
    if (!g_warnings.isEmpty()) {
        qInfo() << "warnings:";
        for (const QString &w : g_warnings) qInfo().noquote() << "  " << w;
    }
    return 0;
}
