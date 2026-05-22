#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QBuffer>
#include <QTextStream>
#include <QStandardItemModel>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QThread>
#include <QListWidget>
#include <QProgressBar>
#include <QTimer>
#include <QMutex>
#include <QTranslator>
#include <QFile>
#include <QDateTime>
#include "encryptionengine.h"
#include "encryptionworker.h"
#include "customlistwidget.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool eventFilter(QObject *obj, QEvent *event) override;
    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);

    // Expose encryption engine for testing
    EncryptionEngine& getEncryptionEngine() { return encryptionEngine; }

    bool prepareToClose();

private slots:
    void workerFinished(const QString &result, bool success, bool isFile);
    void updateProgress(int value);
    void showEstimatedTime(const QString &timeStr);
    void on_fileEncryptButton_clicked();
    void on_fileDecryptButton_clicked();
    void on_folderEncryptButton_clicked();
    void on_folderDecryptButton_clicked();
    void on_fileBrowseButton_clicked();
    void on_folderBrowseButton_clicked();
    void on_fileKeyfileBrowseButton_clicked();
    void on_folderKeyfileBrowseButton_clicked();
    void on_benchmarkButton_clicked();
    void on_actionExit_triggered();
    void on_actionPreferences_triggered();
    void on_actionAbout_triggered();
    void on_actionAboutCiphers_triggered();
    void on_actionAboutKDFs_triggered();
    void on_actionAboutIterations_triggered();
    void on_actionSecurityGuide_triggered();
    void on_m_cryptoProviderComboBox_currentIndexChanged(const QString &providerName);
    void showProviderCapabilities();
    void updateBenchmarkTable(int iterations, double mbps, double ms, const QString &algorithm, const QString &kdf);

    // Disk operations slots - these will be implemented in mainwindow_disk.cpp
    void on_diskEncryptButton_clicked();
    void on_diskDecryptButton_clicked(); 
    void on_diskBrowseButton_clicked();
    void on_diskKeyfileBrowseButton_clicked();
    void on_refreshDisksButton_clicked();
    void on_diskSecureWipeCheckBox_toggled(bool checked);
    void on_wipePatternComboBox_currentIndexChanged(int index);

private:
    // Sets the iteration spinbox minimum to the actual per-KDF floor enforced
    // by the engine (Argon2=3, Scrypt=16384, PBKDF2=600000). Wired to each
    // KDF combobox's currentTextChanged so switching KDF instantly updates
    // the spinbox; the value gets auto-clamped by Qt if it was below the new
    // minimum. The corresponding tooltip is updated too.
    void applyKdfIterationFloor(const QString &kdf, class QSpinBox *spinBox);

private:
    Ui::MainWindow *ui;
    EncryptionEngine encryptionEngine;
    EncryptionWorker *worker;
    QThread workerThread;
    bool m_signalsConnected;
    QString currentTheme;
    
    static QTextStream *s_logStream;
    
    QLabel *fileSecurityStatusLabel;
    QLabel *folderSecurityStatusLabel;
    QLabel *diskSecurityStatusLabel;
    
    QLabel *filePasswordStrengthLabel;
    QLabel *folderPasswordStrengthLabel;
    QLabel *diskPasswordStrengthLabel;

    void setupUI();
    void setupComboBoxes();
    void setupSecurePasswordFields();
    void connectSignalsAndSlots();
    void startWorker(bool encrypt, bool isFile);
    void updateSecurityStatus(const QString &path, QLabel *statusLabel);
    void showSecurityTips(const QString &context);
    void checkPasswordStrength(const QString &password);
    void checkHardwareAcceleration();
    void applyTheme(const QString &theme);
    void loadPreferences();
    void savePreferences();
    void safeConnect(const QObject *sender, const char *signal, const QObject *receiver, const char *method);
    
    // Disk helper functions
    bool hasAdminPrivileges();
    bool elevatePrivileges(const QString &diskPath);
    bool containsKeyfile(QListWidget *listWidget, const QString &path);
    
    // Entropy-related methods
    void setupEntropyMonitoring();
    void createEntropyMonitoringUI(QWidget *tabWidget, const QString &prefix);
    void updateEntropyHealth();
    void runEntropyTest();
    void updateEntropyDisplays();
    void updateTabEntropyDisplay(const QString &prefix, const QString &source, int entropyPerc, 
                                bool isCritical, int refreshRate, const QDateTime &lastUpdate);
};

#endif // MAINWINDOW_H 