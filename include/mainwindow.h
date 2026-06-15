#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <functional>
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

    // Deniable-container GUI core, factored out of the dialog slots so it can be
    // tested without driving native file dialogs. createContainerFromFiles reads
    // the outer (and optional hidden) file into a deniable container;
    // openContainerToFile decrypts and writes the volume the password unlocks.
    bool createContainerFromFiles(const QString& containerPath, qint64 sizeMiB,
                                  const QString& outerFile, const QString& outerPassword,
                                  const QString& hiddenFile, const QString& hiddenPassword,
                                  const QString& kdf, int iterations,
                                  QString* error,
                                  const std::function<void(int)>& progress = {});
    // Returns 1 = outer volume extracted, 2 = hidden, 0 = failure (sets *error).
    int openContainerToFile(const QString& containerPath, const QString& password,
                            const QString& extractTo, const QString& kdf, int iterations,
                            QString* error);

    // Shamir share files: split a password into n base64 share files (k needed
    // to recover) at <baseFilePath>.1.share ... .n.share, and recover a password
    // from any sufficient set of share files. Factored out for testing.
    bool splitPasswordToShares(const QString& password, int n, int k,
                               const QString& baseFilePath,
                               QStringList* writtenFiles, QString* error);
    bool recoverPasswordFromShares(const QStringList& shareFiles,
                                   QString* password, QString* error);

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
    void on_actionCreateContainer_triggered();
    void on_actionOpenContainer_triggered();
    void on_m_cryptoProviderComboBox_currentIndexChanged(const QString &providerName);
    void showProviderCapabilities();
    void updateBenchmarkTable(int iterations, double mbps, double ms, const QString &algorithm, const QString &kdf);
    // Fired when the worker has measured every combo - promotes the
    // "best so far" line to the final "OK Recommended" recommendation.
    void onBenchmarkComplete();

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

    // Security rating for a (cipher, KDF) pair, used by the benchmark tab.
    // This tool ranks by SECURITY first - speed is only a tiebreaker among
    // equally-secure options, and for KDFs faster is actively worse (lower
    // attacker work factor). tier is 1..3 (3 = strongest), computed as the
    // weakest-link min of the cipher tier and the KDF tier. label is a
    // human string ("Strong" / "Good" / "Weak") with a * rendering.
    struct SecurityRating { int tier; QString label; QString stars; };
    static SecurityRating securityRatingFor(const QString &cipher, const QString &kdf);

    // Rough order-of-magnitude multiplier for how many parallel guesses an
    // attacker with a GPU/ASIC farm can run against this KDF, relative to one
    // CPU core. Driven by the KDF's per-guess memory cost: PBKDF2 (no memory)
    // parallelizes almost freely; Argon2 (1 GiB/guess) barely at all. Used to
    // turn the measured single-core rate into a realistic attacker estimate.
    static double gpuParallelismFactor(const QString &kdf);

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

    // Running "best" config for the benchmark recommendation banner:
    // highest security tier, then highest cipher throughput within that tier.
    // Reset when a benchmark run starts; updated as each result arrives. The
    // banner only shows "best so far" until benchmarkFinished fires - a real
    // recommendation can't be made before every combo has been measured.
    int     m_benchRecTier = -1;
    double  m_benchRecMbps = -1.0;
    QString m_benchRecCipher;
    QString m_benchRecKdf;
    QString m_benchRecTierLabel;
    double  m_benchRecUnlockMs = 0.0;
    double  m_benchRecGpuRate  = 0.0;
    bool    m_benchRunning     = false;

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