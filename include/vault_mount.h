#ifndef VAULT_MOUNT_H
#define VAULT_MOUNT_H

#include <QObject>
#include <QString>
#include <QVector>
class QProcess;

// Cross-platform orchestration for mounting an encrypted BlockVolume as a
// usable drive, layered on the opencryptui-mount FUSE driver.
//
// The driver decrypts on the fly and exposes one file, disk.img, at a FUSE
// mountpoint (on Windows that mountpoint is a drive letter, courtesy of
// WinFsp's libfuse layer). To present a real, browsable drive we put a
// filesystem on that image at create time and mount it at open time:
//
//   Linux  : mkfs.ext4 on create; `mount -o loop` to a real dir. Needs root,
//            so when not root we try pkexec; if neither works we FALL BACK to
//            exposing the decrypted disk.img via FUSE only - and say so.
//   macOS  : hdiutil attach (best effort; macFUSE provides the FUSE layer).
//   Windows: WinFsp gives a drive letter directly when the driver runs; the
//            image is surfaced there (full in-drive filesystem is experimental).
//
// The fallback is never silent: callers learn whether they got a real drive or
// just the FUSE image, and tell the user.
class VaultMounter : public QObject
{
    Q_OBJECT
public:
    struct ActiveMount {
        QString   volumePath;        // encrypted backing file
        QString   fuseDir;           // FUSE mountpoint (contains disk.img)
        QString   drivePath;         // real mounted dir/letter ("" => FUSE-only)
        QProcess* driver = nullptr;  // long-lived FUSE driver process
        bool      realDrive = false; // true => drivePath is a usable drive
    };

    explicit VaultMounter(QObject* parent = nullptr);
    ~VaultMounter() override;

    // Locate the opencryptui-mount binary next to the app or on PATH ("" if absent).
    static QString defaultMountBinary();
    void setMountBinary(const QString& path) { m_bin = path; }
    QString mountBinary() const { return m_bin; }

    // Is mounting possible here (driver built, FUSE usable)? Sets *whyNot if not.
    bool available(QString* whyNot) const;

    // Create a fresh mountable vault of sizeMiB and lay a filesystem on it so it
    // mounts as a usable drive. Returns false (and sets *error) on failure.
    bool createMountable(const QString& volumePath, qint64 sizeMiB,
                         const QString& password, const QString& kdf, int iter,
                         QString* error);

    // Mount volumePath. On success appends to active() and sets *outOpenPath to
    // the path the user should open (the real drive, or the FUSE dir on
    // fallback) and *usedFallback accordingly.
    bool mount(const QString& volumePath, const QString& password,
               const QString& kdf, int iter,
               QString* outOpenPath, bool* usedFallback, QString* error);

    // Unmount the active mount at index; removes it from active() on success.
    bool unmount(int index, QString* error);

    const QVector<ActiveMount>& active() const { return m_mounts; }

private:
    // Start the FUSE driver on volumePath, waiting until disk.img appears.
    // Returns the running process (kept alive by the caller) and the mountpoint.
    bool startFuse(const QString& volumePath, const QString& password,
                   const QString& kdf, int iter,
                   QProcess** outProc, QString* outFuseDir, QString* error);
    // Tear down a FUSE mount: unmount and reap the driver.
    void stopFuse(QProcess* proc, const QString& fuseDir);

    QString m_bin;
    QVector<ActiveMount> m_mounts;
};

#endif // VAULT_MOUNT_H
