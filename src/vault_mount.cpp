#include "vault_mount.h"
#include "logging/secure_logger.h"
#include <QProcess>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QThread>
#include <QUuid>

#ifndef Q_OS_WIN
#include <unistd.h>   // geteuid
#endif

namespace {

// A fresh empty directory to use as a FUSE mountpoint, under the temp dir.
QString makeMountpointDir()
{
    const QString base = QDir::tempPath() + "/ocui-mnt-"
        + QUuid::createUuid().toString(QUuid::Id128);
    QDir().mkpath(base);
    return base;
}

// Like QStandardPaths::findExecutable but also checks the sbin dirs, which hold
// filesystem tools (mkfs.ext4) and are often absent from a GUI app's PATH.
QString findTool(const QString& name)
{
    QString p = QStandardPaths::findExecutable(name);
    if (!p.isEmpty()) return p;
    for (const QString& dir : { QStringLiteral("/sbin"), QStringLiteral("/usr/sbin"),
                                QStringLiteral("/usr/local/sbin") }) {
        const QString cand = dir + "/" + name;
        if (QFileInfo(cand).isExecutable()) return cand;
    }
    return QString();
}

bool isRoot()
{
#ifndef Q_OS_WIN
    return geteuid() == 0;
#else
    return false; // Windows uses WinFsp's service; no euid concept.
#endif
}

// Run a command to completion, capturing combined output. Returns exit code,
// or -1 if it failed to start / timed out.
int runSync(const QString& program, const QStringList& args, QString* output, int timeoutMs = 60000)
{
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(program, args);
    if (!p.waitForStarted(5000)) { if (output) *output = "could not start " + program; return -1; }
    if (!p.waitForFinished(timeoutMs)) { p.kill(); p.waitForFinished(2000); if (output) *output = program + " timed out"; return -1; }
    if (output) *output = QString::fromLocal8Bit(p.readAll());
    return p.exitCode();
}

} // namespace

VaultMounter::VaultMounter(QObject* parent)
    : QObject(parent), m_bin(defaultMountBinary())
{
}

VaultMounter::~VaultMounter()
{
    // Best-effort clean unmount of everything still mounted.
    while (!m_mounts.isEmpty()) {
        QString err;
        if (!unmount(m_mounts.size() - 1, &err)) {
            // Force-reap the driver so we don't leak a process on exit.
            ActiveMount m = m_mounts.takeLast();
            if (m.driver) { m.driver->kill(); m.driver->waitForFinished(2000); delete m.driver; }
        }
    }
}

QString VaultMounter::defaultMountBinary()
{
#ifdef Q_OS_WIN
    const QString name = "opencryptui-mount.exe";
#else
    const QString name = "opencryptui-mount";
#endif
    const QString beside = QCoreApplication::applicationDirPath() + "/" + name;
    if (QFileInfo::exists(beside)) return beside;
    return QStandardPaths::findExecutable(name); // "" if not on PATH
}

bool VaultMounter::available(QString* whyNot) const
{
    if (m_bin.isEmpty() || !QFileInfo::exists(m_bin)) {
        if (whyNot) *whyNot = "The mount helper (opencryptui-mount) is not installed. "
                              "Build it with -DOCUI_ENABLE_FUSE=ON.";
        return false;
    }
#ifdef Q_OS_LINUX
    if (!QFileInfo::exists("/dev/fuse")) {
        if (whyNot) *whyNot = "FUSE is not available on this system (/dev/fuse is missing). "
                              "Install fuse3 to mount vaults.";
        return false;
    }
#endif
    return true;
}

bool VaultMounter::startFuse(const QString& volumePath, const QString& password,
                             const QString& kdf, int iter,
                             QProcess** outProc, QString* outFuseDir, QString* error)
{
    const QString fuseDir = makeMountpointDir();
    QProcess* p = new QProcess(this);
    p->setProcessChannelMode(QProcess::MergedChannels);
    p->start(m_bin, { volumePath, fuseDir,
                      "--kdf", kdf, "--iter", QString::number(iter) });
    if (!p->waitForStarted(5000)) {
        if (error) *error = "Could not start the mount helper.";
        delete p; QDir().rmdir(fuseDir); return false;
    }
    // The driver reads the password from stdin once. Flush it explicitly: this
    // can run without a spinning event loop (e.g. from a button handler), so we
    // must push the bytes to the child rather than rely on the event loop.
    p->write((password + "\n").toUtf8());
    p->waitForBytesWritten(3000);
    p->closeWriteChannel();

    // Wait (up to ~15s) for disk.img to appear, or the driver to exit early.
    const QString image = fuseDir + "/disk.img";
    for (int i = 0; i < 75; ++i) {
        if (QFileInfo::exists(image)) {
            *outProc = p; *outFuseDir = fuseDir;
            return true;
        }
        if (p->state() == QProcess::NotRunning) break; // died (likely wrong password)
        QThread::msleep(200);
    }

    const QString out = QString::fromLocal8Bit(p->readAll());
    if (p->state() != QProcess::NotRunning) { p->kill(); p->waitForFinished(2000); }
    delete p;
    QProcess::execute("fusermount3", { "-u", fuseDir });
    QDir().rmdir(fuseDir);
    if (error) *error = out.trimmed().isEmpty()
        ? "The vault did not mount (wrong password, or unsupported volume)."
        : out.trimmed();
    return false;
}

void VaultMounter::stopFuse(QProcess* proc, const QString& fuseDir)
{
#ifdef Q_OS_LINUX
    if (QProcess::execute("fusermount3", { "-u", fuseDir }) != 0)
        QProcess::execute("fusermount", { "-u", fuseDir });
#else
    // macOS/Windows: unmounting the driver's mountpoint stops it.
    QProcess::execute("umount", { fuseDir });
#endif
    if (proc) {
        if (!proc->waitForFinished(5000)) { proc->kill(); proc->waitForFinished(2000); }
        delete proc;
    }
    QDir().rmdir(fuseDir);
}

bool VaultMounter::createMountable(const QString& volumePath, qint64 sizeMiB,
                                   const QString& password, const QString& kdf, int iter,
                                   QString* error)
{
    QString why;
    if (!available(&why)) { if (error) *error = why; return false; }

    // 1. Create the encrypted BlockVolume via the driver's --create mode.
    {
        QProcess p;
        p.setProcessChannelMode(QProcess::MergedChannels);
        p.start(m_bin, { "--create", volumePath, "--size", QString::number(sizeMiB),
                         "--kdf", kdf, "--iter", QString::number(iter) });
        if (!p.waitForStarted(5000)) { if (error) *error = "Could not start the mount helper."; return false; }
        p.write((password + "\n" + password + "\n").toUtf8());
        p.waitForBytesWritten(3000);
        p.closeWriteChannel();
        if (!p.waitForFinished(600000)) { p.kill(); if (error) *error = "Creating the vault timed out."; return false; }
        if (p.exitCode() != 0 || !QFileInfo::exists(volumePath)) {
            if (error) *error = "Could not create the vault: " + QString::fromLocal8Bit(p.readAll()).trimmed();
            return false;
        }
    }

    // 2. Lay a filesystem on the image so it mounts as a usable drive.
#ifdef Q_OS_LINUX
    QString mkfs = findTool("mkfs.ext4");
    QStringList mkfsArgs;
    if (!mkfs.isEmpty()) {
        mkfsArgs = QStringList{ "-q", "-F" };
    } else {
        mkfs = findTool("mke2fs");
        mkfsArgs = QStringList{ "-q", "-F", "-t", "ext4" };
    }
    if (mkfs.isEmpty()) {
        if (error) *error = "Vault created, but no filesystem tool (mkfs.ext4) was found, "
                            "so it cannot mount as a drive. Install e2fsprogs.";
        return false;
    }
    QProcess* fuse = nullptr; QString fuseDir;
    if (!startFuse(volumePath, password, kdf, iter, &fuse, &fuseDir, error)) return false;
    QString out;
    const int rc = runSync(mkfs, mkfsArgs + QStringList{ fuseDir + "/disk.img" }, &out, 120000);
    stopFuse(fuse, fuseDir);
    if (rc != 0) {
        if (error) *error = "Vault created, but formatting its filesystem failed: " + out.trimmed();
        return false;
    }
#else
    // macOS/Windows formatting is done at mount time by the OS image tooling;
    // the bare volume is created above. (Cross-platform mkfs is a follow-up.)
#endif
    return true;
}

bool VaultMounter::mount(const QString& volumePath, const QString& password,
                         const QString& kdf, int iter,
                         QString* outOpenPath, bool* usedFallback, QString* error)
{
    QString why;
    if (!available(&why)) { if (error) *error = why; return false; }

    QProcess* fuse = nullptr; QString fuseDir;
    if (!startFuse(volumePath, password, kdf, iter, &fuse, &fuseDir, error)) return false;

    const QString image = fuseDir + "/disk.img";
    ActiveMount m;
    m.volumePath = volumePath;
    m.fuseDir = fuseDir;
    m.driver = fuse;

#if defined(Q_OS_LINUX)
    // Turn the decrypted image into a real drive via a loop mount (root, else
    // pkexec). If that is not possible, fall back to the FUSE image.
    const QString driveDir = makeMountpointDir();
    QString out;
    int rc;
    if (isRoot())
        rc = runSync("mount", { "-o", "loop", image, driveDir }, &out);
    else
        rc = runSync("pkexec", { "mount", "-o", "loop", image, driveDir }, &out);
    if (rc == 0) {
        m.drivePath = driveDir; m.realDrive = true;
    } else {
        QDir().rmdir(driveDir);
        SECURE_LOG(INFO, "VaultMounter",
                   QString("Loop mount unavailable (%1); exposing FUSE image instead.").arg(out.trimmed()));
    }
#elif defined(Q_OS_MACOS)
    // macFUSE exposes the image; attach it as a volume via hdiutil.
    QString out;
    if (runSync("hdiutil", { "attach", "-imagekey", "diskimage-class=CRawDiskImage",
                             "-nobrowse", image }, &out) == 0) {
        // hdiutil prints the mountpoint as the last whitespace-separated field.
        const QStringList lines = out.split('\n', Qt::SkipEmptyParts);
        if (!lines.isEmpty()) {
            const QString last = lines.last();
            const int idx = last.indexOf("/Volumes/");
            if (idx >= 0) { m.drivePath = last.mid(idx).trimmed(); m.realDrive = true; }
        }
    }
#elif defined(Q_OS_WIN)
    // WinFsp surfaces the mountpoint as a drive directly; full in-drive
    // filesystem mounting is experimental, so expose the image location.
#endif

    if (!m.realDrive)
        SECURE_LOG(INFO, "VaultMounter", "Mounted with FUSE image fallback (no elevated drive).");

    m_mounts.append(m);
    if (outOpenPath)   *outOpenPath = m.realDrive ? m.drivePath : m.fuseDir;
    if (usedFallback)  *usedFallback = !m.realDrive;
    return true;
}

bool VaultMounter::unmount(int index, QString* error)
{
    if (index < 0 || index >= m_mounts.size()) { if (error) *error = "No such mount."; return false; }
    ActiveMount m = m_mounts.at(index);

    if (m.realDrive && !m.drivePath.isEmpty()) {
        QString out; int rc;
#if defined(Q_OS_MACOS)
        rc = runSync("hdiutil", { "detach", m.drivePath }, &out);
#else
        if (isRoot()) rc = runSync("umount", { m.drivePath }, &out);
        else          rc = runSync("pkexec", { "umount", m.drivePath }, &out);
#endif
        if (rc != 0) { if (error) *error = "Could not unmount the drive: " + out.trimmed(); return false; }
        QDir().rmdir(m.drivePath);
    }

    stopFuse(m.driver, m.fuseDir);
    m_mounts.removeAt(index);
    return true;
}
