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
// filesystem tools (mkfs.*) and are often absent from a GUI app's PATH.
QString findTool(const QString& name)
{
    QString p = QStandardPaths::findExecutable(name);
    if (!p.isEmpty()) return p;
#ifndef Q_OS_WIN
    for (const QString& dir : { QStringLiteral("/sbin"), QStringLiteral("/usr/sbin"),
                                QStringLiteral("/usr/local/sbin"), QStringLiteral("/opt/homebrew/bin") }) {
        const QString cand = dir + "/" + name;
        if (QFileInfo(cand).isExecutable()) return cand;
    }
#endif
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

// Run a command to completion, capturing combined output. Returns the exit
// code, or -1 if it failed to start / timed out.
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

#ifdef Q_OS_WIN
// First drive letter (D..Z) with no volume present, as "X:". "" if none free.
QString firstFreeDriveLetter()
{
    for (char c = 'D'; c <= 'Z'; ++c) {
        const QString root = QString("%1:/").arg(c);
        if (!QDir(root).exists()) return QString("%1:").arg(c);
    }
    return QString();
}
#endif

// --- Per-OS second step: lay a filesystem on the decrypted image, and mount /
// unmount it as a real drive. The image is the disk.img the FUSE driver
// exposes. Each returns "" on success or a human-readable reason.

// Put a portable filesystem on `image` so the vault mounts on Linux, macOS and
// Windows alike. exFAT is preferred (universally supported); FAT32 then ext4
// are fallbacks. *fsType is set to the filesystem actually written.
QString formatImage(const QString& image, QString* fsType)
{
#if defined(Q_OS_LINUX)
    QString tool = findTool("mkfs.exfat");
    if (!tool.isEmpty()) {
        if (fsType) *fsType = "exFAT";
        QString out; if (runSync(tool, { image }, &out, 120000) == 0) return QString();
        return "mkfs.exfat failed: " + out.trimmed();
    }
    tool = findTool("mkfs.vfat");
    if (!tool.isEmpty()) {
        if (fsType) *fsType = "FAT32";
        QString out; if (runSync(tool, { "-F", "32", image }, &out, 120000) == 0) return QString();
        return "mkfs.vfat failed: " + out.trimmed();
    }
    tool = findTool("mkfs.ext4");
    if (tool.isEmpty()) tool = findTool("mke2fs");
    if (!tool.isEmpty()) {
        if (fsType) *fsType = "ext4 (Linux-only)";
        QString out; if (runSync(tool, { "-q", "-F", "-t", "ext4", image }, &out, 120000) == 0) return QString();
        return "mkfs.ext4 failed: " + out.trimmed();
    }
    return "No filesystem tool found (install exfatprogs for a portable vault).";

#elif defined(Q_OS_MACOS)
    // Attach the raw image as a device without mounting, format it exFAT, detach.
    QString out;
    if (runSync("hdiutil", { "attach", "-imagekey", "diskimage-class=CRawDiskImage",
                             "-nomount", image }, &out) != 0)
        return "hdiutil attach (for format) failed: " + out.trimmed();
    // hdiutil prints the new /dev/diskN as the first token.
    const QString dev = out.split('\n', Qt::SkipEmptyParts).value(0).section(' ', 0, 0).trimmed();
    if (!dev.startsWith("/dev/")) return "could not determine device from hdiutil output";
    QString fout;
    const int rc = runSync("newfs_exfat", { "-v", "VAULT", dev }, &fout, 120000);
    runSync("hdiutil", { "detach", dev }, nullptr);
    if (fsType) *fsType = "exFAT";
    return rc == 0 ? QString() : ("newfs_exfat failed: " + fout.trimmed());

#elif defined(Q_OS_WIN)
    // Attach the image to a drive letter via ImDisk, format it exFAT, detach.
    const QString imdisk = findTool("imdisk");
    if (imdisk.isEmpty())
        return "ImDisk is required to format a mountable vault on Windows "
               "(install it from ltr-data.se).";
    const QString letter = firstFreeDriveLetter();
    if (letter.isEmpty()) return "no free drive letter available";
    QString out;
    if (runSync(imdisk, { "-a", "-t", "file", "-f", image, "-m", letter }, &out) != 0)
        return "ImDisk attach (for format) failed: " + out.trimmed();
    QString fout;
    const int rc = runSync("powershell", { "-NoProfile", "-Command",
        QString("Format-Volume -DriveLetter %1 -FileSystem exFAT -Confirm:$false")
            .arg(letter.left(1)) }, &fout, 120000);
    runSync(imdisk, { "-D", "-m", letter }, nullptr);
    if (fsType) *fsType = "exFAT";
    return rc == 0 ? QString() : ("Format-Volume failed: " + fout.trimmed());
#else
    return "Mountable vaults are not supported on this platform.";
#endif
}

// Mount the decrypted `image` as a real drive. On success sets *driveOut to the
// path/letter to open and returns ""; returns a reason on failure (caller then
// falls back to exposing the FUSE image).
QString mountImageAsDrive(const QString& image, QString* driveOut)
{
#if defined(Q_OS_LINUX)
    const QString driveDir = makeMountpointDir();
    QString out; int rc;
    if (isRoot()) rc = runSync("mount", { "-o", "loop", image, driveDir }, &out);
    else          rc = runSync("pkexec", { "mount", "-o", "loop", image, driveDir }, &out);
    if (rc == 0) { *driveOut = driveDir; return QString(); }
    QDir().rmdir(driveDir);
    return out.trimmed().isEmpty() ? "loop mount unavailable" : out.trimmed();

#elif defined(Q_OS_MACOS)
    QString out;
    if (runSync("hdiutil", { "attach", "-imagekey", "diskimage-class=CRawDiskImage",
                             "-nobrowse", image }, &out) != 0)
        return "hdiutil attach failed: " + out.trimmed();
    // The mountpoint is the /Volumes/... path in the last line.
    const QStringList lines = out.split('\n', Qt::SkipEmptyParts);
    for (int i = lines.size() - 1; i >= 0; --i) {
        const int idx = lines[i].indexOf("/Volumes/");
        if (idx >= 0) { *driveOut = lines[i].mid(idx).trimmed(); return QString(); }
    }
    return "mounted, but could not find the /Volumes mountpoint";

#elif defined(Q_OS_WIN)
    const QString imdisk = findTool("imdisk");
    if (imdisk.isEmpty())
        return "ImDisk is required to mount a vault as a drive on Windows "
               "(install it from ltr-data.se).";
    const QString letter = firstFreeDriveLetter();
    if (letter.isEmpty()) return "no free drive letter available";
    QString out;
    if (runSync(imdisk, { "-a", "-t", "file", "-f", image, "-m", letter }, &out) != 0)
        return "ImDisk attach failed: " + out.trimmed();
    *driveOut = letter + "\\";
    return QString();
#else
    Q_UNUSED(image); Q_UNUSED(driveOut);
    return "unsupported platform";
#endif
}

void unmountDrive(const QString& drivePath)
{
#if defined(Q_OS_LINUX)
    if (isRoot()) runSync("umount", { drivePath }, nullptr);
    else          runSync("pkexec", { "umount", drivePath }, nullptr);
    QDir().rmdir(drivePath);
#elif defined(Q_OS_MACOS)
    runSync("hdiutil", { "detach", drivePath }, nullptr);
#elif defined(Q_OS_WIN)
    const QString imdisk = findTool("imdisk");
    if (!imdisk.isEmpty()) {
        QString letter = drivePath; letter.remove('\\'); letter.remove('/');
        runSync(imdisk, { "-D", "-m", letter }, nullptr);
    }
#else
    Q_UNUSED(drivePath);
#endif
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
#if defined(Q_OS_LINUX)
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
    // WinFsp mounts to a drive letter; libfuse (Linux/macOS) to a directory.
#ifdef Q_OS_WIN
    const QString fuseDir = firstFreeDriveLetter();
    if (fuseDir.isEmpty()) { if (error) *error = "No free drive letter for the mount."; return false; }
#else
    const QString fuseDir = makeMountpointDir();
#endif
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
    stopFuse(nullptr, fuseDir); // clean up the mountpoint
    if (error) *error = out.trimmed().isEmpty()
        ? "The vault did not mount (wrong password, or unsupported volume)."
        : out.trimmed();
    return false;
}

void VaultMounter::stopFuse(QProcess* proc, const QString& fuseDir)
{
#if defined(Q_OS_LINUX)
    if (QProcess::execute("fusermount3", { "-u", fuseDir }) != 0)
        QProcess::execute("fusermount", { "-u", fuseDir });
#elif defined(Q_OS_MACOS)
    if (QProcess::execute("umount", { fuseDir }) != 0)
        QProcess::execute("diskutil", { "unmount", "force", fuseDir });
#endif
    // On Windows (WinFsp) the mount goes away when the driver process exits;
    // there is no external unmount command.
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

    // 2. Lay a portable filesystem on the decrypted image so it mounts as a
    //    usable drive on any OS. We need the image exposed (via FUSE) first.
    QProcess* fuse = nullptr; QString fuseDir;
    if (!startFuse(volumePath, password, kdf, iter, &fuse, &fuseDir, error)) return false;
    QString fsType;
    const QString fsErr = formatImage(fuseDir + "/disk.img", &fsType);
    stopFuse(fuse, fuseDir);
    if (!fsErr.isEmpty()) {
        if (error) *error = "Vault created, but laying its filesystem failed: " + fsErr;
        return false;
    }
    SECURE_LOG(INFO, "VaultMounter", QString("Created mountable vault (%1).").arg(fsType));
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

    ActiveMount m;
    m.volumePath = volumePath;
    m.fuseDir = fuseDir;
    m.driver = fuse;

    QString driveOut;
    const QString mErr = mountImageAsDrive(fuseDir + "/disk.img", &driveOut);
    if (mErr.isEmpty()) {
        m.drivePath = driveOut;
        m.realDrive = true;
    } else {
        SECURE_LOG(INFO, "VaultMounter",
                   QString("Real drive unavailable (%1); exposing FUSE image instead.").arg(mErr));
    }

    m_mounts.append(m);
    if (outOpenPath)  *outOpenPath = m.realDrive ? m.drivePath : m.fuseDir;
    if (usedFallback) *usedFallback = !m.realDrive;
    return true;
}

bool VaultMounter::unmount(int index, QString* error)
{
    if (index < 0 || index >= m_mounts.size()) { if (error) *error = "No such mount."; return false; }
    ActiveMount m = m_mounts.at(index);

    if (m.realDrive && !m.drivePath.isEmpty())
        unmountDrive(m.drivePath);

    stopFuse(m.driver, m.fuseDir);
    m_mounts.removeAt(index);
    return true;
}
