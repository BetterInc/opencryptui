#include "block_device_io.h"
#include "logging/secure_logger.h"
#include <QFileInfo>

#if defined(Q_OS_WIN)
#  include <windows.h>
#  include <winioctl.h>
#elif defined(Q_OS_LINUX)
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/ioctl.h>
#  include <linux/fs.h>    // BLKGETSIZE64
#elif defined(Q_OS_MACOS)
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/ioctl.h>
#  include <sys/disk.h>    // DKIOCGETBLOCKCOUNT / DKIOCGETBLOCKSIZE
#endif

bool BlockDeviceIo::isRawDevicePath(const QString& path)
{
#if defined(Q_OS_WIN)
    return path.startsWith(QLatin1String("\\\\.\\"));
#else
    return path.startsWith(QLatin1String("/dev/"));
#endif
}

qint64 BlockDeviceIo::sizeBytes(const QString& path)
{
    if (isRawDevicePath(path)) {
#if defined(Q_OS_WIN)
        HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),
                               GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return -1;
        GET_LENGTH_INFORMATION li; DWORD got = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                                  &li, sizeof(li), &got, nullptr);
        CloseHandle(h);
        return ok ? qint64(li.Length.QuadPart) : -1;
#elif defined(Q_OS_LINUX)
        int fd = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        quint64 sz = 0;
        int rc = ::ioctl(fd, BLKGETSIZE64, &sz);
        ::close(fd);
        return (rc == 0 && sz > 0) ? qint64(sz) : -1;
#elif defined(Q_OS_MACOS)
        int fd = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        quint64 cnt = 0; quint32 bs = 0;
        int rc1 = ::ioctl(fd, DKIOCGETBLOCKCOUNT, &cnt);
        int rc2 = ::ioctl(fd, DKIOCGETBLOCKSIZE, &bs);
        ::close(fd);
        return (rc1 == 0 && rc2 == 0 && cnt > 0 && bs > 0) ? qint64(cnt) * bs : -1;
#else
        return -1;
#endif
    }
    QFileInfo info(path);
    return info.exists() ? info.size() : -1;
}

BlockDeviceIo::~BlockDeviceIo() { close(); }

bool BlockDeviceIo::open(const QString& path, bool readOnly, bool truncate)
{
    close();
    m_error.clear();
#if defined(Q_OS_WIN)
    if (isRawDevicePath(path)) {
        const DWORD access = GENERIC_READ | (readOnly ? 0 : GENERIC_WRITE);
        HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), access,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            m_error = QString("CreateFile failed for %1 (error %2 - administrator "
                              "rights are required for raw device access).")
                          .arg(path).arg(GetLastError());
            return false;
        }
        // Sector size for alignment; a 4096 fallback is a multiple of every
        // real sector size in the field.
        DISK_GEOMETRY_EX geo; DWORD got = 0;
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0,
                            &geo, sizeof(geo), &got, nullptr)
            && geo.Geometry.BytesPerSector > 0)
            m_sector = qint64(geo.Geometry.BytesPerSector);
        else
            m_sector = 4096;
        GET_LENGTH_INFORMATION li;
        m_devSize = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                                    &li, sizeof(li), &got, nullptr)
                        ? qint64(li.Length.QuadPart) : -1;
        m_handle = h;
        m_raw = true;
        m_open = true;
        return true;
    }
#endif
    m_file.setFileName(path);
    QIODevice::OpenMode mode = readOnly ? QIODevice::ReadOnly : QIODevice::ReadWrite;
    if (truncate && !readOnly && !isRawDevicePath(path)) mode |= QIODevice::Truncate;
    if (!m_file.open(mode)) {
        m_error = QString("Cannot open %1: %2").arg(path, m_file.errorString());
        return false;
    }
    m_raw = false;
    m_open = true;
    return true;
}

void BlockDeviceIo::close()
{
#if defined(Q_OS_WIN)
    if (m_raw && m_handle) {
        CloseHandle(static_cast<HANDLE>(m_handle));
        m_handle = nullptr;
    }
#endif
    if (m_file.isOpen()) m_file.close();
    m_open = false;
    m_raw = false;
}

#if defined(Q_OS_WIN)
bool BlockDeviceIo::rawReadSpan(qint64 alignedOff, char* dst, qint64 alignedLen)
{
    HANDLE h = static_cast<HANDLE>(m_handle);
    LARGE_INTEGER li; li.QuadPart = alignedOff;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    qint64 done = 0;
    while (done < alignedLen) {
        const DWORD want = DWORD(qMin<qint64>(alignedLen - done, 16 * 1024 * 1024));
        DWORD got = 0;
        if (!ReadFile(h, dst + done, want, &got, nullptr) || got == 0) return false;
        done += got;
    }
    return true;
}

bool BlockDeviceIo::rawWriteSpan(qint64 alignedOff, const char* src, qint64 alignedLen)
{
    HANDLE h = static_cast<HANDLE>(m_handle);
    LARGE_INTEGER li; li.QuadPart = alignedOff;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    qint64 done = 0;
    while (done < alignedLen) {
        const DWORD want = DWORD(qMin<qint64>(alignedLen - done, 16 * 1024 * 1024));
        DWORD put = 0;
        if (!WriteFile(h, src + done, want, &put, nullptr) || put == 0) return false;
        done += put;
    }
    return true;
}
#endif

bool BlockDeviceIo::readAt(qint64 offset, char* data, qint64 len)
{
    if (!m_open || offset < 0 || len < 0) return false;
#if defined(Q_OS_WIN)
    if (m_raw) {
        // Bounce through a sector-aligned span (direct disk handles reject
        // unaligned I/O on Windows).
        const qint64 alignedOff = offset - (offset % m_sector);
        const qint64 end        = offset + len;
        const qint64 alignedEnd = ((end + m_sector - 1) / m_sector) * m_sector;
        QByteArray span(int(alignedEnd - alignedOff), Qt::Uninitialized);
        if (!rawReadSpan(alignedOff, span.data(), span.size())) return false;
        memcpy(data, span.constData() + (offset - alignedOff), size_t(len));
        return true;
    }
#endif
    if (!m_file.seek(offset)) return false;
    qint64 done = 0;
    while (done < len) {
        const qint64 got = m_file.read(data + done, len - done);
        if (got <= 0) return false;
        done += got;
    }
    return true;
}

bool BlockDeviceIo::writeAt(qint64 offset, const char* data, qint64 len)
{
    if (!m_open || offset < 0 || len < 0) return false;
#if defined(Q_OS_WIN)
    if (m_raw) {
        const qint64 alignedOff = offset - (offset % m_sector);
        const qint64 end        = offset + len;
        const qint64 alignedEnd = ((end + m_sector - 1) / m_sector) * m_sector;
        QByteArray span(int(alignedEnd - alignedOff), Qt::Uninitialized);
        // Read-modify-write unless the request happens to cover the whole span.
        if (alignedOff != offset || alignedEnd != end) {
            if (!rawReadSpan(alignedOff, span.data(), span.size())) return false;
        }
        memcpy(span.data() + (offset - alignedOff), data, size_t(len));
        return rawWriteSpan(alignedOff, span.constData(), span.size());
    }
#endif
    if (!m_file.seek(offset)) return false;
    qint64 done = 0;
    while (done < len) {
        const qint64 put = m_file.write(data + done, len - done);
        if (put <= 0) return false;
        done += put;
    }
    return true;
}

bool BlockDeviceIo::flush()
{
    if (!m_open) return false;
#if defined(Q_OS_WIN)
    if (m_raw) return FlushFileBuffers(static_cast<HANDLE>(m_handle)) != 0;
#endif
    return m_file.flush();
}

#if defined(Q_OS_WIN)
// ---------------------------------------------------------------------------
// WinVolumeLockGuard: lock + dismount every volume on the target physical
// drive so a whole-device format cannot race a mounted filesystem. Lock
// failure means the volume is in use - we refuse rather than force.
// ---------------------------------------------------------------------------
static int physicalDriveNumber(const QString& devicePath)
{
    const QString prefix = QStringLiteral("\\\\.\\PhysicalDrive");
    if (!devicePath.startsWith(prefix, Qt::CaseInsensitive)) return -1;
    bool ok = false;
    const int n = devicePath.mid(prefix.size()).toInt(&ok);
    return ok ? n : -1;
}

// Disk numbers a volume handle's extents live on.
static std::vector<int> volumeDiskNumbers(HANDLE vol)
{
    std::vector<int> out;
    QByteArray buf(sizeof(VOLUME_DISK_EXTENTS) + 32 * sizeof(DISK_EXTENT), 0);
    DWORD got = 0;
    if (!DeviceIoControl(vol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                         buf.data(), DWORD(buf.size()), &got, nullptr))
        return out;
    const auto* ext = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buf.constData());
    for (DWORD i = 0; i < ext->NumberOfDiskExtents; ++i)
        out.push_back(int(ext->Extents[i].DiskNumber));
    return out;
}

// Disk numbers hosting the running Windows installation.
static std::vector<int> systemDiskNumbers()
{
    std::vector<int> out;
    wchar_t windir[MAX_PATH] = {0};
    if (!GetWindowsDirectoryW(windir, MAX_PATH)) return out;
    const QString sysVol = QStringLiteral("\\\\.\\") + QString::fromWCharArray(windir).left(2);
    HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(sysVol.utf16()), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    out = volumeDiskNumbers(h);
    CloseHandle(h);
    return out;
}

// Try-lock a volume without dismounting it: succeeds only when nothing is
// using the filesystem. The lock is released immediately.
static bool volumeIsIdle(HANDLE vol)
{
    DWORD got = 0;
    if (!DeviceIoControl(vol, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &got, nullptr))
        return false;
    DeviceIoControl(vol, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &got, nullptr);
    return true;
}

QString winDeviceEraseBlocker(const QString& devicePath)
{
    if (!BlockDeviceIo::isRawDevicePath(devicePath))
        return QString();                                   // regular file: safe

    const std::vector<int> sysDisks = systemDiskNumbers();
    const int disk = physicalDriveNumber(devicePath);

    if (disk >= 0) {
        for (int d : sysDisks)
            if (d == disk)
                return QStringLiteral("This is the system disk Windows is running from - refusing.");
        // Probe every volume on the disk; any in-use one blocks the erase.
        wchar_t name[MAX_PATH];
        HANDLE it = FindFirstVolumeW(name, MAX_PATH);
        if (it == INVALID_HANDLE_VALUE) return QString();
        QString blocker;
        do {
            QString vol = QString::fromWCharArray(name);
            if (vol.endsWith(QLatin1Char('\\'))) vol.chop(1);
            HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(vol.utf16()),
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) continue;
            bool onTarget = false;
            for (int d : volumeDiskNumbers(h)) if (d == disk) onTarget = true;
            if (onTarget && !volumeIsIdle(h))
                blocker = QString("A volume on this disk (%1) is in use - close "
                                  "anything using it first.").arg(vol);
            CloseHandle(h);
            if (!blocker.isEmpty()) break;
        } while (FindNextVolumeW(it, name, MAX_PATH));
        FindVolumeClose(it);
        return blocker;
    }

    // "\\.\X:"-style volume path.
    HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(devicePath.utf16()),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return QString("Cannot open %1 (administrator rights required?).").arg(devicePath);
    QString blocker;
    const std::vector<int> volDisks = volumeDiskNumbers(h);
    for (int d : volDisks)
        for (int s : sysDisks)
            if (d == s) blocker = QStringLiteral("This volume lives on the system disk - refusing.");
    if (blocker.isEmpty() && !volumeIsIdle(h))
        blocker = QString("%1 is in use - close anything using it first.").arg(devicePath);
    CloseHandle(h);
    return blocker;
}

WinVolumeLockGuard::WinVolumeLockGuard(const QString& devicePath)
{
    const int disk = physicalDriveNumber(devicePath);
    if (disk < 0) { m_ok = true; return; }   // volume path or file: nothing to sweep

    wchar_t name[MAX_PATH];
    HANDLE it = FindFirstVolumeW(name, MAX_PATH);
    if (it == INVALID_HANDLE_VALUE) { m_ok = true; return; }
    m_ok = true;
    do {
        QString vol = QString::fromWCharArray(name);
        if (vol.endsWith(QLatin1Char('\\'))) vol.chop(1);   // CreateFile wants no slash
        HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(vol.utf16()),
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;            // no access = not ours to lock
        bool onTarget = false;
        for (int d : volumeDiskNumbers(h)) if (d == disk) onTarget = true;
        if (!onTarget) { CloseHandle(h); continue; }
        DWORD got = 0;
        if (!DeviceIoControl(h, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &got, nullptr)) {
            m_ok = false;
            m_reason = QString("A volume on this disk (%1) is in use and cannot be "
                               "locked - close anything using it, or eject and "
                               "re-insert the drive.").arg(vol);
            CloseHandle(h);
            break;
        }
        DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &got, nullptr);
        m_handles.push_back(h);                             // hold until destruction
    } while (FindNextVolumeW(it, name, MAX_PATH));
    FindVolumeClose(it);

    if (!m_ok) {
        for (void* h : m_handles) CloseHandle(static_cast<HANDLE>(h));
        m_handles.clear();
    }
}

WinVolumeLockGuard::~WinVolumeLockGuard()
{
    for (void* h : m_handles) {
        DWORD got = 0;
        DeviceIoControl(static_cast<HANDLE>(h), FSCTL_UNLOCK_VOLUME,
                        nullptr, 0, nullptr, 0, &got, nullptr);
        CloseHandle(static_cast<HANDLE>(h));
    }
}
#endif
