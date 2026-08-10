// Cross-platform backing I/O for BlockVolume: regular files everywhere, plus
// raw block devices on Linux (/dev/sdX), macOS (/dev/diskN) and Windows
// (\\.\PhysicalDriveN, \\.\X:).
//
// Why this exists: on POSIX a buffered block-device node accepts ordinary
// unaligned read/write, so QFile is enough. On Windows a direct disk or
// volume handle is always non-cached and every read/write MUST be aligned to
// the sector size - and our on-disk block records (nonce||ct||tag) are not.
// The Windows path therefore bounce-buffers each request through a
// sector-aligned span (read-modify-write for writes).
#ifndef OPENCRYPTUI_BLOCK_DEVICE_IO_H
#define OPENCRYPTUI_BLOCK_DEVICE_IO_H

#include <QString>
#include <QFile>
#include <vector>

class BlockDeviceIo
{
public:
    BlockDeviceIo() = default;
    ~BlockDeviceIo();
    BlockDeviceIo(const BlockDeviceIo&) = delete;
    BlockDeviceIo& operator=(const BlockDeviceIo&) = delete;

    // True if `path` names a raw device rather than a regular file:
    // "\\.\..." on Windows, "/dev/..." elsewhere.
    static bool isRawDevicePath(const QString& path);

    // Size in bytes: real device size for raw device paths (BLKGETSIZE64 /
    // DKIOCGETBLOCKCOUNT*DKIOCGETBLOCKSIZE / IOCTL_DISK_GET_LENGTH_INFO),
    // else the regular-file size. -1 on failure.
    static qint64 sizeBytes(const QString& path);

    // Open for reading (readOnly=true) or read+write. `truncate` is honoured
    // only for regular files (devices are never truncated). Returns false and
    // sets error() on failure.
    bool open(const QString& path, bool readOnly, bool truncate = false);
    void close();
    bool isOpen() const { return m_open; }
    QString error() const { return m_error; }

    // Positioned I/O. Exact-length or fail; no short reads/writes.
    bool readAt(qint64 offset, char* data, qint64 len);
    bool writeAt(qint64 offset, const char* data, qint64 len);
    bool flush();

private:
    bool    m_open = false;
    bool    m_raw  = false;      // raw Windows device handle in use
    QString m_error;
    QFile   m_file;              // used for all POSIX paths + Windows regular files
#if defined(Q_OS_WIN)
    void*   m_handle = nullptr;  // HANDLE, avoids windows.h in this header
    qint64  m_sector = 512;      // device sector size for alignment
    qint64  m_devSize = -1;
    bool rawReadSpan(qint64 alignedOff, char* dst, qint64 alignedLen);
    bool rawWriteSpan(qint64 alignedOff, const char* src, qint64 alignedLen);
#endif
};

#if defined(Q_OS_WIN)
// Empty if the device looks safe to erase; otherwise a human-readable reason:
// the system disk, or a volume on the disk that is in use (probe-locked
// without dismounting). Regular files are always safe.
QString winDeviceEraseBlocker(const QString& devicePath);

// Locks and dismounts every mounted volume that lives on the given physical
// drive for the lifetime of this object (the Windows equivalent of "unmount
// it first"). Construction fails (ok()==false, reason()) if any volume is in
// use. No-op for non-PhysicalDrive paths.
class WinVolumeLockGuard
{
public:
    explicit WinVolumeLockGuard(const QString& devicePath);
    ~WinVolumeLockGuard();
    bool ok() const { return m_ok; }
    QString reason() const { return m_reason; }

private:
    bool m_ok = false;
    QString m_reason;
    std::vector<void*> m_handles; // HANDLEs held until destruction
};
#endif

#endif // OPENCRYPTUI_BLOCK_DEVICE_IO_H
