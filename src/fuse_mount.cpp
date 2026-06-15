// opencryptui-mount — FUSE driver that exposes an encrypted BlockVolume as a
// single virtual disk image, decrypting on read and encrypting on write, live.
//
// Usage:
//   opencryptui-mount <volume-file> <mountpoint> [--kdf Argon2] [--iter N]
//   # then: sudo mount -o loop <mountpoint>/disk.img /mnt/data
//   # (put any filesystem in the image: mkfs.ext4 on first use)
//
// The mountpoint contains exactly one file, "disk.img", whose byte range maps
// onto BlockVolume::readRange/writeRange. Reads decrypt on the fly; writes
// re-encrypt the touched blocks (each with a fresh nonce — see block_volume).
// On unmount the data is sealed; only ciphertext remains on disk.
//
// Cross-platform note: this is written against the libfuse3 high-level API,
// which WinFsp (Windows) and macFUSE (macOS) also expose, so the same source
// builds on all three with their respective FUSE packages installed.
//
// Built only when -DOCUI_ENABLE_FUSE=ON and libfuse3 is present.
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include "block_volume.h"
#include "encryptionengine.h"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <cstdio>
#include <cstring>
#include <termios.h>
#include <unistd.h>

// Single global mount state (one volume per process).
namespace {
EncryptionEngine* g_eng = nullptr;
BlockVolume::Handle g_vol;
const char* kImageName = "disk.img"; // the one file exposed in the mount

bool isImagePath(const char* path) {
    return path && path[0] == '/' && std::strcmp(path + 1, kImageName) == 0;
}
} // namespace

static int ocui_getattr(const char* path, struct stat* st, struct fuse_file_info*)
{
    std::memset(st, 0, sizeof(*st));
    if (std::strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0700;
        st->st_nlink = 2;
        return 0;
    }
    if (isImagePath(path)) {
        st->st_mode = S_IFREG | 0600;
        st->st_nlink = 1;
        st->st_size = BlockVolume::capacity(g_vol);
        return 0;
    }
    return -ENOENT;
}

static int ocui_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                        off_t, struct fuse_file_info*, enum fuse_readdir_flags)
{
    if (std::strcmp(path, "/") != 0) return -ENOENT;
    const fuse_fill_dir_flags zero = static_cast<fuse_fill_dir_flags>(0);
    filler(buf, ".",  nullptr, 0, zero);
    filler(buf, "..", nullptr, 0, zero);
    filler(buf, kImageName, nullptr, 0, zero);
    return 0;
}

static int ocui_open(const char* path, struct fuse_file_info* fi)
{
    if (!isImagePath(path)) return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY &&
        (fi->flags & O_ACCMODE) != O_RDWR &&
        (fi->flags & O_ACCMODE) != O_WRONLY)
        return -EACCES;
    return 0;
}

static int ocui_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info*)
{
    if (!isImagePath(path)) return -ENOENT;
    QByteArray out = BlockVolume::readRange(g_vol, offset, qint64(size));
    if (out.isEmpty() && size > 0 && offset < BlockVolume::capacity(g_vol)) return -EIO;
    std::memcpy(buf, out.constData(), out.size());
    return int(out.size());
}

static int ocui_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info*)
{
    if (!isImagePath(path)) return -ENOENT;
    QByteArray data(buf, int(size));
    if (!BlockVolume::writeRange(g_vol, offset, data)) return -EIO;
    return int(size);
}

// truncate/flush/fsync are no-ops: the image is fixed-size and writes are
// synchronous to the encrypted backing file.
static int ocui_truncate(const char*, off_t, struct fuse_file_info*) { return 0; }
static int ocui_flush(const char*, struct fuse_file_info*) { return 0; }
static int ocui_fsync(const char*, int, struct fuse_file_info*) { return 0; }

static const struct fuse_operations ocui_ops = []{
    struct fuse_operations o{};
    o.getattr  = ocui_getattr;
    o.readdir  = ocui_readdir;
    o.open     = ocui_open;
    o.read     = ocui_read;
    o.write    = ocui_write;
    o.truncate = ocui_truncate;
    o.flush    = ocui_flush;
    o.fsync    = ocui_fsync;
    return o;
}();

static QString promptPassword(const char* prompt)
{
    std::fprintf(stderr, "%s", prompt);
    std::fflush(stderr);
    termios oldt{}; tcgetattr(STDIN_FILENO, &oldt);
    termios noecho = oldt; noecho.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    char line[1024] = {0};
    if (!fgets(line, sizeof(line), stdin)) line[0] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::fprintf(stderr, "\n");
    QString p = QString::fromUtf8(line).trimmed();
    return p;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    if (argc < 3) {
        std::fprintf(stderr,
            "Usage: %s <volume-file> <mountpoint> [--kdf Argon2|Scrypt|PBKDF2] [--iter N]\n"
            "       %s --create <volume-file> --size <MiB> [--kdf ...] [--iter N]\n"
            "       %s --format-device <device> [--kdf ...] [--iter N]   (DESTRUCTIVE)\n",
            argv[0], argv[0], argv[0]);
        return 2;
    }

    QString kdf = "Argon2"; int iter = 3; bool doCreate = false, doFormatDev = false;
    qint64 sizeMiB = 0;
    QString volPath, mountPoint;
    QStringList positional;
    for (int i = 1; i < argc; ++i) {
        QString a = QString::fromUtf8(argv[i]);
        if (a == "--kdf" && i+1 < argc) kdf = QString::fromUtf8(argv[++i]);
        else if (a == "--iter" && i+1 < argc) iter = QString::fromUtf8(argv[++i]).toInt();
        else if (a == "--create") doCreate = true;
        else if (a == "--format-device") doFormatDev = true;
        else if (a == "--size" && i+1 < argc) sizeMiB = QString::fromUtf8(argv[++i]).toLongLong();
        else positional << a;
    }

    EncryptionEngine eng;
    g_eng = &eng;

    if (doFormatDev) {
        if (positional.isEmpty()) { std::fprintf(stderr, "--format-device needs a <device>\n"); return 2; }
        const QString dev = positional.at(0);
        // Refuse early if obviously unsafe, with a clear reason.
        const QString blocker = BlockVolume::deviceEraseBlocker(dev);
        if (!blocker.isEmpty()) { std::fprintf(stderr, "Refusing: %s\n", blocker.toUtf8().constData()); return 1; }
        const qint64 sz = BlockVolume::deviceSizeBytes(dev);
        std::fprintf(stderr,
            "\n*** DESTRUCTIVE: this ERASES EVERYTHING on %s ***\n"
            "    size: %.1f MiB\n"
            "Type exactly  ERASE %s  to proceed: ",
            dev.toUtf8().constData(),
            sz > 0 ? double(sz)/(1024*1024) : 0.0,
            dev.toUtf8().constData());
        std::fflush(stderr);
        char line[1024] = {0};
        if (!fgets(line, sizeof(line), stdin)) return 1;
        QString typed = QString::fromUtf8(line).trimmed();
        if (typed != QString("ERASE %1").arg(dev)) {
            std::fprintf(stderr, "Confirmation did not match. Aborted.\n");
            return 1;
        }
        QString p1 = promptPassword("New volume password: ");
        QString p2 = promptPassword("Confirm password:    ");
        if (p1 != p2) { std::fprintf(stderr, "Passwords do not match.\n"); return 1; }
        QString err;
        int lastPct = -1;
        bool ok = BlockVolume::formatDeviceWhole(eng, dev, p1, kdf, iter, &err,
            [&lastPct](int pct){ if (pct != lastPct) { std::fprintf(stderr, "\rFormatting… %d%%", pct); std::fflush(stderr); lastPct = pct; } });
        std::fprintf(stderr, "\n");
        if (!ok) { std::fprintf(stderr, "Format failed: %s\n", err.toUtf8().constData()); return 1; }
        std::fprintf(stderr, "Done. %s is now an encrypted volume. Mount it with:\n"
                             "  %s %s <mountpoint>\n"
                             "then put a filesystem on <mountpoint>/disk.img.\n",
                     dev.toUtf8().constData(), argv[0], dev.toUtf8().constData());
        return 0;
    }

    if (doCreate) {
        if (positional.isEmpty() || sizeMiB <= 0) {
            std::fprintf(stderr, "--create needs <volume-file> and --size <MiB>\n");
            return 2;
        }
        volPath = positional.at(0);
        QString p1 = promptPassword("New volume password: ");
        QString p2 = promptPassword("Confirm password:    ");
        if (p1 != p2) { std::fprintf(stderr, "Passwords do not match.\n"); return 1; }
        const quint32 bs = BlockVolume::DEFAULT_BLOCK_SIZE;
        const quint64 nb = quint64(sizeMiB) * 1024 * 1024 / bs;
        QString err;
        if (!BlockVolume::create(eng, volPath, p1, kdf, iter, bs, nb, &err)) {
            std::fprintf(stderr, "Create failed: %s\n", err.toUtf8().constData());
            return 1;
        }
        std::fprintf(stderr, "Created %lld MiB volume at %s (%llu blocks of %u).\n",
                     (long long)sizeMiB, volPath.toUtf8().constData(),
                     (unsigned long long)nb, bs);
        std::fprintf(stderr, "Mount it, then: mkfs.ext4 <mountpoint>/disk.img && "
                             "sudo mount -o loop <mountpoint>/disk.img /mnt/data\n");
        return 0;
    }

    if (positional.size() < 2) {
        std::fprintf(stderr, "Need <volume-file> and <mountpoint>.\n");
        return 2;
    }
    volPath = positional.at(0);
    mountPoint = positional.at(1);

    QString pw = promptPassword("Volume password: ");
    g_vol = BlockVolume::open(eng, volPath, pw, kdf, iter);
    if (!g_vol.ok) {
        std::fprintf(stderr, "Open failed: %s\n", g_vol.error.toUtf8().constData());
        return 1;
    }
    // Keep the mountpoint bytes alive for the whole fuse_main call.
    QByteArray mpBytes = mountPoint.toUtf8();
    std::fprintf(stderr, "Mounted %lld-byte image at %s/%s — write a filesystem to it, "
                         "then loop-mount.\n",
                 (long long)BlockVolume::capacity(g_vol),
                 mpBytes.constData(), kImageName);

    // Hand control to FUSE. Build a minimal argv: program + mountpoint + -f (foreground).
    char optF[] = "-f";
    char* fargv[3] = { argv[0], mpBytes.data(), optF };
    int rc = fuse_main(3, fargv, &ocui_ops, nullptr);

    BlockVolume::close(g_vol);
    return rc;
}
