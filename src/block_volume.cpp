#include "block_volume.h"
#include "block_device_io.h"
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QFileInfo>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <cstring>
#if defined(Q_OS_MACOS)
#  include <sys/param.h>
#  include <sys/ucred.h>
#  include <sys/mount.h>   // getmntinfo
#endif

static const char    BV_MAGIC[8] = {'O','C','U','I','B','L','K','1'};
static constexpr int BV_HDR_PT   = 8 + 1 + 3 + 4 + 8 + 32; // 56
static constexpr int BV_SALT     = 32;

static void put32(unsigned char* p, quint32 v) { for (int i=0;i<4;++i) p[i]=(v>>(24-8*i))&0xFF; }
static void put64(unsigned char* p, quint64 v) { for (int i=0;i<8;++i) p[i]=(v>>(56-8*i))&0xFF; }
static quint32 get32(const unsigned char* p){ quint32 v=0; for(int i=0;i<4;++i) v=(v<<8)|p[i]; return v; }
static quint64 get64(const unsigned char* p){ quint64 v=0; for(int i=0;i<8;++i) v=(v<<8)|p[i]; return v; }

// AES-256-GCM one-shot helpers for the header.
static bool gcmEnc(const QByteArray& key, const QByteArray& nonce, const QByteArray& pt,
                   QByteArray& ct, QByteArray& tag)
{
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    ct.resize(pt.size()); tag.resize(BlockVolume::TAG_LEN);
    int o=0,f=0; bool ok =
        EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)==1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr)==1 &&
        EVP_EncryptInit_ex(c, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData()))==1 &&
        EVP_EncryptUpdate(c, reinterpret_cast<unsigned char*>(ct.data()), &o,
            reinterpret_cast<const unsigned char*>(pt.constData()), pt.size())==1 &&
        EVP_EncryptFinal_ex(c, reinterpret_cast<unsigned char*>(ct.data())+o, &f)==1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, BlockVolume::TAG_LEN, tag.data())==1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}
static bool gcmDec(const QByteArray& key, const QByteArray& nonce, const QByteArray& ct,
                   const QByteArray& tag, QByteArray& pt)
{
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    pt.resize(ct.size());
    int o=0,f=0; bool ok =
        EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)==1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr)==1 &&
        EVP_DecryptInit_ex(c, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData()))==1 &&
        EVP_DecryptUpdate(c, reinterpret_cast<unsigned char*>(pt.data()), &o,
            reinterpret_cast<const unsigned char*>(ct.constData()), ct.size())==1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, BlockVolume::TAG_LEN,
            const_cast<char*>(tag.constData()))==1 &&
        EVP_DecryptFinal_ex(c, reinterpret_cast<unsigned char*>(pt.data())+o, &f) > 0;
    EVP_CIPHER_CTX_free(c);
    if (!ok) { sodium_memzero(pt.data(), pt.size()); pt.clear(); }
    return ok;
}

// Shared core for create() (new file, truncates) and createOnDevice()
// (existing device/backing, must NOT truncate or delete on failure).
bool BlockVolume::createImpl(EncryptionEngine& eng, const QString& path,
                       const QString& password, const QString& kdf, int iterations,
                       quint32 blockSize, quint64 blockCount, bool truncate, bool ownsFile,
                       QString* error, const ProgressFn& progress)
{
    auto fail=[&](const QString&m){ if(error)*error=m; SECURE_LOG(ERROR_LEVEL,"BlockVolume",m); return false; };
    if (blockSize < 512 || (blockSize % 16) != 0) return fail("Block size must be a multiple of 16 and >= 512.");
    if (blockCount == 0) return fail("Block count must be > 0.");

    // Header key + random data key.
    QByteArray salt(BV_SALT,0), hnonce(NONCE_LEN,0), dataKey(32,0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()),BV_SALT)!=1) return fail("RNG failed.");
    if (RAND_bytes(reinterpret_cast<unsigned char*>(hnonce.data()),NONCE_LEN)!=1) return fail("RNG failed.");
    if (RAND_bytes(reinterpret_cast<unsigned char*>(dataKey.data()),32)!=1) return fail("RNG failed.");

    QByteArray master = eng.deriveKey(password, salt, {}, kdf, iterations);
    if (master.size() < 32) { if(!master.isEmpty())sodium_memzero(master.data(),master.size()); return fail("Key derivation failed."); }
    QByteArray headerKey = master.left(32); sodium_memzero(master.data(),master.size());

    QByteArray pt(BV_HDR_PT,0);
    unsigned char* p = reinterpret_cast<unsigned char*>(pt.data());
    memcpy(p, BV_MAGIC, 8); p[8]=1;
    put32(p+12, blockSize); put64(p+16, blockCount); memcpy(p+24, dataKey.constData(), 32);

    QByteArray ct, tag;
    bool hok = gcmEnc(headerKey, hnonce, pt, ct, tag);
    sodium_memzero(headerKey.data(), headerKey.size()); sodium_memzero(pt.data(), pt.size());
    if (!hok) { sodium_memzero(dataKey.data(),dataKey.size()); return fail("Header encryption failed."); }

    BlockDeviceIo io;
    if (!io.open(path, /*readOnly=*/false, truncate)) {
        sodium_memzero(dataKey.data(),dataKey.size());
        return fail(io.error().isEmpty() ? QStringLiteral("Cannot open path.") : io.error());
    }
    if (ownsFile) QFile::setPermissions(path, QFileDevice::ReadOwner|QFileDevice::WriteOwner);

    // Header slot: salt|nonce|ct|tag then random pad to HEADER_SIZE.
    QByteArray header = salt + hnonce + ct + tag;
    QByteArray pad(HEADER_SIZE - header.size(), 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(pad.data()), pad.size());
    const QByteArray hdr = header + pad;
    if (!io.writeAt(0, hdr.constData(), hdr.size())) {
        io.close(); if (ownsFile) QFile::remove(path); sodium_memzero(dataKey.data(),dataKey.size()); return fail("Header write failed.");
    }

    // Initialise every block to encrypted zeros (fresh nonce each).
    QByteArray zeros(blockSize, 0);
    Handle h; h.ok=true; h.path=path; h.blockSize=blockSize; h.blockCount=blockCount; h.dataKey=dataKey;
    io.close();
    bool initOk = true;
    int lastPct = -1;
    if (progress) progress(0);
    for (quint64 i=0;i<blockCount && initOk;++i) {
        initOk = writeBlock(h, i, zeros);
        if (progress) {
            const int pct = int((i + 1) * 100 / blockCount);
            if (pct != lastPct) { progress(pct); lastPct = pct; } // whole-percent only
        }
    }
    sodium_memzero(dataKey.data(),dataKey.size());
    sodium_memzero(h.dataKey.data(), h.dataKey.size());
    if (!initOk) { if (ownsFile) QFile::remove(path); return fail("Block initialisation failed."); }
    return true;
}

// Public create(): new file backing - truncate + own the file.
bool BlockVolume::create(EncryptionEngine& eng, const QString& path,
                         const QString& password, const QString& kdf, int iterations,
                         quint32 blockSize, quint64 blockCount, QString* error,
                         const ProgressFn& progress)
{
    return createImpl(eng, path, password, kdf, iterations, blockSize, blockCount,
                      /*truncate=*/true, /*ownsFile=*/true, error, progress);
}

// Format an EXISTING device/backing of `sizeBytes` as an encrypted volume.
// Does not truncate or delete the backing. blockCount is sized to fill it.
// WARNING: this overwrites the entire device - the caller MUST confirm with the
// user and ensure the device is unmounted and not a system disk.
bool BlockVolume::createOnDevice(EncryptionEngine& eng, const QString& devicePath,
                                 const QString& password, const QString& kdf, int iterations,
                                 quint32 blockSize, qint64 sizeBytes, QString* error,
                                 const ProgressFn& progress)
{
    if (sizeBytes < HEADER_SIZE + onDiskBlockSize(blockSize)) {
        if (error) *error = "Device too small to hold even one block.";
        return false;
    }
    const quint64 blockCount =
        quint64((sizeBytes - HEADER_SIZE) / onDiskBlockSize(blockSize));
    return createImpl(eng, devicePath, password, kdf, iterations, blockSize, blockCount,
                      /*truncate=*/false, /*ownsFile=*/false, error, progress);
}

BlockVolume::Handle BlockVolume::open(EncryptionEngine& eng, const QString& path,
                                      const QString& password, const QString& kdf, int iterations)
{
    Handle h;
    BlockDeviceIo io;
    if (!io.open(path, /*readOnly=*/true)) { h.error="Cannot open volume."; return h; }
    QByteArray pre(BV_SALT + NONCE_LEN + BV_HDR_PT + TAG_LEN, 0);
    const bool got = io.readAt(0, pre.data(), pre.size());
    io.close();
    if (!got) { h.error="Volume too small."; return h; }

    QByteArray salt=pre.left(BV_SALT), hnonce=pre.mid(BV_SALT,NONCE_LEN);
    QByteArray ct=pre.mid(BV_SALT+NONCE_LEN, BV_HDR_PT), tag=pre.right(TAG_LEN);

    QByteArray master = eng.deriveKey(password, salt, {}, kdf, iterations);
    if (master.size()<32){ if(!master.isEmpty())sodium_memzero(master.data(),master.size()); h.error="Key derivation failed."; return h; }
    QByteArray headerKey=master.left(32); sodium_memzero(master.data(),master.size());

    QByteArray pt;
    bool ok = gcmDec(headerKey, hnonce, ct, tag, pt);
    sodium_memzero(headerKey.data(), headerKey.size());
    if (!ok) { h.error="Wrong password or not a volume."; return h; }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(pt.constData());
    if (sodium_memcmp(p, BV_MAGIC, 8)!=0) { sodium_memzero(pt.data(),pt.size()); h.error="Bad volume magic."; return h; }

    h.blockSize  = get32(p+12);
    h.blockCount = get64(p+16);
    h.dataKey    = QByteArray(reinterpret_cast<const char*>(p+24), 32);
    sodium_memzero(pt.data(), pt.size());
    h.ok = true; h.path = path;
    return h;
}

QByteArray BlockVolume::readBlock(const Handle& h, quint64 index)
{
    if (!h.ok || index >= h.blockCount) return {};
    BlockDeviceIo io;
    if (!io.open(h.path, /*readOnly=*/true)) return {};
    const qint64 off = HEADER_SIZE + qint64(index) * onDiskBlockSize(h.blockSize);
    QByteArray raw(int(onDiskBlockSize(h.blockSize)), 0);
    const bool got = io.readAt(off, raw.data(), raw.size());
    io.close();
    if (!got) return {};
    QByteArray nonce = raw.left(NONCE_LEN);
    QByteArray ct = raw.mid(NONCE_LEN, h.blockSize);
    QByteArray tag = raw.right(TAG_LEN);
    QByteArray pt;
    if (!gcmDec(h.dataKey, nonce, ct, tag, pt)) return {}; // tamper / wrong key
    return pt;
}

bool BlockVolume::writeBlock(const Handle& h, quint64 index, const QByteArray& block)
{
    if (!h.ok || index >= h.blockCount) return false;
    if (block.size() != int(h.blockSize)) return false;
    QByteArray nonce(NONCE_LEN, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), NONCE_LEN) != 1) return false;
    QByteArray ct, tag;
    if (!gcmEnc(h.dataKey, nonce, block, ct, tag)) return false;
    BlockDeviceIo io;
    if (!io.open(h.path, /*readOnly=*/false)) return false; // never truncates
    const qint64 off = HEADER_SIZE + qint64(index) * onDiskBlockSize(h.blockSize);
    QByteArray rec = nonce + ct + tag;
    bool ok = io.writeAt(off, rec.constData(), rec.size());
    io.flush(); io.close();
    return ok;
}

QByteArray BlockVolume::readRange(const Handle& h, qint64 offset, qint64 length)
{
    if (!h.ok || offset < 0 || length < 0) return {};
    const qint64 cap = capacity(h);
    if (offset >= cap) return {};
    length = qMin(length, cap - offset);
    QByteArray out; out.reserve(int(length));
    qint64 pos = offset;
    while (pos < offset + length) {
        const quint64 idx = quint64(pos / h.blockSize);
        const int within = int(pos % h.blockSize);
        QByteArray blk = readBlock(h, idx);
        if (blk.size() != int(h.blockSize)) return {};
        const int take = int(qMin<qint64>(h.blockSize - within, offset + length - pos));
        out.append(blk.constData() + within, take);
        pos += take;
    }
    return out;
}

bool BlockVolume::writeRange(const Handle& h, qint64 offset, const QByteArray& data)
{
    if (!h.ok || offset < 0) return false;
    const qint64 cap = capacity(h);
    if (offset + data.size() > cap) return false;
    qint64 pos = offset; int srcPos = 0;
    while (srcPos < data.size()) {
        const quint64 idx = quint64(pos / h.blockSize);
        const int within = int(pos % h.blockSize);
        const int chunk = int(qMin<qint64>(h.blockSize - within, data.size() - srcPos));
        QByteArray blk;
        if (within == 0 && chunk == int(h.blockSize)) {
            blk = data.mid(srcPos, chunk);                 // full-block overwrite
        } else {
            blk = readBlock(h, idx);                       // read-modify-write
            if (blk.size() != int(h.blockSize)) return false;
            memcpy(blk.data() + within, data.constData() + srcPos, chunk);
        }
        if (!writeBlock(h, idx, blk)) return false;
        pos += chunk; srcPos += chunk;
    }
    return true;
}

QString BlockVolume::deviceEraseBlocker(const QString& path)
{
#if defined(Q_OS_LINUX)
    // Refuse if the device, or any partition on it, is currently mounted.
    QFile mounts("/proc/mounts");
    if (mounts.open(QIODevice::ReadOnly)) {
        const QList<QByteArray> lines = mounts.readAll().split('\n');
        mounts.close();
        for (const QByteArray& line : lines) {
            const QList<QByteArray> f = line.simplified().split(' ');
            if (f.size() < 2) continue;
            const QString src = QString::fromLocal8Bit(f[0]);
            const QString mnt = QString::fromLocal8Bit(f[1]);
            // /dev/sdb matches /dev/sdb and /dev/sdb1, /dev/sdb2, ...
            if (src == path || (src.startsWith(path) && path.startsWith("/dev/"))) {
                return QString("%1 is mounted at %2 - unmount it first (it must not be in use).")
                    .arg(src, mnt);
            }
        }
    }
    return QString(); // looks safe
#elif defined(Q_OS_MACOS)
    // Refuse if the device, or any slice on it, is currently mounted
    // ("diskutil unmountDisk diskN" is the fix). Plain files are safe.
    if (!path.startsWith("/dev/")) return QString();
    struct statfs* mnts = nullptr;
    const int n = getmntinfo(&mnts, MNT_NOWAIT);
    for (int i = 0; i < n; ++i) {
        const QString src = QString::fromLocal8Bit(mnts[i].f_mntfromname);
        // /dev/disk2 matches /dev/disk2 and its slices /dev/disk2s1, ... -
        // require the 's' so /dev/disk2 does not match /dev/disk20.
        if (src == path || src.startsWith(path + QLatin1String("s"))) {
            return QString("%1 is mounted at %2 - unmount it first "
                           "(diskutil unmountDisk).")
                .arg(src, QString::fromLocal8Bit(mnts[i].f_mntonname));
        }
    }
    return QString(); // looks safe
#elif defined(Q_OS_WIN)
    return winDeviceEraseBlocker(path);
#else
    Q_UNUSED(path);
    return QString("Raw whole-device encryption is not supported on this OS yet.");
#endif
}

bool BlockVolume::formatDeviceWhole(EncryptionEngine& eng, const QString& devicePath,
                                    const QString& password, const QString& kdf, int iterations,
                                    QString* error, const ProgressFn& progress, quint32 blockSize)
{
    auto fail=[&](const QString&m){ if(error)*error=m; SECURE_LOG(ERROR_LEVEL,"BlockVolume",m); return false; };
    const QString blocker = deviceEraseBlocker(devicePath);
    if (!blocker.isEmpty()) return fail(blocker);
    const qint64 size = deviceSizeBytes(devicePath);
    if (size <= 0) return fail("Could not determine the device size (need a real block "
                               "device or a pre-sized file).");
#if defined(Q_OS_WIN)
    // Hold every volume on the target disk locked + dismounted for the whole
    // format, so a mounted filesystem can never race the erase.
    WinVolumeLockGuard lock(devicePath);
    if (!lock.ok()) return fail(lock.reason());
#endif
    return createOnDevice(eng, devicePath, password, kdf, iterations, blockSize, size,
                          error, progress);
}

qint64 BlockVolume::deviceSizeBytes(const QString& path)
{
    // Raw block devices report size 0 via stat; BlockDeviceIo queries the
    // kernel per-OS (BLKGETSIZE64 / DKIOCGETBLOCK* / IOCTL_DISK_GET_LENGTH_INFO)
    // and falls back to the regular-file size otherwise.
    return BlockDeviceIo::sizeBytes(path);
}

void BlockVolume::close(Handle& h)
{
    if (!h.dataKey.isEmpty()) sodium_memzero(h.dataKey.data(), h.dataKey.size());
    h.dataKey.clear();
    h.ok = false;
}
