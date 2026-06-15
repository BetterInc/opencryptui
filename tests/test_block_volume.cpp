// Authenticated random-access block volume test — the substrate for mounting.
//
// Critical property under test: in-place block REWRITES must not reuse a GCM
// nonce. We write the same block twice with different content and confirm the
// on-disk nonce changes (no nonce reuse) and both reads are correct.
//
// Also: fresh volume reads as zeros, random-order block writes round-trip,
// byte-range read/modify/write works across block boundaries, wrong password
// is rejected, and tampering any block fails authentication.
#include "block_volume.h"
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QByteArray>
#include <cstdio>
#include <cstring>

static int s_failures = 0;
static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
}

static QByteArray rngData(int size, quint32 seed)
{
    QByteArray b(size, 0);
    quint32 r = seed;
    for (int i = 0; i < size; ++i) { r = r*1664525u + 1013904223u; b[i] = char(r >> 24); }
    return b;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    const QString path = dir.filePath("vol.bin");
    const QString pw = "block-volume-pw";
    const QString kdf = "Argon2";
    const int iters = 3;
    const quint32 BS = 4096;
    const quint64 NB = 64; // 256 KiB volume

    // Progress callback must fire monotonically and reach 100.
    QString err;
    int lastPct = -1; bool monotonic = true; bool reached100 = false; int calls = 0;
    bool ok = BlockVolume::create(eng, path, pw, kdf, iters, BS, NB, &err,
        [&](int pct){ ++calls; if (pct < lastPct) monotonic=false; lastPct=pct; if (pct==100) reached100=true; });
    check(ok, ("create" + (ok ? QString() : ": " + err)).toUtf8().constData());
    check(calls > 0, "progress callback was invoked");
    check(monotonic, "progress is monotonic (never goes backward)");
    check(reached100, "progress reaches 100%");

    auto h = BlockVolume::open(eng, path, pw, kdf, iters);
    check(h.ok, ("open" + (h.ok ? QString() : ": " + h.error)).toUtf8().constData());
    check(h.blockSize == BS && h.blockCount == NB, "header params round-trip");

    // Fresh volume reads as zeros.
    {
        QByteArray b0 = BlockVolume::readBlock(h, 0);
        QByteArray b63 = BlockVolume::readBlock(h, 63);
        check(b0 == QByteArray(BS, 0), "fresh block 0 reads as zeros");
        check(b63 == QByteArray(BS, 0), "fresh block 63 reads as zeros");
    }

    // Random-order writes round-trip.
    {
        QByteArray a = rngData(BS, 0x11), b = rngData(BS, 0x22), c = rngData(BS, 0x33);
        check(BlockVolume::writeBlock(h, 10, a), "write block 10");
        check(BlockVolume::writeBlock(h, 63, c), "write block 63");
        check(BlockVolume::writeBlock(h, 0,  b), "write block 0");
        check(BlockVolume::readBlock(h, 10) == a, "block 10 round-trips");
        check(BlockVolume::readBlock(h, 63) == c, "block 63 round-trips");
        check(BlockVolume::readBlock(h, 0)  == b, "block 0 round-trips");
        check(BlockVolume::readBlock(h, 5) == QByteArray(BS, 0), "unwritten block 5 still zeros");
    }

    // NONCE-REUSE GUARD: rewrite the same block with different content; the
    // 12-byte on-disk nonce must change between writes.
    {
        auto nonceOf = [&](quint64 idx) {
            QFile f(path); f.open(QIODevice::ReadOnly);
            f.seek(BlockVolume::HEADER_SIZE + qint64(idx) * BlockVolume::onDiskBlockSize(BS));
            QByteArray n = f.read(BlockVolume::NONCE_LEN); f.close(); return n;
        };
        BlockVolume::writeBlock(h, 20, rngData(BS, 0xAB));
        QByteArray n1 = nonceOf(20);
        BlockVolume::writeBlock(h, 20, rngData(BS, 0xCD));
        QByteArray n2 = nonceOf(20);
        check(n1 != n2, "rewrite uses a FRESH nonce (no GCM nonce reuse)");
        check(BlockVolume::readBlock(h, 20) == rngData(BS, 0xCD), "rewrite content correct");
    }

    // Byte-range read/modify/write across block boundaries.
    {
        QByteArray span = rngData(BS * 2 + 123, 0x77);
        check(BlockVolume::writeRange(h, BS - 50, span), "writeRange across 3 blocks");
        QByteArray back = BlockVolume::readRange(h, BS - 50, span.size());
        check(back == span, "readRange returns what was written");
    }

    // Tamper a data block → read fails authentication.
    {
        QFile f(path);
        if (f.open(QIODevice::ReadWrite)) {
            qint64 at = BlockVolume::HEADER_SIZE + 10 * BlockVolume::onDiskBlockSize(BS) + BlockVolume::NONCE_LEN + 4;
            f.seek(at); char x; f.read(&x,1); x ^= 0x80; f.seek(at); f.write(&x,1); f.close();
        }
        QByteArray b = BlockVolume::readBlock(h, 10);
        check(b.isEmpty(), "tampered block fails authentication");
    }
    BlockVolume::close(h);

    // Wrong password rejected.
    {
        auto bad = BlockVolume::open(eng, path, "wrong-pw", kdf, iters);
        check(!bad.ok, "wrong password rejected");
    }

    if (s_failures) { std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures); return 1; }
    std::fprintf(stderr, "ALL BLOCK-VOLUME TESTS PASSED\n");
    return 0;
}
