// Authenticated, random-access encrypted block device backed by a file.
//
// This is the substrate a mounted volume sits on: the FUSE driver presents a
// virtual disk image whose reads/writes map onto readBlock()/writeBlock().
//
// SECURITY — nonce handling: a mountable volume rewrites blocks in place, so a
// deterministic per-index nonce would be REUSED across writes (catastrophic
// for AES-GCM: leaks the auth subkey, enables forgery). Therefore every block
// write picks a FRESH random 96-bit nonce, stored alongside the block. Each
// (key, nonce) pair is thus used once.
//
// On-disk layout:
//   [0 .. 4096)  header: salt(32) ‖ nonce(12) ‖ AES-256-GCM(hdr)+tag ‖ random pad
//   then blockCount blocks, each: nonce(12) ‖ AES-256-GCM(block)+tag(16)
//
// header plaintext = magic(8) "OCUIBLK1" ‖ ver(1) ‖ pad(3) ‖ blockSize(4 BE)
//                    ‖ blockCount(8 BE) ‖ dataKey(32)
//
// create() initialises every block to encrypted zeros, so a fresh volume reads
// back as a zeroed disk (no ambiguity between "unwritten" and "tampered").
#ifndef OPENCRYPTUI_BLOCK_VOLUME_H
#define OPENCRYPTUI_BLOCK_VOLUME_H

#include <QString>
#include <QByteArray>
#include <functional>

class EncryptionEngine;

class BlockVolume {
public:
    static constexpr qint64 HEADER_SIZE = 4096;
    static constexpr int    NONCE_LEN   = 12;
    static constexpr int    TAG_LEN     = 16;
    static constexpr quint32 DEFAULT_BLOCK_SIZE = 4096;

    // An open volume: holds the data key in memory. Wipe via close().
    struct Handle {
        bool       ok = false;
        QString    path;
        quint32    blockSize  = 0;
        quint64    blockCount = 0;
        QByteArray dataKey;     // 32 bytes; sensitive
        QString    error;
    };

    // On-disk bytes for one block (nonce + ciphertext + tag).
    static qint64 onDiskBlockSize(quint32 blockSize) {
        return NONCE_LEN + qint64(blockSize) + TAG_LEN;
    }
    // Total file size for a volume.
    static qint64 fileSize(quint32 blockSize, quint64 blockCount) {
        return HEADER_SIZE + qint64(blockCount) * onDiskBlockSize(blockSize);
    }
    // Logical capacity (what a mounted FS sees).
    static qint64 capacity(const Handle& h) {
        return qint64(h.blockCount) * h.blockSize;
    }

    // Optional progress sink: called with 0..100 as the volume is initialised.
    // Useful when creating a large container (e.g. on a USB) so the UI can show
    // a live percentage. Invoked only on whole-percent changes.
    using ProgressFn = std::function<void(int)>;

    // Create a new volume (initialised to encrypted zeros). Returns false +
    // sets *error on failure. `progress` may be empty.
    static bool create(EncryptionEngine& eng, const QString& path,
                       const QString& password, const QString& kdf, int iterations,
                       quint32 blockSize, quint64 blockCount, QString* error = nullptr,
                       const ProgressFn& progress = {});

    // Open an existing volume; the returned Handle carries the data key.
    static Handle open(EncryptionEngine& eng, const QString& path,
                       const QString& password, const QString& kdf, int iterations);

    // Random-access block I/O. readBlock returns blockSize bytes (or empty on
    // auth failure / OOB). writeBlock requires exactly blockSize bytes.
    static QByteArray readBlock(const Handle& h, quint64 index);
    static bool       writeBlock(const Handle& h, quint64 index, const QByteArray& block);

    // Byte-range helpers for the FUSE layer (read-modify-write across blocks).
    static QByteArray readRange(const Handle& h, qint64 offset, qint64 length);
    static bool       writeRange(const Handle& h, qint64 offset, const QByteArray& data);

    // Zero + release the in-memory key.
    static void close(Handle& h);
};

#endif // OPENCRYPTUI_BLOCK_VOLUME_H
