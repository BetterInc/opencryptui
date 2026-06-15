// Deniable encrypted container with optional hidden volume.
//
// Why a new format (not the disk JSON header): the disk header stores a
// plaintext "magic" + "hasHiddenVolume" flag, which announces both that the
// volume is encrypted AND that a hidden volume exists — fatal for deniability.
// A deniable container must be indistinguishable from random data end to end.
//
// On-disk layout (fixed-size file of N bytes, every byte random/ciphertext):
//
//   [0 .. 64KiB)        outer header slot   (always present)
//   [64KiB .. 128KiB)   hidden header slot  (always present; random if no
//                                            hidden volume — indistinguishable
//                                            from an encrypted hidden header)
//   [128KiB .. N)       data area
//                         outer volume data grows from 128KiB forward
//                         hidden volume data sits at the TAIL (end backward)
//
// Each header slot: salt(32) ‖ nonce(12) ‖ AES-256-GCM(headerPlaintext)+tag,
// then random padding to fill the 64KiB slot. The salt/nonce are random and
// the ciphertext is indistinguishable from random, so the whole slot looks
// like noise. headerKey = deriveKey(password, salt). A password "opens" a
// volume iff its slot's GCM tag verifies AND the decrypted magic matches.
//
// Deniability property: with only the OUTER password you can validate the
// outer slot and read the outer (decoy) volume; the hidden slot and the tail
// are random bytes you cannot distinguish from the outer volume's free space.
// An outer-only container and an outer+hidden container of the same size are
// byte-for-byte indistinguishable to anyone without the hidden password.
//
// NOTE: this is a file/blob container (decrypt-to-extract), not yet a mounted
// filesystem — mounting is a separate feature built on top of this.
#ifndef OPENCRYPTUI_DENIABLE_CONTAINER_H
#define OPENCRYPTUI_DENIABLE_CONTAINER_H

#include <QString>
#include <QByteArray>

class EncryptionEngine;

class DeniableContainer {
public:
    enum class VolumeKind { None = 0, Outer = 1, Hidden = 2 };

    struct OpenResult {
        bool        ok   = false;
        VolumeKind  kind = VolumeKind::None;
        QByteArray  data;
        QString     error;
    };

    // Fixed sizes (bytes).
    static constexpr qint64 HEADER_SLOT   = 64 * 1024;   // 64 KiB per header
    static constexpr qint64 OUTER_HDR_OFF = 0;
    static constexpr qint64 HIDDEN_HDR_OFF = HEADER_SLOT;          // 64 KiB
    static constexpr qint64 DATA_OFF       = 2 * HEADER_SLOT;      // 128 KiB

    // On-disk size of `plainLen` bytes once chunked + AEAD-tagged.
    static qint64 chunkedSize(qint64 plainLen);

    // Smallest container that fits the given outer/hidden plaintext lengths.
    static qint64 minSize(qint64 outerLen, qint64 hiddenLen);

    // Create a deniable container. The whole file is filled with CSPRNG random
    // first, so unused space and the (absent) hidden header are indistinguishable
    // from real encrypted data. Pass an empty hiddenPassword for outer-only.
    // Returns false and sets *error on failure.
    static bool create(EncryptionEngine& eng,
                       const QString& path, qint64 sizeBytes,
                       const QString& outerPassword, const QByteArray& outerData,
                       const QString& kdf, int iterations,
                       const QString& hiddenPassword = QString(),
                       const QByteArray& hiddenData = QByteArray(),
                       QString* error = nullptr);

    // Open with a password. Which volume you get is determined solely by which
    // header slot the password validates — the outer password yields the outer
    // (decoy) volume, the hidden password yields the hidden volume.
    static OpenResult open(EncryptionEngine& eng, const QString& path,
                           const QString& password,
                           const QString& kdf, int iterations);
};

#endif // OPENCRYPTUI_DENIABLE_CONTAINER_H
