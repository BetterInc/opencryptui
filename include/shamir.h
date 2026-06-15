// Shamir's Secret Sharing over GF(2^8).
//
// Splits a secret into `n` shares such that any `k` of them reconstruct it and
// any `k-1` reveal nothing (information-theoretic). Use it to split a container
// password or master key across people/locations so no single seized share -
// or single coerced person - can unlock anything.
//
// Byte-wise scheme: each secret byte is the constant term of an independent
// degree-(k-1) polynomial over GF(2^8) (AES field, reduction 0x11b); share i is
// the polynomials evaluated at x=i. Reconstruction is Lagrange interpolation at
// x=0. Coefficients come from a CSPRNG (RAND_bytes).
//
// Integrity: classic SSS gives no error on wrong/insufficient shares - you just
// get garbage. We append a 4-byte SHA-256 checksum to the secret BEFORE
// splitting, so combine() can verify and FAIL LOUDLY rather than return junk.
// The checksum is split too, so fewer than k shares still reveal nothing.
//
// Share wire format (one QByteArray per share):
//   [x: 1 byte, 1..255] [y-bytes: secret.size()+4 bytes]
#ifndef OPENCRYPTUI_SHAMIR_H
#define OPENCRYPTUI_SHAMIR_H

#include <QByteArray>
#include <QVector>
#include <QString>

class Shamir {
public:
    struct SplitResult {
        bool ok = false;
        QVector<QByteArray> shares;  // n shares
        QString error;
    };
    struct CombineResult {
        bool ok = false;
        QByteArray secret;
        QString error;
    };

    // Split `secret` into `n` shares, threshold `k` (2 <= k <= n <= 255).
    static SplitResult split(const QByteArray& secret, int n, int k);

    // Reconstruct from any shares. Needs >= the original threshold of valid,
    // distinct shares; verifies the embedded checksum and fails otherwise.
    static CombineResult combine(const QVector<QByteArray>& shares);
};

#endif // OPENCRYPTUI_SHAMIR_H
