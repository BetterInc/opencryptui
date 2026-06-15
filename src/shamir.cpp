#include "shamir.h"
#include "logging/secure_logger.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sodium.h>

namespace {

constexpr int CHECKSUM_LEN = 4;

// GF(2^8) multiply, AES reduction polynomial 0x11b.
inline quint8 gmul(quint8 a, quint8 b)
{
    quint8 p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        const quint8 hi = a & 0x80;
        a = static_cast<quint8>(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Multiplicative inverse in GF(2^8): a^(254) since a^255 == 1 for a != 0.
inline quint8 ginv(quint8 a)
{
    quint8 result = 1, base = a;
    int exp = 254;
    while (exp) {
        if (exp & 1) result = gmul(result, base);
        base = gmul(base, base);
        exp >>= 1;
    }
    return result;
}

// 4-byte SHA-256 prefix checksum of `data`.
QByteArray checksum4(const QByteArray& data)
{
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.constData()), data.size(), h);
    return QByteArray(reinterpret_cast<const char*>(h), CHECKSUM_LEN);
}

} // namespace

Shamir::SplitResult Shamir::split(const QByteArray& secret, int n, int k)
{
    SplitResult r;
    auto fail = [&](const QString& m){ r.error = m; SECURE_LOG(ERROR_LEVEL, "Shamir", m); return r; };

    if (secret.isEmpty()) return fail("Secret is empty.");
    if (k < 2)            return fail("Threshold k must be >= 2.");
    if (n < k)            return fail("Share count n must be >= threshold k.");
    if (n > 255)          return fail("Share count n must be <= 255.");

    // Wrap secret with a checksum so combine() can detect bad/insufficient shares.
    QByteArray blob = secret + checksum4(secret);
    const int m = blob.size();

    // Per secret-byte polynomial: coeff[0] = blob byte, coeff[1..k-1] random.
    // Pre-generate all random coefficients: m * (k-1) bytes.
    QByteArray coeffs((k - 1) * m, 0);
    if (!coeffs.isEmpty() &&
        RAND_bytes(reinterpret_cast<unsigned char*>(coeffs.data()), coeffs.size()) != 1) {
        sodium_memzero(blob.data(), blob.size());
        return fail("CSPRNG failure generating polynomial coefficients.");
    }
    const quint8* C = reinterpret_cast<const quint8*>(coeffs.constData());
    const quint8* B = reinterpret_cast<const quint8*>(blob.constData());

    for (int s = 1; s <= n; ++s) {
        const quint8 x = static_cast<quint8>(s); // distinct nonzero x in 1..n
        QByteArray share(1 + m, 0);
        share[0] = static_cast<char>(x);
        quint8* Y = reinterpret_cast<quint8*>(share.data()) + 1;
        for (int b = 0; b < m; ++b) {
            // Horner: f(x) = (((c_{k-1} x + c_{k-2}) x + ...) x + c_0
            quint8 acc = 0;
            for (int deg = k - 1; deg >= 1; --deg)
                acc = static_cast<quint8>(gmul(acc, x) ^ C[(deg - 1) * m + b]);
            acc = static_cast<quint8>(gmul(acc, x) ^ B[b]);
            Y[b] = acc;
        }
        r.shares.append(share);
    }

    sodium_memzero(coeffs.data(), coeffs.size());
    sodium_memzero(blob.data(), blob.size());
    r.ok = true;
    return r;
}

Shamir::CombineResult Shamir::combine(const QVector<QByteArray>& shares)
{
    CombineResult r;
    auto fail = [&](const QString& m){ r.error = m; SECURE_LOG(ERROR_LEVEL, "Shamir", m); return r; };

    if (shares.size() < 2) return fail("Need at least 2 shares.");

    const int shareLen = shares.first().size();
    if (shareLen < 1 + (1 + CHECKSUM_LEN)) return fail("Share too short / malformed.");
    const int m = shareLen - 1; // blob length (secret + checksum)

    // Collect distinct x-coords and y-vectors.
    QVector<quint8> xs;
    QVector<const quint8*> ys;
    for (const QByteArray& sh : shares) {
        if (sh.size() != shareLen) return fail("Shares have inconsistent length.");
        const quint8 x = static_cast<quint8>(sh[0]);
        if (x == 0) return fail("Invalid share (x = 0).");
        if (xs.contains(x)) return fail("Duplicate share supplied.");
        xs.append(x);
        ys.append(reinterpret_cast<const quint8*>(sh.constData()) + 1);
    }

    const int t = xs.size();
    // Precompute Lagrange basis at x=0:  L_j = prod_{i!=j} x_i / (x_i ^ x_j)
    QVector<quint8> basis(t, 0);
    for (int j = 0; j < t; ++j) {
        quint8 num = 1, den = 1;
        for (int i = 0; i < t; ++i) {
            if (i == j) continue;
            num = gmul(num, xs[i]);
            den = gmul(den, static_cast<quint8>(xs[i] ^ xs[j])); // x_i - x_j == x_i ^ x_j in GF2
        }
        basis[j] = gmul(num, ginv(den));
    }

    QByteArray blob(m, 0);
    quint8* out = reinterpret_cast<quint8*>(blob.data());
    for (int b = 0; b < m; ++b) {
        quint8 acc = 0;
        for (int j = 0; j < t; ++j)
            acc ^= gmul(ys[j][b], basis[j]);
        out[b] = acc;
    }

    // Verify checksum.
    const QByteArray secret = blob.left(m - CHECKSUM_LEN);
    const QByteArray cks    = blob.right(CHECKSUM_LEN);
    const bool good = (checksum4(secret) == cks);
    if (!good) {
        sodium_memzero(blob.data(), blob.size());
        return fail("Reconstruction failed - wrong, corrupted, or too few shares.");
    }

    r.secret = secret;
    sodium_memzero(blob.data(), blob.size());
    r.ok = true;
    return r;
}
