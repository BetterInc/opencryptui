// Shamir Secret Sharing tests: k-of-n round-trip, threshold enforcement,
// corrupted-share rejection, and checksum-based failure (no silent garbage).
#include "shamir.h"
#include <QCoreApplication>
#include <QByteArray>
#include <QVector>
#include <cstdio>

static int s_failures = 0;
static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
}

// Pick `count` shares by index from a share set.
static QVector<QByteArray> pick(const QVector<QByteArray>& all, QVector<int> idx)
{
    QVector<QByteArray> out;
    for (int i : idx) out.append(all[i]);
    return out;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    const QByteArray secret = QByteArray::fromHex(
        "00112233445566778899aabbccddeeff0123456789abcdef0011223344556677"); // 32-byte key

    // ---- 3-of-5 ----
    auto sp = Shamir::split(secret, 5, 3);
    check(sp.ok, "split 3-of-5 succeeds");
    check(sp.shares.size() == 5, "produces 5 shares");
    check(sp.shares[0] != sp.shares[1], "shares differ");

    // Any 3 distinct shares reconstruct.
    {
        auto c = Shamir::combine(pick(sp.shares, {0,2,4}));
        check(c.ok && c.secret == secret, "any 3 shares reconstruct (0,2,4)");
        auto c2 = Shamir::combine(pick(sp.shares, {1,3,4}));
        check(c2.ok && c2.secret == secret, "a different 3 reconstruct (1,3,4)");
        auto c3 = Shamir::combine(sp.shares); // all 5 also work
        check(c3.ok && c3.secret == secret, "all 5 shares reconstruct");
    }

    // Fewer than k → must FAIL (checksum), not return garbage.
    {
        auto c = Shamir::combine(pick(sp.shares, {0,1}));
        check(!c.ok, "2 of 3-of-5 is rejected (below threshold)");
        check(c.secret.isEmpty(), "no secret leaked on sub-threshold combine");
    }

    // A corrupted share among k → rejected.
    {
        auto shares = pick(sp.shares, {0,1,2});
        shares[1][5] = shares[1][5] ^ 0x80; // flip a byte in a y-value
        auto c = Shamir::combine(shares);
        check(!c.ok, "corrupted share is rejected");
    }

    // Duplicate share → rejected.
    {
        auto c = Shamir::combine(pick(sp.shares, {2,2,3}));
        check(!c.ok, "duplicate share is rejected");
    }

    // ---- 2-of-2 and threshold == n edge ----
    {
        auto s2 = Shamir::split(secret, 2, 2);
        check(s2.ok, "split 2-of-2");
        auto c = Shamir::combine(s2.shares);
        check(c.ok && c.secret == secret, "2-of-2 reconstructs");
        auto c1 = Shamir::combine(pick(s2.shares, {0}));
        check(!c1.ok, "1 of 2-of-2 rejected");
    }

    // ---- larger threshold 7-of-10, variable secret length ----
    {
        const QByteArray sec2 = QByteArray("split-this-password-across-a-team!").repeated(3);
        auto s = Shamir::split(sec2, 10, 7);
        check(s.ok && s.shares.size() == 10, "split 7-of-10 (long secret)");
        auto c = Shamir::combine(pick(s.shares, {9,0,5,2,7,3,8}));
        check(c.ok && c.secret == sec2, "7 arbitrary shares reconstruct long secret");
        auto cbad = Shamir::combine(pick(s.shares, {9,0,5,2,7,3})); // only 6
        check(!cbad.ok, "6 of 7-of-10 rejected");
    }

    // ---- input validation ----
    check(!Shamir::split(secret, 5, 1).ok, "k<2 rejected");
    check(!Shamir::split(secret, 2, 3).ok, "n<k rejected");
    check(!Shamir::split(QByteArray(), 3, 2).ok, "empty secret rejected");

    // ---- 1-byte secret (smallest meaningful) ----
    {
        QByteArray one("Z");
        auto s = Shamir::split(one, 3, 2);
        check(s.ok, "split 1-byte secret");
        auto c = Shamir::combine(pick(s.shares, {0,2}));
        check(c.ok && c.secret == one, "1-byte secret reconstructs");
    }

    if (s_failures) { std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures); return 1; }
    std::fprintf(stderr, "ALL SHAMIR TESTS PASSED\n");
    return 0;
}
