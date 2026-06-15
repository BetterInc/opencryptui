// Deniable container + hidden volume test, with a FORENSIC indistinguishability
// check — the whole point of a hidden volume is that its existence can't be
// proven. A hidden volume that's detectable is worse than none (false
// confidence under coercion), so this test is the acceptance gate.
//
// Asserts:
//   1. Outer-only container round-trips (create → open with outer pw → data).
//   2. Outer+hidden: outer pw yields the decoy, hidden pw yields the real data.
//   3. FORENSIC: an outer-only container and an outer+hidden container, created
//      with the SAME outer password/data/size, are statistically
//      indistinguishable — the hidden header slot and the tail are
//      high-entropy in BOTH, so an examiner with only the outer password
//      cannot tell a hidden volume exists.
//   4. No plaintext markers anywhere on disk.
//   5. Wrong password is rejected.
//   6. Tampering is detected.
//   7. Outer password cannot reach hidden data; hidden password cannot reach
//      outer data.
#include "deniable_container.h"
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QByteArray>
#include <cmath>
#include <cstdio>
#include <cstring>

static int s_failures = 0;
static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
}

static QByteArray rngData(qint64 size, quint32 seed)
{
    QByteArray b(size, 0);
    quint32 r = seed;
    for (qint64 i = 0; i < size; ++i) { r = r*1664525u + 1013904223u; b[int(i)] = char(r >> 24); }
    return b;
}

static QByteArray readAll(const QString& p)
{
    QFile f(p); if (!f.open(QIODevice::ReadOnly)) return {}; return f.readAll();
}

// Shannon entropy (bits/byte) of a region — random/ciphertext ≈ 8.0.
static double entropy(const QByteArray& d, int off, int len)
{
    if (off + len > d.size()) len = d.size() - off;
    if (len <= 0) return 0.0;
    long counts[256] = {0};
    for (int i = 0; i < len; ++i) counts[(unsigned char)d[off + i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!counts[i]) continue;
        double p = double(counts[i]) / len;
        h -= p * std::log2(p);
    }
    return h;
}

static int findSeq(const QByteArray& h, const char* n, int len)
{
    for (int i = 0; i + len <= h.size(); ++i)
        if (std::memcmp(h.constData() + i, n, len) == 0) return i;
    return -1;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    const QString kdf = "Argon2";
    const int iters = 3;

    const qint64 SIZE = 8 * 1024 * 1024; // 8 MiB
    const QByteArray outerData  = rngData(512 * 1024, 0xAAAA);   // decoy
    const QByteArray hiddenData = rngData(256 * 1024, 0x5555);   // real secret
    const QString outerPw = "outer-decoy-password";
    const QString hiddenPw = "hidden-real-password";

    // ---- 1. Outer-only round-trip ----
    const QString c1 = dir.filePath("outer_only.dc");
    {
        QString err;
        bool ok = DeniableContainer::create(eng, c1, SIZE, outerPw, outerData, kdf, iters,
                                            QString(), QByteArray(), &err);
        check(ok, ("outer-only create" + (ok ? QString() : ": " + err)).toUtf8().constData());
        auto r = DeniableContainer::open(eng, c1, outerPw, kdf, iters);
        check(r.ok && r.kind == DeniableContainer::VolumeKind::Outer, "outer-only: opens as Outer");
        check(r.data == outerData, "outer-only: data round-trips");
    }

    // ---- 2. Outer + hidden ----
    const QString c2 = dir.filePath("with_hidden.dc");
    {
        QString err;
        bool ok = DeniableContainer::create(eng, c2, SIZE, outerPw, outerData, kdf, iters,
                                            hiddenPw, hiddenData, &err);
        check(ok, ("hidden create" + (ok ? QString() : ": " + err)).toUtf8().constData());

        auto ro = DeniableContainer::open(eng, c2, outerPw, kdf, iters);
        check(ro.ok && ro.kind == DeniableContainer::VolumeKind::Outer, "hidden: outer pw → Outer volume");
        check(ro.data == outerData, "hidden: outer pw yields decoy data");

        auto rh = DeniableContainer::open(eng, c2, hiddenPw, kdf, iters);
        check(rh.ok && rh.kind == DeniableContainer::VolumeKind::Hidden, "hidden: hidden pw → Hidden volume");
        check(rh.data == hiddenData, "hidden: hidden pw yields real data");

        // Cross-checks: neither password reaches the other's data.
        check(ro.data != hiddenData, "outer pw cannot reach hidden data");
        check(rh.data != outerData,  "hidden pw cannot reach outer data");
    }

    // ---- 3. FORENSIC indistinguishability ----
    // Same outer pw/data/size; one has a hidden volume, one doesn't.
    {
        QByteArray a = readAll(c1); // outer-only
        QByteArray b = readAll(c2); // with hidden
        check(a.size() == b.size(), "both containers identical size");

        // Hidden header slot [64KiB,128KiB): high entropy in BOTH (random vs
        // encrypted header — indistinguishable).
        double eaHdr = entropy(a, int(DeniableContainer::HIDDEN_HDR_OFF), 65536);
        double ebHdr = entropy(b, int(DeniableContainer::HIDDEN_HDR_OFF), 65536);
        check(eaHdr > 7.9, "outer-only: hidden-header region looks random (H>7.9)");
        check(ebHdr > 7.9, "with-hidden: hidden-header region looks random (H>7.9)");

        // Tail (where hidden data lives in c2): high entropy in BOTH.
        int tailOff = int(SIZE - 256 * 1024);
        double eaTail = entropy(a, tailOff, 256 * 1024);
        double ebTail = entropy(b, tailOff, 256 * 1024);
        check(eaTail > 7.9, "outer-only: tail looks random (H>7.9)");
        check(ebTail > 7.9, "with-hidden: tail (hidden data) looks random (H>7.9)");

        // The two regions' entropies must be close — no statistical tell.
        check(std::fabs(eaHdr - ebHdr) < 0.05, "hidden-header entropy indistinguishable");
        check(std::fabs(eaTail - ebTail) < 0.05, "tail entropy indistinguishable");
    }

    // ---- 4. No plaintext markers on disk ----
    {
        QByteArray b = readAll(c2);
        // Scan for THIS format's real 8-byte magic "OCUIVOL1" (chance collision
        // ~2^-64, negligible). NOT a bare 4-byte "OCUI" — that's a different
        // format's marker and would collide ~0.2% of runs in 8 MiB of random
        // data (a false-positive flake, not a real leak).
        check(findSeq(b, "OCUIVOL1", 8) == -1, "no 'OCUIVOL1' magic in plaintext on disk");
        check(findSeq(b, "hidden", 6) == -1, "no 'hidden' string on disk");
    }

    // ---- 5. Wrong password ----
    {
        auto r = DeniableContainer::open(eng, c2, "totally-wrong", kdf, iters);
        check(!r.ok, "wrong password rejected");
    }

    // ---- 6. Tamper detection (flip a byte in the outer data region) ----
    {
        const QString c3 = dir.filePath("tamper.dc");
        DeniableContainer::create(eng, c3, SIZE, outerPw, outerData, kdf, iters);
        QFile f(c3);
        if (f.open(QIODevice::ReadWrite)) {
            qint64 at = DeniableContainer::DATA_OFF + 100;
            f.seek(at); char x; f.read(&x,1); x ^= 0x20; f.seek(at); f.write(&x,1); f.close();
        }
        auto r = DeniableContainer::open(eng, c3, outerPw, kdf, iters);
        check(!r.ok, "tampered outer data rejected");
    }

    if (s_failures) { std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures); return 1; }
    std::fprintf(stderr, "ALL DENIABLE-CONTAINER TESTS PASSED\n");
    return 0;
}
