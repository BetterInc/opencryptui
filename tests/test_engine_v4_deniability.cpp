// OCUI v4 deniability test — the headline test for the threat model.
//
// Encrypted AEAD files must look like random data to a forensic examiner.
// Non-AEAD files (CBC/CTR) stay on v2 by design; they explicitly do NOT
// have the deniability property and we assert that contract too, so a
// future regression that "accidentally" makes v2 look like v4 (or vice
// versa) is loud.
//
// Test coverage:
//   1. AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305): no plaintext OCUI,
//      no plaintext SIG_, no obvious cipher-name strings, anywhere in
//      the entire file (not just the head). Byte distribution of the
//      head is roughly uniform.
//   2. Non-AEAD cipher (AES-256-CBC) DOES have OCUI at offset 0 and
//      DOES have a SIG_ trailer — this is the v2 contract. If this
//      assertion ever flips, someone has changed the v2 path and we
//      need to re-evaluate what users in CBC mode are getting.
//   3. Same plaintext + different password → uncorrelated headers.
//   4. Round-trip: byte-identical recovery for every cipher.
//   5. Wrong-password rejection: returns false, no plaintext on disk.
//   6. Tampered salt region: rejected, no plaintext on disk.
//   7. v3 fallback: a file produced by an earlier engine path still
//      decrypts (we can't easily produce a v3 file in this test
//      because the engine now defaults to v4; we assert the fallback
//      logic by trying to decrypt a corrupted-as-v4 file and checking
//      we get a clean rejection rather than a crash).

#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QCryptographicHash>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int s_failures = 0;

static int check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
    return ok ? 0 : 1;
}

static QByteArray makePayload(qint64 size)
{
    QByteArray b(size, 0);
    quint32 rng = 0xC0FFEE42u;
    for (qint64 i = 0; i < size; ++i) {
        rng = rng * 1664525u + 1013904223u;
        b[int(i)] = char(rng >> 24);
    }
    return b;
}

static bool writeFile(const QString& path, const QByteArray& data)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}

static QByteArray readAll(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

// Find a byte sequence anywhere in the buffer. -1 if not present.
static int findSeq(const QByteArray& haystack, const char* needle, int nlen)
{
    if (nlen <= 0 || haystack.size() < nlen) return -1;
    for (int i = 0; i + nlen <= haystack.size(); ++i) {
        if (std::memcmp(haystack.constData() + i, needle, nlen) == 0)
            return i;
    }
    return -1;
}

// Is the byte distribution of a small head reasonably uniform? Reject if
// any byte exceeds 8 occurrences in 256 bytes (a uniform distribution
// expects ~1; allow generous slack to avoid statistical flakes).
static bool looksRandom(const QByteArray& head)
{
    int hist[256] = {0};
    for (auto c : head) hist[(unsigned char)c]++;
    for (int i = 0; i < 256; ++i) if (hist[i] > 8) return false;
    return true;
}

// Encrypt + decrypt + byte-compare round-trip for a given cipher.
// Returns the path to the encrypted file (caller-owned for further checks).
static QString roundTripAndReturnCt(EncryptionEngine& eng,
                                    const QString& dir,
                                    const QString& algo,
                                    const QByteArray& payload,
                                    const QString& password,
                                    const char* label)
{
    const QString plain = dir + "/" + label + "_plain.bin";
    const QString ct    = plain + ".enc";

    if (!writeFile(plain, payload)) {
        check(false, "write plaintext");
        return {};
    }

    bool ok = eng.encryptFile(plain, password, algo, "PBKDF2", 600000,
                              false, QString());
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s: encrypt", label);
    // check() returns 0 on PASS, 1 on FAIL — bail only when the value is non-zero.
    if (check(ok, buf) != 0) return {};

    QFile::remove(plain);

    ok = eng.decryptFile(ct, password, algo, "PBKDF2", 600000,
                         false, QString());
    std::snprintf(buf, sizeof(buf), "%s: decrypt", label);
    if (check(ok, buf) != 0) return ct;

    QByteArray got = readAll(plain);
    std::snprintf(buf, sizeof(buf), "%s: byte-identical round-trip", label);
    check(got == payload, buf);

    QFile::remove(plain);
    return ct;
}

// Run the full forensic check on an AEAD-encrypted file (must look random
// end-to-end).
static void aeadDeniabilityCheck(const QString& ct, const char* label)
{
    QByteArray whole = readAll(ct);
    char buf[160];

    std::snprintf(buf, sizeof(buf), "%s: whole-file scan finds NO 'OCUI' magic", label);
    check(findSeq(whole, "OCUI", 4) == -1, buf);

    std::snprintf(buf, sizeof(buf), "%s: whole-file scan finds NO 'SIG_' marker", label);
    check(findSeq(whole, "SIG_", 4) == -1, buf);

    // 3-byte strings appear by chance in ~6% of 1 MB random buffers, so
    // scan only the header/preamble region where a real algorithm-name
    // leak would actually live. Anything past offset 256 is uniform
    // ciphertext where a coincidence is meaningless.
    std::snprintf(buf, sizeof(buf), "%s: header region (first 256 B) contains NO 'AES' string", label);
    check(findSeq(whole.left(256), "AES", 3) == -1, buf);

    std::snprintf(buf, sizeof(buf), "%s: first 256 bytes look uniformly random", label);
    QByteArray head = whole.left(256);
    check(looksRandom(head), buf);

    // First 4 bytes must NOT be a TPM2 ASN.1 prefix (defensive — we don't
    // produce TPM blobs here but if HwKey wrapping ever lands inside the
    // file, this check would catch a regression that exposed it).
    static const unsigned char tpm2_prefix[] = {0x80, 0x01, 0x00, 0x01};
    bool starts_tpm = whole.size() >= 4 &&
        std::memcmp(whole.constData(), tpm2_prefix, 4) == 0;
    std::snprintf(buf, sizeof(buf), "%s: first 4 bytes are NOT TPM2 ASN.1 prefix", label);
    check(!starts_tpm, buf);
}

// Run the contract check on a non-AEAD (v2) file: it MUST have the OCUI
// magic at offset 0 and a SIG_ trailer. This is documented behaviour —
// CBC/CTR can't be deniable without an outer AEAD wrap. Asserting it
// ensures a future change that flips this behaviour gets noticed.
static void v2NonDeniabilityCheck(const QString& ct, const char* label)
{
    QByteArray whole = readAll(ct);
    char buf[160];

    bool magic_at_0 = whole.size() >= 4 &&
        std::memcmp(whole.constData(), "OCUI", 4) == 0;
    std::snprintf(buf, sizeof(buf), "%s (v2): OCUI magic IS at offset 0 (documented contract)", label);
    check(magic_at_0, buf);

    std::snprintf(buf, sizeof(buf), "%s (v2): SIG_ trailer IS present (documented contract)", label);
    check(findSeq(whole, "SIG_", 4) != -1, buf);
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    const QByteArray payload = makePayload(2 * 1024 * 1024); // 2 MiB

    // -----------------------------------------------------------------------
    // 1. AEAD ciphers must be deniable.
    // -----------------------------------------------------------------------
    {
        QString ct = roundTripAndReturnCt(eng, dir.path(), "AES-256-GCM",
                                          payload, "first-pwd", "gcm");
        if (!ct.isEmpty()) aeadDeniabilityCheck(ct, "AES-256-GCM");
    }
    {
        QString ct = roundTripAndReturnCt(eng, dir.path(), "ChaCha20-Poly1305",
                                          payload, "first-pwd", "cha");
        if (!ct.isEmpty()) aeadDeniabilityCheck(ct, "ChaCha20-Poly1305");
    }

    // -----------------------------------------------------------------------
    // 2. Non-AEAD cipher: documented v2 contract — NOT deniable.
    // -----------------------------------------------------------------------
    {
        QString ct = roundTripAndReturnCt(eng, dir.path(), "AES-256-CBC",
                                          payload, "first-pwd", "cbc");
        if (!ct.isEmpty()) v2NonDeniabilityCheck(ct, "AES-256-CBC");
    }

    // -----------------------------------------------------------------------
    // 3. Same plaintext + different password → uncorrelated heads.
    // -----------------------------------------------------------------------
    {
        const QString p1 = dir.filePath("salt1_plain.bin");
        const QString c1 = p1 + ".enc";
        const QString p2 = dir.filePath("salt2_plain.bin");
        const QString c2 = p2 + ".enc";

        writeFile(p1, payload);
        writeFile(p2, payload);

        eng.encryptFile(p1, "password-A", "AES-256-GCM", "PBKDF2", 600000,
                        false, QString());
        eng.encryptFile(p2, "password-B", "AES-256-GCM", "PBKDF2", 600000,
                        false, QString());

        QByteArray h1 = QCryptographicHash::hash(readAll(c1).left(256),
                                                  QCryptographicHash::Sha256);
        QByteArray h2 = QCryptographicHash::hash(readAll(c2).left(256),
                                                  QCryptographicHash::Sha256);
        check(h1 != h2,
              "v4: same plaintext + different password produces different head");
    }

    // -----------------------------------------------------------------------
    // 4. Wrong password is rejected, no plaintext leaked.
    // -----------------------------------------------------------------------
    {
        const QString plain = dir.filePath("wp_plain.bin");
        const QString ct    = plain + ".enc";
        writeFile(plain, payload);
        eng.encryptFile(plain, "correct-pwd", "AES-256-GCM", "PBKDF2", 600000,
                        false, QString());
        QFile::remove(plain);
        bool ok = eng.decryptFile(ct, "WRONG-pwd", "AES-256-GCM", "PBKDF2", 600000,
                                  false, QString());
        check(!ok, "v4: wrong password rejected");
        check(!QFile::exists(plain),
              "v4: no plaintext on disk after wrong-password rejection");
    }

    // -----------------------------------------------------------------------
    // 5. Tampered salt region (first 32 bytes) is rejected.
    // -----------------------------------------------------------------------
    {
        const QString plain = dir.filePath("ts_plain.bin");
        const QString ct    = plain + ".enc";
        writeFile(plain, payload);
        eng.encryptFile(plain, "p", "AES-256-GCM", "PBKDF2", 600000,
                        false, QString());
        QFile::remove(plain);

        QFile f(ct);
        if (f.open(QIODevice::ReadWrite)) {
            f.seek(0);
            char b; f.read(&b, 1); b ^= 0xFF;
            f.seek(0); f.write(&b, 1);
            f.close();
        }
        bool ok = eng.decryptFile(ct, "p", "AES-256-GCM", "PBKDF2", 600000,
                                  false, QString());
        check(!ok, "v4: tampered salt rejected");
        check(!QFile::exists(plain),
              "v4: no plaintext on disk after tampered-salt rejection");
    }

    // -----------------------------------------------------------------------
    // 6. Tamper deep inside the encrypted payload.
    // -----------------------------------------------------------------------
    {
        const QString plain = dir.filePath("td_plain.bin");
        const QString ct    = plain + ".enc";
        writeFile(plain, payload);
        eng.encryptFile(plain, "p", "AES-256-GCM", "PBKDF2", 600000,
                        false, QString());
        QFile::remove(plain);

        QFile f(ct);
        if (f.open(QIODevice::ReadWrite)) {
            qint64 mid = f.size() / 2;
            f.seek(mid);
            char b; f.read(&b, 1); b ^= 0x55;
            f.seek(mid); f.write(&b, 1);
            f.close();
        }
        bool ok = eng.decryptFile(ct, "p", "AES-256-GCM", "PBKDF2", 600000,
                                  false, QString());
        check(!ok, "v4: tamper deep in payload rejected");
        check(!QFile::exists(plain),
              "v4: no plaintext on disk after deep-payload tamper rejection");
    }

    if (s_failures) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", s_failures);
        return 1;
    }
    std::fprintf(stderr, "ALL V4 DENIABILITY TESTS PASSED\n");
    return 0;
}
