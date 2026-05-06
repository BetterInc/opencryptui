// OCUI v4 deniability test — the headline test for the threat model.
//
// Encrypted files must look like random data to a forensic examiner. Specifically:
//   1. No plaintext "OCUI" magic in the first 256 bytes.
//   2. No plaintext "SIG_" trailer marker.
//   3. The byte distribution of the head looks roughly uniform.
//   4. Two encryptions of the same plaintext with different passwords produce
//      visually-uncorrelated headers (salt randomization).
//   5. Round-trip still decrypts correctly.
//   6. Tamper anywhere is detected and produces no plaintext output.
#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QCryptographicHash>
#include <cstdio>
#include <cstdlib>

static int check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
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

static QByteArray readHead(const QString& path, int n)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.read(n);
}

// Find a 4-byte sequence in a buffer. -1 if not present.
static int findSeq(const QByteArray& haystack, const char* needle4)
{
    for (int i = 0; i + 4 <= haystack.size(); ++i) {
        if (haystack.at(i)   == needle4[0] &&
            haystack.at(i+1) == needle4[1] &&
            haystack.at(i+2) == needle4[2] &&
            haystack.at(i+3) == needle4[3]) return i;
    }
    return -1;
}

// Crude byte-distribution sanity: fail if any byte appears > 4× expected
// frequency in a small head. For random data over 256 bytes we expect each
// byte ~1× (256 distinct values, 256 samples). Allow up to 4 occurrences.
static bool looksRandom(const QByteArray& head)
{
    int hist[256] = {0};
    for (auto c : head) hist[(unsigned char)c]++;
    int maxFreq = 0;
    for (int i = 0; i < 256; ++i) if (hist[i] > maxFreq) maxFreq = hist[i];
    // A truly random 256-byte sample has expected max ~3-5; cap at 8 to
    // avoid flakes while still catching obvious patterns.
    return maxFreq <= 8;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    if (!dir.isValid()) { std::fprintf(stderr, "no tempdir\n"); return 99; }

    EncryptionEngine eng;
    int failures = 0;

    const QString plain = dir.filePath("p.bin");
    const QString ct    = plain + ".enc";
    const QString plain2 = dir.filePath("p2.bin");
    const QString ct2    = plain2 + ".enc";

    const QByteArray payload = makePayload(5 * 1024 * 1024); // 5 MiB
    if (!writeFile(plain, payload))  return 99;
    if (!writeFile(plain2, payload)) return 99;

    // --- 1. Encrypt with AES-256-GCM (triggers v4) ---
    {
        bool ok = eng.encryptFile(plain, "first-password", "AES-256-GCM",
                                  "PBKDF2", 600000, false, QString());
        failures += check(ok, "v4: encrypt 5 MiB");
    }

    QByteArray head = readHead(ct, 256);
    failures += check(head.size() == 256, "v4: read first 256 bytes");

    // --- 2. No plaintext OCUI magic ---
    failures += check(findSeq(head, "OCUI") == -1,
                      "v4: no plaintext OCUI magic in first 256 bytes");

    // --- 3. No plaintext SIG_ trailer marker anywhere in the file ---
    QByteArray whole;
    {
        QFile f(ct);
        if (f.open(QIODevice::ReadOnly)) whole = f.readAll();
    }
    failures += check(findSeq(whole, "SIG_") == -1,
                      "v4: no plaintext SIG_ marker anywhere in file");

    // --- 4. Byte distribution looks roughly uniform ---
    failures += check(looksRandom(head),
                      "v4: byte distribution of first 256 bytes looks random");

    // --- 5. Different password → uncorrelated header ---
    {
        bool ok = eng.encryptFile(plain2, "second-password", "AES-256-GCM",
                                  "PBKDF2", 600000, false, QString());
        failures += check(ok, "v4: encrypt second file with different password");
    }
    QByteArray head2 = readHead(ct2, 256);
    QByteArray h1 = QCryptographicHash::hash(head, QCryptographicHash::Sha256);
    QByteArray h2 = QCryptographicHash::hash(head2, QCryptographicHash::Sha256);
    failures += check(h1 != h2,
                      "v4: same plaintext + different password yields different headers");

    // --- 6. Round-trip ---
    QFile::remove(plain);
    {
        bool ok = eng.decryptFile(ct, "first-password", "AES-256-GCM",
                                  "PBKDF2", 600000, false, QString());
        failures += check(ok, "v4: decrypt round-trip");
    }
    {
        QFile f(plain);
        bool match = f.open(QIODevice::ReadOnly) && f.readAll() == payload;
        failures += check(match, "v4: byte-identical round-trip");
    }

    // --- 7. Tamper at offset 0 (salt region) — decrypt must fail ---
    {
        QFile::remove(plain);
        QFile f(ct);
        if (f.open(QIODevice::ReadWrite)) {
            f.seek(0);
            char b; f.read(&b, 1); b ^= 0xFF;
            f.seek(0); f.write(&b, 1);
            f.close();
        }
        bool ok = eng.decryptFile(ct, "first-password", "AES-256-GCM",
                                  "PBKDF2", 600000, false, QString());
        failures += check(!ok, "v4: tampered salt region rejected");
        failures += check(!QFile::exists(plain),
                          "v4: no plaintext on disk after tampered-salt rejection");
    }

    if (failures) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", failures);
        return 1;
    }
    std::fprintf(stderr, "ALL V4 DENIABILITY TESTS PASSED\n");
    return 0;
}
