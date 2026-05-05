// test_engine_per_chunk.cpp
//
// Per-chunk AEAD framing tests for OCUI v3 format.
//
// Test cases:
//   1. 10 MiB round-trip   — verifies multi-chunk encrypt/decrypt integrity.
//   2. Naive tamper        — flip a byte in chunk 3 ciphertext; outer Ed25519
//                            signature catches it before AEAD runs.
//   3. Attacker-resigns    — tamper chunk 3 and recompute the Ed25519 trailer
//                            (attacker knows the signing key); AEAD rejects that
//                            specific chunk and no plaintext is left on disk.
//   4. Sub-chunk file      — file smaller than one chunk (edge case).
//   5. Exact 2 MiB file   — file exactly 2 chunks, no partial tail chunk.

#include "encryptionengine.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QDataStream>
#include <QDebug>
#include <sodium.h>
#include <openssl/evp.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool writeFile(const QString& path, const QByteArray& data)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}

static QByteArray readFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

// Generate n bytes of deterministic pseudo-random data (not crypto-quality,
// just for test payload construction).
static QByteArray makePayload(qint64 size)
{
    QByteArray buf(static_cast<int>(size), 0);
    quint32 rng = 0xDEADBEEFu;
    for (int i = 0; i < buf.size(); ++i) {
        rng = rng * 1664525u + 1013904223u; // LCG
        buf[i] = static_cast<char>(rng >> 24);
    }
    return buf;
}

// Flip one byte at `offset` in the file at `path`.
static bool flipByteAt(const QString& path, qint64 offset)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadWrite)) return false;
    if (!f.seek(offset)) return false;
    char b = 0;
    if (f.read(&b, 1) != 1) return false;
    b ^= 0xAA;
    if (!f.seek(offset)) return false;
    return f.write(&b, 1) == 1;
}

// Return the file offset of chunk i's ciphertext, given the v3 format:
//   OCUI_HEADER_SIZE(12) + salt(32) + iv(12) + chunk_size(4) + chunk_count(4)
//   + i * (chunk_size + 16)    [for non-last chunks]
//
// The first chunk starts at offset = 12 + 32 + 12 + 4 + 4 = 64.
static qint64 chunkDataOffset(quint32 chunkIndex, quint32 chunkSize)
{
    const qint64 headerAndFraming = 12 + 32 + 12 + 4 + 4; // 64 bytes
    return headerAndFraming + static_cast<qint64>(chunkIndex) * (chunkSize + 16);
}

// Re-derive the Ed25519 signing key from password+salt (mirrors what
// EncryptionEngine does internally) so we can forge a valid signature.
// This simulates an attacker who controls the signing key (e.g. they
// extracted it from memory or know the password).
static bool reSignFile(const QString& filePath, const QByteArray& sigKey)
{
    // Remove old signature trailer: read the last 12 bytes to find sigLen.
    QFile f(filePath);
    if (!f.open(QIODevice::ReadWrite)) return false;

    if (f.size() < 12) return false;
    f.seek(f.size() - 12);
    QDataStream ds(&f);
    ds.setByteOrder(QDataStream::BigEndian);
    quint32 magic; ds >> magic;
    if (magic != 0x5349475F) return false; // "SIG_"
    quint32 sigLen; ds >> sigLen;

    qint64 newSize = f.size() - static_cast<qint64>(sigLen) - 12;
    f.resize(newSize);
    f.close();

    // Now re-sign the truncated file and append a fresh trailer.
    // We replicate the appendSignature logic from encryptionengine_tamperevidence.cpp.
    if (!f.open(QIODevice::ReadWrite)) return false;

    // Hash the file body.
    f.seek(0);
    unsigned char hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hashLen = 0;
    {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
        QByteArray buf(4096, 0);
        while (!f.atEnd()) {
            qint64 n = f.read(buf.data(), buf.size());
            if (n > 0) EVP_DigestUpdate(ctx, buf.constData(), static_cast<size_t>(n));
        }
        EVP_DigestFinal_ex(ctx, hash, &hashLen);
        EVP_MD_CTX_free(ctx);
    }

    // Derive Ed25519 keypair from seed.
    QByteArray pubKey(crypto_sign_PUBLICKEYBYTES, 0);
    QByteArray secKey(crypto_sign_SECRETKEYBYTES, 0);
    crypto_sign_seed_keypair(
        reinterpret_cast<unsigned char*>(pubKey.data()),
        reinterpret_cast<unsigned char*>(secKey.data()),
        reinterpret_cast<const unsigned char*>(sigKey.constData()));

    // Sign hash.
    QByteArray sig(crypto_sign_BYTES + hashLen, 0);
    unsigned long long sigLen2 = 0;
    crypto_sign_detached(
        reinterpret_cast<unsigned char*>(sig.data()), &sigLen2,
        hash, hashLen,
        reinterpret_cast<const unsigned char*>(secKey.constData()));
    sig.resize(static_cast<int>(sigLen2));
    sig.append(pubKey);

    sodium_memzero(secKey.data(), secKey.size());

    // Append trailer: [sig][SIG_ magic][sigLen][CRC32].
    f.seek(f.size());
    f.write(sig);
    {
        // CRC32 over the signature bytes.
        quint32 crc = 0xFFFFFFFF;
        static const quint32 crcTable[256] = {
            0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
            0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
            0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
            0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
            0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
            0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
            0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
            0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
            0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
            0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
            0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
            0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
            0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
            0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
            0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
            0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
            0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
            0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
            0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
            0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
            0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
            0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
            0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
            0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
            0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
            0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
            0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
            0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
            0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
            0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
            0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
            0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
        };
        for (int i = 0; i < sig.size(); ++i) {
            crc = (crc >> 8) ^ crcTable[(crc ^ static_cast<unsigned char>(sig[i])) & 0xFF];
        }
        crc = ~crc;

        QDataStream trailer(&f);
        trailer.setByteOrder(QDataStream::BigEndian);
        trailer << quint32(0x5349475F);          // "SIG_"
        trailer << quint32(sig.size());
        trailer << crc;
    }
    f.close();
    return true;
}

// Derive the signing key for a given encrypted file by re-reading the file
// header and re-deriving keys.  This is only possible if the attacker knows
// the password (which is the scenario for test 3).
static QByteArray deriveSigningKey(EncryptionEngine& eng,
                                   const QString& ctPath,
                                   const QString& password,
                                   const QString& algorithm,
                                   const QString& kdf,
                                   int iters)
{
    (void)iters;
    QFile f(ctPath);
    if (!f.open(QIODevice::ReadOnly)) return {};

    // Skip 12-byte OCUI header.
    if (!f.seek(12)) return {};

    // Read salt (32 bytes).
    QByteArray salt(32, 0);
    if (f.read(salt.data(), 32) != 32) return {};

    // Derive master key from password + salt (no keyfiles).
    QByteArray master = eng.deriveKey(password, salt, QStringList(), kdf, 600000);
    if (master.isEmpty()) return {};

    // Split into encKey + sigKey using the same HKDF as the engine.
    // We call deriveSubkeys indirectly by using the public API to re-derive
    // via a known-plaintext: just get the salt from the file and compute.
    //
    // Since deriveSubkeys is private, we replicate the libsodium call here.
    if (master.size() < static_cast<int>(crypto_kdf_KEYBYTES)) return {};
    unsigned char kdfMaster[crypto_kdf_KEYBYTES];
    memcpy(kdfMaster, master.constData(), crypto_kdf_KEYBYTES);
    sodium_memzero(master.data(), master.size());

    QByteArray sigKey(static_cast<int>(crypto_sign_SEEDBYTES), 0);
    crypto_kdf_derive_from_key(
        reinterpret_cast<unsigned char*>(sigKey.data()),
        static_cast<size_t>(sigKey.size()),
        2, "OCUI-SIG",
        kdfMaster);

    sodium_memzero(kdfMaster, sizeof(kdfMaster));
    (void)algorithm;
    return sigKey;
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

static int check(bool ok, const char* label)
{
    if (!ok) { qCritical() << "FAIL:" << label; return 1; }
    qInfo()  << "PASS:" << label;
    return 0;
}

// TC1: 10 MiB round-trip.
static int tc1_roundtrip10MiB(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + "/tc1_plain.bin";
    const QString ct    = plain + ".enc";

    QByteArray payload = makePayload(10 * 1024 * 1024); // 10 MiB
    if (!writeFile(plain, payload)) return check(false, "TC1: write plain");

    bool ok = eng.encryptFile(plain, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    if (!check(ok, "TC1: encrypt 10 MiB")) return 1;

    QFile::remove(plain);

    ok = eng.decryptFile(ct, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    if (!check(ok, "TC1: decrypt 10 MiB")) return 1;

    QByteArray got = readFile(plain);
    if (!check(got == payload, "TC1: 10 MiB round-trip byte-identical")) return 1;

    QFile::remove(plain);
    QFile::remove(ct);
    return 0;
}

// TC2: Naive tamper — flip a byte in chunk 3; Ed25519 sig catches it first.
static int tc2_naiveTamperChunk3(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + "/tc2_plain.bin";
    const QString ct    = plain + ".enc";

    QByteArray payload = makePayload(10 * 1024 * 1024);
    if (!writeFile(plain, payload)) return check(false, "TC2: write plain");

    bool ok = eng.encryptFile(plain, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    if (!check(ok, "TC2: encrypt")) return 1;

    QFile::remove(plain);

    // Flip one byte inside chunk 3 ciphertext.  Ed25519 covers everything
    // so the signature should fail before AEAD even runs.
    const qint64 offset = chunkDataOffset(3, 1048576) + 512;
    if (!flipByteAt(ct, offset)) return check(false, "TC2: flip byte");

    ok = eng.decryptFile(ct, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    int failures = 0;
    failures += check(!ok, "TC2: tampered decrypt rejected");
    failures += check(!QFile::exists(plain), "TC2: no plaintext left on disk");

    QFile::remove(ct);
    return failures;
}

// TC3: Attacker recomputes Ed25519 signature after tampering chunk 3.
//      AEAD tag verification must catch the corruption and reject.
static int tc3_attackerResigns(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + "/tc3_plain.bin";
    const QString ct    = plain + ".enc";

    QByteArray payload = makePayload(10 * 1024 * 1024);
    if (!writeFile(plain, payload)) return check(false, "TC3: write plain");

    bool ok = eng.encryptFile(plain, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    if (!check(ok, "TC3: encrypt")) return 1;

    QFile::remove(plain);

    // Derive the signing key (attacker knows the password).
    QByteArray sigKey = deriveSigningKey(eng, ct, "test-password-v3",
                                         "AES-256-GCM", "PBKDF2", 600000);
    if (!check(!sigKey.isEmpty(), "TC3: derived signing key")) return 1;

    // Tamper chunk 3.
    const qint64 offset = chunkDataOffset(3, 1048576) + 42;
    if (!flipByteAt(ct, offset)) return check(false, "TC3: flip byte");

    // Re-sign with the correct key so the Ed25519 check passes.
    if (!reSignFile(ct, sigKey)) return check(false, "TC3: resign file");

    // Now decrypt: Ed25519 passes, but AEAD on chunk 3 must fail.
    ok = eng.decryptFile(ct, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    int failures = 0;
    failures += check(!ok, "TC3: attacker-resigned tamper rejected by AEAD");
    failures += check(!QFile::exists(plain), "TC3: no plaintext left on disk after AEAD rejection");

    QFile::remove(ct);
    return failures;
}

// TC4: Sub-chunk file (< 1 MiB) — exactly one chunk.
static int tc4_subChunkFile(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + "/tc4_plain.bin";
    const QString ct    = plain + ".enc";

    QByteArray payload = makePayload(123456); // 123 KiB
    if (!writeFile(plain, payload)) return check(false, "TC4: write plain");

    bool ok = eng.encryptFile(plain, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    if (!check(ok, "TC4: encrypt <1 MiB")) return 1;

    QFile::remove(plain);

    ok = eng.decryptFile(ct, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    if (!check(ok, "TC4: decrypt <1 MiB")) return 1;

    QByteArray got = readFile(plain);
    if (!check(got == payload, "TC4: <1 MiB round-trip byte-identical")) return 1;

    QFile::remove(plain);
    QFile::remove(ct);
    return 0;
}

// TC5: Exactly 2 MiB file — two full chunks, no partial tail.
static int tc5_exact2MiB(EncryptionEngine& eng, const QString& dir)
{
    const QString plain = dir + "/tc5_plain.bin";
    const QString ct    = plain + ".enc";

    QByteArray payload = makePayload(2 * 1024 * 1024); // exactly 2 MiB
    if (!writeFile(plain, payload)) return check(false, "TC5: write plain");

    bool ok = eng.encryptFile(plain, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                              false, QString());
    if (!check(ok, "TC5: encrypt 2 MiB")) return 1;

    QFile::remove(plain);

    ok = eng.decryptFile(ct, "test-password-v3", "AES-256-GCM", "PBKDF2", 600000,
                         false, QString());
    if (!check(ok, "TC5: decrypt 2 MiB")) return 1;

    QByteArray got = readFile(plain);
    if (!check(got == payload, "TC5: 2 MiB round-trip byte-identical")) return 1;

    QFile::remove(plain);
    QFile::remove(ct);
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    QTemporaryDir dir;
    if (!dir.isValid()) { qCritical("no tempdir"); return 99; }

    if (sodium_init() < 0) { qCritical("sodium_init failed"); return 99; }

    EncryptionEngine eng;
    int failures = 0;

    qInfo("=== TC1: 10 MiB round-trip ===");
    failures += tc1_roundtrip10MiB(eng, dir.path());

    qInfo("=== TC2: Naive tamper in chunk 3 (Ed25519 catches it) ===");
    failures += tc2_naiveTamperChunk3(eng, dir.path());

    qInfo("=== TC3: Attacker re-signs after tampering chunk 3 (AEAD catches it) ===");
    failures += tc3_attackerResigns(eng, dir.path());

    qInfo("=== TC4: Sub-chunk file (<1 MiB, 1 chunk) ===");
    failures += tc4_subChunkFile(eng, dir.path());

    qInfo("=== TC5: Exactly 2 MiB file (2 full chunks) ===");
    failures += tc5_exact2MiB(eng, dir.path());

    if (failures) {
        qCritical() << "TOTAL FAILURES:" << failures;
        return 1;
    }
    qInfo("ALL PER-CHUNK AEAD TESTS PASSED");
    return 0;
}
