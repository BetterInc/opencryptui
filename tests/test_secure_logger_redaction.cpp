// test_secure_logger_redaction.cpp
//
// Unit tests for SecureLogger::sanitizeMessage() value-aware redaction.
//
// Test cases:
//   TC1  "salt: <64-hex>"            — hex value after colon masked
//   TC2  "iv=<mixed-case hex>"       — equals-form, mixed-case hex masked
//   TC3  "the password is hunter2"   — non-hex value NOT masked (plaintext word)
//   TC4  Bare 64-char hex string     — free-floating long hex masked
//   TC5  "no secret here"            — unchanged, no sensitive data
//   TC6  Short hex "id: 1234"        — short hex (<16 hex chars) NOT masked
//   TC7  Empty string                — returns empty string
//   TC8  "key (hex): <32-hex>"       — parenthesised form masked
//   TC9  "token (base64): <b64>"     — base64 form masked
//   TC10 Bare 44-char base64         — free-floating long base64 masked
//   TC11 "Generated salt (hex): <64-hex>" — original bug scenario fixed
//   TC12 Size annotation in output   — <REDACTED:N-bytes> encodes correct N

#include "logging/secure_logger.h"
#include <QCoreApplication>
#include <QString>
#include <cstdio>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int failures = 0;

static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) ++failures;
}

// Convenience: call sanitizeMessage on a plain C-string literal.
static QString sanitize(const char* msg)
{
    return SecureLogger::getInstance().sanitizeMessage(QString::fromUtf8(msg));
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// TC1: "salt: <64 hex chars>" — value must be masked, keyword preserved.
static void tc1_saltColonHex()
{
    const char* input =
        "salt: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    QString out = sanitize(input);

    bool valueGone  = !out.contains("a1b2c3d4e5f6");
    bool hasMarker  = out.contains("<REDACTED:");
    // "salt" keyword itself should still be present (we mask the value, not the label)
    bool kwPresent  = out.toLower().contains("salt") || out.contains("[REDACTED]");

    check(valueGone,  "TC1: hex value removed from output");
    check(hasMarker,  "TC1: <REDACTED:N-bytes> marker present");
    check(kwPresent,  "TC1: keyword still identifiable in output");
}

// TC2: "iv=<mixed-case hex 32 chars>" — equals form, mixed case.
static void tc2_ivEqualsHexMixedCase()
{
    const char* input = "iv=A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5";  // 32 hex chars
    QString out = sanitize(input);

    bool valueGone = !out.contains("A1B2C3D4");
    bool hasMarker = out.contains("<REDACTED:");
    check(valueGone, "TC2: mixed-case hex value removed");
    check(hasMarker, "TC2: <REDACTED:N-bytes> marker present");
}

// TC3: "the password is hunter2" — "hunter2" is not hex; must NOT be treated
//      as a secret value.  The keyword "password" may be masked via the
//      fallback, but "hunter2" must survive intact.
static void tc3_nonHexValuePreserved()
{
    const char* input = "the password is hunter2";
    QString out = sanitize(input);

    bool hunter2Present = out.contains("hunter2");
    check(hunter2Present, "TC3: non-hex value 'hunter2' not redacted");
}

// TC4: Bare 64-char hex string anywhere in the message (no keyword label).
static void tc4_freeFloatingLongHex()
{
    // 64 hex chars = 32 bytes, threshold for free-floating redaction.
    const char* input =
        "debug dump: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff end";
    QString out = sanitize(input);

    bool hexGone   = !out.contains("00112233445566778899");
    bool hasMarker = out.contains("<REDACTED:");
    check(hexGone,   "TC4: free-floating long hex removed");
    check(hasMarker, "TC4: <REDACTED:N-bytes> marker present");
}

// TC5: Benign message — must come through unchanged (modulo home-path masking
//      which is unrelated to this test — we don't embed home path here).
static void tc5_benignMessage()
{
    const char* input = "no secret here";
    QString out = sanitize(input);
    check(out == input, "TC5: benign message unchanged");
}

// TC6: Short hex-like string "id: 1234" — only 4 hex chars, below threshold.
static void tc6_shortHexNotMasked()
{
    const char* input = "id: 1234";
    QString out = sanitize(input);
    bool shortHexPresent = out.contains("1234");
    check(shortHexPresent, "TC6: short hex value (<16 chars) not masked");
}

// TC7: Empty string.
static void tc7_emptyString()
{
    QString out = sanitize("");
    check(out.isEmpty(), "TC7: empty input produces empty output");
}

// TC8: "key (hex): <32-hex-chars>" — parenthesised labelled form.
static void tc8_keyParenHex()
{
    const char* input = "key (hex): deadbeefcafebabe0102030405060708";  // 32 hex chars
    QString out = sanitize(input);

    bool valueGone = !out.contains("deadbeef");
    bool hasMarker = out.contains("<REDACTED:");
    check(valueGone, "TC8: (hex): value removed");
    check(hasMarker, "TC8: <REDACTED:N-bytes> marker present");
}

// TC9: "token (base64): <base64>" — parenthesised base64 form.
static void tc9_tokenParenBase64()
{
    // 44 chars of base64 encodes 33 bytes (with one pad char).
    const char* input = "token (base64): SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSA==";
    QString out = sanitize(input);

    bool valueGone = !out.contains("SGVsbG9X");
    bool hasMarker = out.contains("<REDACTED:");
    check(valueGone, "TC9: base64 value removed");
    check(hasMarker, "TC9: <REDACTED:N-bytes> marker present");
}

// TC10: Bare long base64 string (>= 44 chars) without a keyword label.
static void tc10_freeFloatingLongBase64()
{
    // 44 base64 chars with valid padding.
    const char* input = "state: SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSA==";
    QString out = sanitize(input);

    bool b64Gone   = !out.contains("SGVsbG9X");
    bool hasMarker = out.contains("<REDACTED:");
    check(b64Gone,   "TC10: free-floating long base64 removed");
    check(hasMarker, "TC10: <REDACTED:N-bytes> marker present");
}

// TC11: The original bug scenario — "Generated salt (hex): <64-hex>".
//       Before the fix the hex value survived sanitization.
static void tc11_generatedSaltHex()
{
    const char* input =
        "Generated salt (hex): a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    QString out = sanitize(input);

    bool hexGone   = !out.contains("a1b2c3d4e5f6a7b8");
    bool hasMarker = out.contains("<REDACTED:");
    check(hexGone,   "TC11: original-bug hex value no longer leaks");
    check(hasMarker, "TC11: <REDACTED:N-bytes> marker present");
}

// TC12: The <REDACTED:N-bytes> annotation encodes the correct byte count.
//       32 hex chars = 16 bytes.
static void tc12_sizeAnnotation()
{
    const char* input = "salt: 0102030405060708090a0b0c0d0e0f10";  // 32 hex chars = 16 bytes (wait: 34 chars)
    // Use exactly 32 hex chars (16 bytes).
    const char* input16 = "salt: 0102030405060708090a0b0c0d0e0f";  // 34 chars — still valid, 17 bytes
    // Construct a clean 32-char (16 byte) value.
    const char* inputClean = "salt: 00112233445566778899aabbccddeeff";  // 32 hex = 16 bytes
    QString out = sanitize(inputClean);

    // "00112233445566778899aabbccddeeff" is 32 hex chars => 16 bytes.
    bool correct = out.contains("<REDACTED:16-bytes>");
    check(correct, "TC12: <REDACTED:16-bytes> annotation is correct for 32-char hex");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    tc1_saltColonHex();
    tc2_ivEqualsHexMixedCase();
    tc3_nonHexValuePreserved();
    tc4_freeFloatingLongHex();
    tc5_benignMessage();
    tc6_shortHexNotMasked();
    tc7_emptyString();
    tc8_keyParenHex();
    tc9_tokenParenBase64();
    tc10_freeFloatingLongBase64();
    tc11_generatedSaltHex();
    tc12_sizeAnnotation();

    if (failures) {
        std::fprintf(stderr, "\nFAILED: %d test(s)\n", failures);
        std::fflush(stderr);
        return 1;
    }
    std::fprintf(stderr, "\nALL REDACTION TESTS PASSED\n");
    std::fflush(stderr);
    return 0;
}
