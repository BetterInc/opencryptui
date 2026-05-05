#include "logging/secure_logger.h"
#include <QDir>
#include <QRegularExpression>
#include <QStandardPaths>

SecureLogger& SecureLogger::getInstance() {
    static SecureLogger instance;
    return instance;
}

SecureLogger::SecureLogger() 
    : m_currentLogLevel(LogLevel::WARNING),
      m_logToFile(false),
      m_logFile(nullptr),
      m_logStream(nullptr) {
    // Default log path in user's home directory
    m_logFilePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/logs/opencryptui.log";
}

SecureLogger::~SecureLogger() {
    // Close and delete file if it exists
    if (m_logFile) {
        if (m_logFile->isOpen()) {
            m_logFile->close();
        }
        delete m_logFile;
    }
    
    // Delete stream if it exists
    if (m_logStream) {
        delete m_logStream;
    }
}

void SecureLogger::log(LogLevel level, const QString& component, const QString& message) {
    // All log control is now done in the SECURE_LOG macro
    QMutexLocker locker(&m_mutex);

    // Check if logging is allowed based on current log level
    if (level < m_currentLogLevel) return;

    // Sanitize the message
    QString sanitizedMessage = sanitizeMessage(message);

    // Prepare log entry
    QString logEntry = QString("[%1] [%2] %3: %4")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
        .arg(logLevelToString(level))
        .arg(component)
        .arg(sanitizedMessage);

    // Always log to console during tests
    bool isTest = qgetenv("QT_LOGGING_RULES").contains("*.debug=true") || 
                  component.startsWith("TestOpenCryptUI") || 
                  component.startsWith("Test");

    // Always log during debugging, but also always log for tests and OpenSSL provider
    // regardless of build type to help with debugging tests
    if (isTest || component.startsWith("OpenSSLProvider") || component == "EncryptionEngine") {
        switch(level) {
            case LogLevel::DEBUG:
                qDebug() << "SECLOG:" << logEntry;
                break;
            case LogLevel::INFO:
                qInfo() << "SECLOG:" << logEntry;
                break;
            case LogLevel::WARNING:
                qWarning() << "SECLOG:" << logEntry;
                break;
            case LogLevel::ERROR_LEVEL:
                qCritical() << "SECLOG:" << logEntry;
                break;
        }
    }
    #ifndef QT_NO_DEBUG
    else {
        switch(level) {
            case LogLevel::DEBUG:
                qDebug() << logEntry;
                break;
            case LogLevel::INFO:
                qInfo() << logEntry;
                break;
            case LogLevel::WARNING:
                qWarning() << logEntry;
                break;
            case LogLevel::ERROR_LEVEL:
                qCritical() << logEntry;
                break;
        }
    }
    #endif

    // File logging
    if (m_logToFile) {
        // Ensure log directory exists
        QDir().mkpath(QFileInfo(m_logFilePath).path());

        // Open log file
        if (!m_logFile) {
            m_logFile = new QFile(m_logFilePath);
            if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
                m_logStream = new QTextStream(m_logFile);
            }
        }

        // Write to file if possible
        if (m_logStream) {
            *m_logStream << logEntry << "\n";
            m_logStream->flush();
        }
    }
}

void SecureLogger::setLogLevel(LogLevel level) {
    m_currentLogLevel = level;
}

void SecureLogger::setLogToFile(bool enabled, const QString& filePath) {
    m_logToFile = enabled;
    if (!filePath.isEmpty()) {
        m_logFilePath = filePath;
    }
}

QString SecureLogger::logLevelToString(LogLevel level) {
    switch(level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// sanitizeMessage — value-aware redaction
//
// Design decisions:
//
//  • All QRegularExpression objects are static locals compiled once at first
//    call.  QRegularExpression is re-entrant for matching, so this is safe
//    under the mutex that log() already holds before calling us.
//
//  • Three layers of detection (applied in order, most-specific first):
//
//    1. Labelled patterns  — "<keyword>: <hex>", "<keyword>=<hex>",
//                            "<keyword> (hex): <hex>", "<keyword> (base64): <b64>"
//       Replace only the value token; keep the keyword in the output so the
//       reader knows what field was present.
//
//    2. Free-floating long secrets — bare hex run >= 64 chars (32 bytes) or
//       bare base64 run >= 44 chars (32+ bytes) anywhere in the message.
//       These are overwhelmingly cryptographic material with no legitimate
//       reason to appear verbatim in a log line.
//
//    3. Keyword-only fallback — matches from the original code, kept for
//       backward compatibility with explicit "[REDACTED]" markers in call
//       sites that were added before value-redaction existed.
//
//  • Output format: <REDACTED:N-bytes> preserves size metadata useful for
//    "salt size mismatch" diagnostics without leaking the value.
// ---------------------------------------------------------------------------

// Estimate byte count from a matched value token.
static int hexBytes(const QString& s)   { return s.length() / 2; }
static int b64Bytes(const QString& s)
{
    // base64: every 4 chars encodes 3 bytes; trim padding.
    int len = s.length();
    int pad = s.endsWith("==") ? 2 : (s.endsWith('=') ? 1 : 0);
    return (len / 4) * 3 - pad;
}

QString SecureLogger::sanitizeMessage(const QString& message) {
    QString sanitized = message;

    // 1. Replace home path (path information leak, not a crypto secret but
    //    retained from the original implementation).
    sanitized.replace(QDir::homePath(), "[HOME]");

    // -----------------------------------------------------------------------
    // Regex patterns — compiled once.
    // -----------------------------------------------------------------------

    // Keyword group (case-insensitive).
    static const QString kKeywords =
        QStringLiteral("password|passphrase|pwd|key|salt|iv|nonce|tag|mac|hmac|secret|token|seed");

    // Hex value: 16 or more hex digits (lower bound keeps short IDs like
    // "id: 1234" untouched — those have fewer than 16 hex chars).
    static const QString kHex = QStringLiteral("[0-9A-Fa-f]{16,}");

    // Base64 value: 16 or more base64 chars (covers >=12 bytes).
    static const QString kB64 = QStringLiteral("[A-Za-z0-9+/]{16,}={0,2}");

    // Pattern 1a: keyword: <hex>   (colon-space separated)
    static const QRegularExpression reColonHex(
        QStringLiteral("(?i)\\b(") + kKeywords + QStringLiteral(")\\s*:\\s*(") + kHex + QStringLiteral(")\\b"),
        QRegularExpression::CaseInsensitiveOption);

    // Pattern 1b: keyword=<hex>   (equals-separated, e.g. query-string style)
    static const QRegularExpression reEqHex(
        QStringLiteral("(?i)\\b(") + kKeywords + QStringLiteral(")=") + QStringLiteral("(") + kHex + QStringLiteral(")"),
        QRegularExpression::CaseInsensitiveOption);

    // Pattern 1c: keyword (hex): <hex>
    static const QRegularExpression reParenHex(
        QStringLiteral("(?i)\\b(") + kKeywords + QStringLiteral(")\\s+\\(hex\\)\\s*:\\s*(") + kHex + QStringLiteral(")"),
        QRegularExpression::CaseInsensitiveOption);

    // Pattern 1d: keyword (base64): <b64>
    static const QRegularExpression reParenB64(
        QStringLiteral("(?i)\\b(") + kKeywords + QStringLiteral(")\\s+\\(base64\\)\\s*:\\s*(") + kB64 + QStringLiteral(")"),
        QRegularExpression::CaseInsensitiveOption);

    // Pattern 2a: free-floating long hex (>= 64 hex chars = 32 bytes).
    static const QRegularExpression reLongHex(
        QStringLiteral("\\b([0-9A-Fa-f]{64,})\\b"));

    // Pattern 2b: free-floating long base64 (>= 32 alphanum chars ~ 24 bytes).
    // No trailing \b — base64 padding ends in '=' which is non-word, and
    // \b can't match between a non-word char and EOS. Use a lookahead
    // for any non-word boundary OR end-of-string instead.
    // Threshold of 32 catches typical cryptographic blobs (24+ bytes) while
    // staying well above any legitimate identifier length we'd log.
    static const QRegularExpression reLongB64(
        QStringLiteral("\\b([A-Za-z0-9+/]{32,}={0,2})(?=[^A-Za-z0-9+/=]|$)"));

    // -----------------------------------------------------------------------
    // Apply labelled patterns first (1a–1d): replace only the value capture.
    // -----------------------------------------------------------------------

    auto replaceValue = [](QString& s, const QRegularExpression& re, bool isB64) {
        int offset = 0;
        QRegularExpressionMatch m;
        while ((m = re.match(s, offset)).hasMatch()) {
            // capture(1) = keyword, capture(2) = value
            QString redacted = QStringLiteral("<REDACTED:%1-bytes>")
                .arg(isB64 ? b64Bytes(m.captured(2)) : hexBytes(m.captured(2)));
            // Replace only the value part (capture group 2).
            int valStart = m.capturedStart(2);
            int valLen   = m.capturedLength(2);
            s.replace(valStart, valLen, redacted);
            // Advance past the replaced region (keyword is still there).
            offset = valStart + redacted.length();
        }
    };

    replaceValue(sanitized, reColonHex,  false);
    replaceValue(sanitized, reEqHex,     false);
    replaceValue(sanitized, reParenHex,  false);
    replaceValue(sanitized, reParenB64,  true);

    // -----------------------------------------------------------------------
    // Apply free-floating long-secret patterns (2a–2b).
    // Skip if the match position is already inside a <REDACTED:…> token to
    // avoid double-processing; a simple "does the match start after a '>'"
    // check is sufficient because we just injected those markers.
    // -----------------------------------------------------------------------

    auto replaceLong = [](QString& s, const QRegularExpression& re, bool isB64) {
        int offset = 0;
        QRegularExpressionMatch m;
        while ((m = re.match(s, offset)).hasMatch()) {
            QString val = m.captured(1);
            // Skip tokens that are part of a <REDACTED:N-bytes> we inserted.
            if (m.capturedStart(1) > 0 &&
                s.at(m.capturedStart(1) - 1) == QLatin1Char(':')) {
                offset = m.capturedEnd();
                continue;
            }
            QString redacted = QStringLiteral("<REDACTED:%1-bytes>")
                .arg(isB64 ? b64Bytes(val) : hexBytes(val));
            s.replace(m.capturedStart(1), m.capturedLength(1), redacted);
            offset = m.capturedStart(1) + redacted.length();
        }
    };

    replaceLong(sanitized, reLongHex, false);
    replaceLong(sanitized, reLongB64, true);

    // NOTE: the original keyword-only fallback (replace bare "secret" /
    // "key" with "[REDACTED]") was REMOVED. It was the source of the
    // forensics-audit finding it was supposed to defend against — masking
    // the keyword leaves the value exposed, AND it false-positive-matches
    // benign sentences like "no secret here". The labelled value-aware
    // patterns plus the free-floating hex/base64 nets above are the source
    // of truth now. If a log message says "Processing key material" with
    // no secret bytes attached, the word "key" remains visible — that's
    // fine and arguably more useful for debugging.
    return sanitized;
}
