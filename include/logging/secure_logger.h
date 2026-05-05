#ifndef SECURE_LOGGER_H
#define SECURE_LOGGER_H

#include <QString>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>

class SecureLogger {
public:
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR_LEVEL  // Changed from ERROR to avoid Windows macro conflict
    };

    // Singleton pattern
    static SecureLogger& getInstance();

    // Logging methods
    void log(LogLevel level, const QString& component, const QString& message);
    void setLogLevel(LogLevel level);
    void setLogToFile(bool enabled, const QString& filePath = QString());

    // Disable copy constructor and assignment operator
    SecureLogger(SecureLogger const&) = delete;
    void operator=(SecureLogger const&) = delete;

    // Sanitize log message (remove sensitive information).
    // Public so tests can exercise it directly without going through log().
    QString sanitizeMessage(const QString& message);

private:
    SecureLogger(); // Private constructor
    ~SecureLogger();

    LogLevel m_currentLogLevel;
    bool m_logToFile;
    QString m_logFilePath;
    QFile* m_logFile;
    QTextStream* m_logStream;
    QMutex m_mutex;

    // Convert log level to string
    QString logLevelToString(LogLevel level);
};

// Check for CI/CD environment
#ifndef SECURE_LOGGER_H_CI_ENV
#define SECURE_LOGGER_H_CI_ENV
#include <QProcessEnvironment>
#include <QCoreApplication>

// Check if we're in release mode (no logging mode)
inline bool isReleaseMode() {
    static bool checked = false;
    static bool inRelease = false;
    if (!checked) {
        // Release mode (no logging) if:
        // 1. NO_LOGGING environment var exists OR
        // 2. NO_LOGGING defined at compile time
        // 3. App was compiled with NDEBUG and we're NOT in CI environment
        // 4. NOT explicitly ENABLE_LOGGING defined (for tests)
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        bool isCI = env.contains("CI") || env.contains("GITHUB_ACTIONS") || 
                   env.contains("GITLAB_CI") || env.contains("TRAVIS");
        
        // Check if logging is explicitly enabled for tests
        #ifdef ENABLE_LOGGING
            inRelease = false;
        #else
            // Explicitly disabled or release build outside CI
            #ifdef NO_LOGGING
                inRelease = true;
            #else
                inRelease = env.contains("NO_LOGGING") || 
                           (
                            #ifdef NDEBUG
                                true &&
                            #else
                                false &&
                            #endif
                            !isCI
                           );
            #endif
        #endif
        checked = true;
    }
    return inRelease;
}
#endif

// For ERROR level compatibility (since we renamed it to ERROR_LEVEL)
// Use a safer name that won't conflict with Windows headers
#define SECURE_LOG_ERROR ERROR_LEVEL

// Macro for logging with compile-time optimization
#define SECURE_LOG(level, component, message) \
    if (!isReleaseMode()) { \
        SecureLogger::getInstance().log(SecureLogger::LogLevel::level, component, message); \
    }

#endif // SECURE_LOGGER_H