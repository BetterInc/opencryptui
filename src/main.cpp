#include "mainwindow.h"
#include <QApplication>
#include <QLoggingCategory>
#include <openssl/crypto.h>
#include "version.h"
#include "logging/secure_logger.h"

int main(int argc, char *argv[])
{
    // Initialize OpenSSL with error checking
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        // Using our secure logger instead of qCritical
        SecureLogger::getInstance().log(SecureLogger::LogLevel::ERROR_LEVEL, "MainApplication", "Failed to initialize OpenSSL");
        return EXIT_FAILURE;
    }
    
    // Configure logging - simplified approach
    SecureLogger& logger = SecureLogger::getInstance();
    
    // Configure Qt logging rules to disable internal Qt logs
    QLoggingCategory::setFilterRules(
        "qt.*.debug=false\n"
        "qt.*.info=false\n"
        "qt.*.warning=false"
    );
    
    // No logging in the main application (OpenCryptUI)
    // All logging is done in the test version (OpenCryptUITest)
    logger.setLogLevel(SecureLogger::LogLevel::ERROR_LEVEL);
    logger.setLogToFile(false);
    
    // This is a test log message to verify logging configuration
    SECURE_LOG(INFO, "MainApplication", "Application starting - this should only appear in test mode");

#ifdef Q_OS_LINUX
    // Qt 5's native Wayland backend renders top-level popups (the About /
    // Preferences message boxes) with a transparent, unpainted background on
    // some GPU/EGL paths - you see the desktop through the dialog. XWayland
    // (the xcb platform) is unaffected. When we're on a Wayland session and the
    // user hasn't explicitly pinned a platform, prefer xcb so popups are always
    // opaque. Must be set before QApplication is constructed.
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM") &&
        !qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"))
    {
        qputenv("QT_QPA_PLATFORM", "xcb");
    }
#endif

    QApplication app(argc, argv);

    Q_INIT_RESOURCE(resources);

    // Create an instance of MainWindow
    MainWindow mainWindow;

    // Optionally, check if there are any other instances of MainWindow
    QWidgetList topLevelWidgets = QApplication::topLevelWidgets();
    int mainWindowCount = 0;
    for (QWidget *widget : topLevelWidgets) {
        if (qobject_cast<MainWindow*>(widget)) {
            mainWindowCount++;
        }
    }

    // Use SECURE_LOG instead of qDebug for logging MainWindow instances
    #ifdef QT_DEBUG
    SECURE_LOG(DEBUG, "MainApplication", 
        QString("Number of MainWindow instances: %1").arg(mainWindowCount));
    #endif

    // Show the MainWindow
    mainWindow.show();

    return app.exec();
}
