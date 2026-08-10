// Preferences, theme, and persistent settings. Extracted from
// mainwindow.cpp; loadPreferences / savePreferences use QSettings and
// applyTheme swaps the stylesheet. The on_actionPreferences_triggered
// slot that invokes applyTheme lives in mainwindow_menu.cpp.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QSettings>
#include <QTextStream>
#include <QPalette>
#include <QColor>
#include "logging/secure_logger.h"

void MainWindow::applyTheme(const QString &theme)
{
    QString themeFilePath;
    if (theme == "Dark")
    {
        themeFilePath = ":/resources/darktheme.qss";
    }
    else
    {
        themeFilePath = ":/resources/lighttheme.qss";
    }

    SECURE_LOG(DEBUG, "MainWindow", QString("Trying to load stylesheet from: %1").arg(themeFilePath));

    QFile file(themeFilePath);

    if (!file.exists())
    {
        SECURE_LOG(WARNING, "MainWindow", QString("QSS file does not exist at path: %1").arg(themeFilePath));
        return;
    }

    if (file.open(QFile::ReadOnly))
    {
        QString styleSheet = QLatin1String(file.readAll());
        qApp->setStyleSheet(styleSheet);
        file.close();

        // Drive an opaque application palette as well. A stylesheet-only
        // background can leave top-level dialog/popup surfaces (About,
        // Preferences, message boxes) unpainted on some Wayland/EGL backends -
        // the window renders transparent and you see the desktop through it.
        // An explicit palette guarantees an opaque window fill on every backend;
        // styled widgets keep their look because stylesheet rules win over the
        // palette.
        QPalette pal = qApp->palette();
        if (theme == "Dark")
        {
            pal.setColor(QPalette::Window, QColor(0x2d, 0x2d, 0x2d));
            pal.setColor(QPalette::WindowText, QColor(0xd3, 0xd3, 0xd3));
            pal.setColor(QPalette::Base, QColor(0x23, 0x23, 0x23));
            pal.setColor(QPalette::AlternateBase, QColor(0x2d, 0x2d, 0x2d));
            pal.setColor(QPalette::Text, QColor(0xd3, 0xd3, 0xd3));
            pal.setColor(QPalette::Button, QColor(0x2d, 0x2d, 0x2d));
            pal.setColor(QPalette::ButtonText, QColor(0xd3, 0xd3, 0xd3));
            pal.setColor(QPalette::ToolTipBase, QColor(0x3a, 0x3a, 0x3a));
            pal.setColor(QPalette::ToolTipText, QColor(0xd3, 0xd3, 0xd3));
        }
        else
        {
            pal.setColor(QPalette::Window, QColor(0xff, 0xff, 0xff));
            pal.setColor(QPalette::WindowText, QColor(0x00, 0x00, 0x00));
            pal.setColor(QPalette::Base, QColor(0xff, 0xff, 0xff));
            pal.setColor(QPalette::AlternateBase, QColor(0xf0, 0xf0, 0xf0));
            pal.setColor(QPalette::Text, QColor(0x00, 0x00, 0x00));
            pal.setColor(QPalette::Button, QColor(0xf0, 0xf0, 0xf0));
            pal.setColor(QPalette::ButtonText, QColor(0x00, 0x00, 0x00));
            pal.setColor(QPalette::ToolTipBase, QColor(0xff, 0xff, 0xff));
            pal.setColor(QPalette::ToolTipText, QColor(0x00, 0x00, 0x00));
        }
        qApp->setPalette(pal);

        currentTheme = theme; // Update current theme
        SECURE_LOG(INFO, "MainWindow", QString("Successfully applied theme from: %1").arg(themeFilePath));
    }
    else
    {
        SECURE_LOG(ERROR_LEVEL, "MainWindow", QString("Failed to open theme file: %1").arg(file.errorString()));
    }
}

void MainWindow::loadPreferences()
{
    QString settingsDirPath = QDir::homePath() + "/.opencryptui";
    QString settingsFilePath = settingsDirPath + "/config.json";

    // Defaults for a first run (or unreadable config): Light theme, Easy mode
    // so first-time / non-expert users get the simple experience. These must be
    // applied even when no config exists - skipping applyUiMode() would leave
    // BOTH the Easy home and the Advanced tabs visible (setupUi shows the tabs
    // by default).
    QString theme = "Light";
    QString mode = "Easy";

    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists() && !settingsDir.mkpath(settingsDirPath))
    {
        SECURE_LOG(ERROR_LEVEL, "MainWindow", QString("Failed to create settings directory: %1").arg(settingsDirPath));
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.exists())
    {
        SECURE_LOG(INFO, "MainWindow", "Settings file not found, applying defaults.");
    }
    else if (!settingsFile.open(QIODevice::ReadOnly))
    {
        SECURE_LOG(ERROR_LEVEL, "MainWindow", QString("Failed to open settings file for reading: %1").arg(settingsFile.errorString()));
    }
    else
    {
        QByteArray settingsData = settingsFile.readAll();
        QJsonDocument settingsDoc = QJsonDocument::fromJson(settingsData);
        QJsonObject settingsObj = settingsDoc.object();

        theme = settingsObj.value("theme").toString(theme);
        // UI mode: "Easy" (simple home) or "Advanced" (full tabs).
        mode = settingsObj.value("mode").toString(mode);

        settingsFile.close();
    }

    applyTheme(theme);
    applyUiMode(mode == "Advanced");
}

void MainWindow::savePreferences()
{
    QString settingsDirPath = QDir::homePath() + "/.opencryptui";
    QString settingsFilePath = settingsDirPath + "/config.json";

    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists())
    {
        if (!settingsDir.mkpath(settingsDirPath))
        {
            SECURE_LOG(ERROR_LEVEL, "MainWindow", QString("Failed to create settings directory: %1").arg(settingsDirPath));
            return;
        }
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.open(QIODevice::WriteOnly))
    {
        SECURE_LOG(ERROR_LEVEL, "MainWindow", QString("Failed to open settings file for writing: %1").arg(settingsFile.errorString()));
        return;
    }

    QJsonObject settingsObj;
    settingsObj["theme"] = currentTheme; // Assuming currentTheme is a member variable holding the current theme
    settingsObj["mode"] = m_advancedMode ? "Advanced" : "Easy";

    QJsonDocument settingsDoc(settingsObj);
    settingsFile.write(settingsDoc.toJson());

    settingsFile.close();
}

