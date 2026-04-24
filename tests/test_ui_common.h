// Shared include set for the tests/test_ui_*.cpp files. Each of those
// TUs defines methods on TestOpenCryptUI (declared in
// tests/test_encryption_app.h) — they all need the same Qt + Widgets
// headers so pulling the common block into one header keeps the .cpp
// files focused on test logic.
#ifndef TESTS_TEST_UI_COMMON_H
#define TESTS_TEST_UI_COMMON_H

#include "test_encryption_app.h"
#include "logging/secure_logger.h"
#include "encryptionengine.h"

#include <QTest>
#include <QSignalSpy>
#include <QApplication>
#include <QTabWidget>
#include <QMessageBox>
#include <QDialog>
#include <QFile>
#include <QDir>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QListWidget>
#include <QLabel>
#include <QProgressBar>

#endif
