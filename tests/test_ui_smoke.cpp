// UI smoke tests: tab switching + crypto-provider combobox behaviour.
#include "test_ui_common.h"

void TestOpenCryptUI::testTabSwitching()
{
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Starting tab switching test");

    QTabWidget *tabWidget = mainWindow->findChild<QTabWidget *>("tabWidget");
    QVERIFY(tabWidget);

    // First verify the tab count and names
    SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Tab count: %1").arg(tabWidget->count()));
    QStringList tabNames;
    for (int i = 0; i < tabWidget->count(); i++)
    {
        tabNames << tabWidget->tabText(i);
        SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Tab %1: %2").arg(i).arg(tabWidget->tabText(i)));
    }
    SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Available tabs: %1").arg(tabNames.join(", ")));

    // Store starting index - don't assume it's 0
    int startingIndex = tabWidget->currentIndex();
    SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Starting at tab index: %1").arg(startingIndex));

    // Try switching to each tab and verify UI elements
    // 1. File Tab
    switchToTab("File");
    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit *>("filePathLineEdit");
    QLineEdit *filePasswordInput = mainWindow->findChild<QLineEdit *>("filePasswordLineEdit");
    QPushButton *fileEncryptButton = mainWindow->findChild<QPushButton *>("fileEncryptButton");
    QVERIFY(filePathInput);
    QVERIFY(filePasswordInput);
    QVERIFY(fileEncryptButton);
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Successfully switched to File tab");

    // 2. Folder Tab
    switchToTab("Folder");
    QLineEdit *folderPathInput = mainWindow->findChild<QLineEdit *>("folderPathLineEdit");
    QLineEdit *folderPasswordInput = mainWindow->findChild<QLineEdit *>("folderPasswordLineEdit");
    QPushButton *folderEncryptButton = mainWindow->findChild<QPushButton *>("folderEncryptButton");
    QVERIFY(folderPathInput);
    QVERIFY(folderPasswordInput);
    QVERIFY(folderEncryptButton);
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Successfully switched to Folder tab");

    // 3. Disk Tab
    switchToTab("Disk");
    QLineEdit *diskPathInput = mainWindow->findChild<QLineEdit *>("diskPathLineEdit");
    QLineEdit *diskPasswordInput = mainWindow->findChild<QLineEdit *>("diskPasswordLineEdit");
    QPushButton *diskEncryptButton = mainWindow->findChild<QPushButton *>("diskEncryptButton");
    QVERIFY(diskPathInput);
    QVERIFY(diskPasswordInput);
    QVERIFY(diskEncryptButton);
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Successfully switched to Disk tab");

    // 4. Benchmark Tab (if exists)
    for (int i = 0; i < tabWidget->count(); i++)
    {
        if (tabWidget->tabText(i).contains("Benchmark", Qt::CaseInsensitive))
        {
            switchToTab("Benchmark");
            QPushButton *benchmarkButton = mainWindow->findChild<QPushButton *>("benchmarkButton");
            QVERIFY(benchmarkButton);
            SECURE_LOG(DEBUG, "TestOpenCryptUI", "Successfully switched to Benchmark tab");
            break;
        }
    }

    // Switch back to starting tab (don't assume it's disk tab)
    SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Switching back to starting tab index: %1").arg(startingIndex));
    tabWidget->setCurrentIndex(startingIndex);
    QTest::qWait(WAIT_TIME_MEDIUM); // Wait after tab switch
    
    // Verify we returned to the starting tab
    QCOMPARE(tabWidget->currentIndex(), startingIndex);

    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Tab switching test completed successfully");
}

// Switch to tab helper function with better platform compatibility
void TestOpenCryptUI::switchToTab(const QString &tabName)
{
    QTabWidget *tabWidget = mainWindow->findChild<QTabWidget *>("tabWidget");
    QVERIFY(tabWidget);

    // Find the tab with the matching name
    int tabIndex = -1;
    for (int i = 0; i < tabWidget->count(); i++)
    {
        if (tabWidget->tabText(i).contains(tabName, Qt::CaseInsensitive))
        {
            tabIndex = i;
            break;
        }
    }

    if (tabIndex >= 0)
    {
        SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Switching to tab: %1 at index %2").arg(tabName).arg(tabIndex));
        tabWidget->setCurrentIndex(tabIndex);
        QTest::qWait(WAIT_TIME_MEDIUM); // Wait for tab switch animation
        QCOMPARE(tabWidget->currentIndex(), tabIndex);
    }
    else
    {
        QFAIL(qPrintable(QString("Tab '%1' not found").arg(tabName)));
    }
}
void TestOpenCryptUI::testCryptoProviderSwitching()
{
    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Starting crypto provider switching test");

    // Find provider combo box
    QComboBox *providerComboBox = mainWindow->findChild<QComboBox *>("m_cryptoProviderComboBox");
    QVERIFY(providerComboBox);

    // Get the list of available providers
    QStringList providers;
    for (int i = 0; i < providerComboBox->count(); i++)
    {
        providers << providerComboBox->itemText(i);
    }

    SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Available crypto providers: %1").arg(providers.join(", ")));
    QVERIFY(!providers.isEmpty());

    // Test each provider with different tabs
    QStringList tabsToTest = {"File", "Folder", "Disk"};

    for (const QString &provider : providers)
    {
        SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Testing provider: %1").arg(provider));
        int providerIndex = providerComboBox->findText(provider);
        QVERIFY(providerIndex >= 0);

        providerComboBox->setCurrentIndex(providerIndex);
        QTest::qWait(WAIT_TIME_LONG); // Wait for provider change

        // Verify provider selection
        QCOMPARE(providerComboBox->currentText(), provider);

        // Verify on different tabs
        for (const QString &tabName : tabsToTest)
        {
            switchToTab(tabName);

            // Get algorithm combo box for this tab
            QString algoComboName = tabName.toLower() + "AlgorithmComboBox";
            QComboBox *algoCombo = mainWindow->findChild<QComboBox *>(algoComboName);
            QVERIFY2(algoCombo, qPrintable(QString("Algorithm combo box not found for tab %1").arg(tabName)));

            // Get KDF combo box for this tab
            QString kdfComboName = tabName.toLower() + "KdfComboBox";
            QComboBox *kdfCombo = mainWindow->findChild<QComboBox *>(kdfComboName);
            if (!kdfCombo)
                kdfCombo = mainWindow->findChild<QComboBox *>("kdfComboBox");
            QVERIFY2(kdfCombo, qPrintable(QString("KDF combo box not found for tab %1").arg(tabName)));

            // Verify algorithm options are loaded
            QStringList algorithms;
            for (int i = 0; i < algoCombo->count(); i++)
            {
                algorithms << algoCombo->itemText(i);
            }
            SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Provider %1 on tab %2 supports algorithms: %3").arg(provider, tabName, algorithms.join(", ")));
            QVERIFY(!algorithms.isEmpty());

            // Verify KDF options are loaded
            QStringList kdfs;
            for (int i = 0; i < kdfCombo->count(); i++)
            {
                kdfs << kdfCombo->itemText(i);
            }
            SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Provider %1 on tab %2 supports KDFs: %3").arg(provider, tabName, kdfs.join(", ")));
            QVERIFY(!kdfs.isEmpty());

            // Test a few algorithm selections to make sure they work
            if (algoCombo->count() > 1)
            {
                algoCombo->setCurrentIndex(0);
                QTest::qWait(WAIT_TIME_SHORT);
                QString firstAlgo = algoCombo->currentText();

                algoCombo->setCurrentIndex(algoCombo->count() - 1);
                QTest::qWait(WAIT_TIME_SHORT);
                QString lastAlgo = algoCombo->currentText();

                SECURE_LOG(DEBUG, "TestOpenCryptUI", QString("Successfully switched algorithms from %1 to %2").arg(firstAlgo, lastAlgo));
            }
        }
    }

    SECURE_LOG(DEBUG, "TestOpenCryptUI", "Crypto provider switching test completed successfully");
}
