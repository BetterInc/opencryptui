// Menu-action slots (Exit, Preferences, About, About Ciphers / KDFs /
// Iterations, Security Guide). Static text dialogs + one QInputDialog —
// no heavy logic, just long literal strings. Pulled out of
// mainwindow.cpp so the main window file can focus on actual UI wiring.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "version.h"
#include "encryptionengine.h"
#include <QApplication>
#include <QMessageBox>
#include <QInputDialog>

void MainWindow::on_actionExit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_actionPreferences_triggered()
{
    QStringList themes = {"Light", "Dark"};
    bool ok;
    QString theme = QInputDialog::getItem(this, "Select Theme", "Theme:", themes, 0, false, &ok);
    if (ok && !theme.isEmpty())
    {
        applyTheme(theme);
    }
}

void MainWindow::on_actionAbout_triggered()
{
    QString aboutText = QString(
                            "Open Encryption UI\n"
                            "Version: %1\n"
                            "Latest Commit: %2\n"
                            "Hardware Acceleration: %3")
                            .arg(GIT_TAG)
                            .arg(GIT_COMMIT_HASH)
                            .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::about(this, "About", aboutText);
}
void MainWindow::on_actionAboutCiphers_triggered()
{
    QString aboutCiphersText = QString(
        "Top Ciphers for File Encryption:\n\n"
        "AES-256-GCM: Provides strong encryption with built-in data integrity and authentication. Highly recommended for file encryption due to its security and performance.\n\n"
        "ChaCha20-Poly1305: A secure cipher that is resistant to timing attacks. It is highly efficient on both software and hardware, and is suitable for environments where performance is critical.\n\n"
        "AES-256-CTR: A strong encryption mode suitable for stream encryption. It does not provide data integrity or authentication by itself, so it should be used with additional integrity checks.\n\n"
        "AES-256-CBC: A widely used encryption mode that provides strong encryption but does not include data integrity or authentication. It is suitable for file encryption but should be combined with a message authentication code (MAC) to ensure data integrity.\n\n"
        "Recommendation: For maximum security in file encryption, use AES-256-GCM or ChaCha20-Poly1305, as they provide both strong encryption and built-in data integrity and authentication.");

    QMessageBox::information(this, "About Ciphers", aboutCiphersText);
}

void MainWindow::on_actionAboutKDFs_triggered()
{
    QString aboutKDFsText = QString(
        "Key Derivation Function (KDF) Information:\n\n"
        "Argon2:\n"
        "  - Designed to resist both GPU and ASIC attacks.\n"
        "  - Highly secure and the winner of the Password Hashing Competition (PHC).\n"
        "  - Recommended for new applications requiring strong password hashing.\n\n"
        "Scrypt:\n"
        "  - Designed to be highly memory-intensive, making it resistant to hardware attacks.\n"
        "  - Suitable for environments where memory usage is not a constraint.\n\n"
        "PBKDF2:\n"
        "  - Widely used and well-established.\n"
        "  - Provides basic protection against brute-force attacks by increasing the computation required.\n"
        "  - Recommended for compatibility with older systems and applications.\n\n"
        "Recommendation:\n"
        "For maximum security, Argon2 is the best choice due to its resistance to various types of attacks. "
        "If memory usage is a concern, Scrypt offers a good balance of security and performance. PBKDF2 should "
        "be used primarily for compatibility with existing systems.");

    QMessageBox::information(this, "About KDFs", aboutKDFsText);
}

void MainWindow::on_actionAboutIterations_triggered()
{
    QString aboutIterationsText = QString(
        "About Iterations:\n\n"
        "The number of iterations used in key derivation functions (KDFs) is a critical factor in the security "
        "of the encryption process. Iterations increase the computational effort required to derive the encryption "
        "key, making brute-force attacks more difficult.\n\n"
        "Recommended Iteration Counts:\n"
        "- Argon2: 10 or more iterations. Argon2 is memory-hard, and higher iterations further increase security.\n"
        "- Scrypt: N = 2^20 (1,048,576) or higher. Scrypt is also memory-hard, and high iteration counts make it more resistant to attacks.\n"
        "- PBKDF2: 10,000,000 or more iterations. PBKDF2 relies on high iteration counts to increase security.\n\n"
        "For maximum security, consider using higher iteration counts, especially if performance is not a critical concern.");

    QMessageBox::information(this, "About Iterations", aboutIterationsText);
}

void MainWindow::on_actionSecurityGuide_triggered()
{
    QString securityGuideText = QString(
        "Security Best Practices Guide\n\n"
        "Secure Password Creation:\n"
        "• Use a MINIMUM of 12 characters, preferably 16+ for highly sensitive data\n"
        "• Include uppercase letters, lowercase letters, numbers, and special characters\n"
        "• Avoid dictionary words, names, dates, or predictable patterns\n"
        "• Consider using a passphrase (multiple words with special characters)\n"
        "• Never reuse passwords from other services or applications\n\n"
        
        "File Security:\n"
        "• Store encrypted files in locations only you have access to\n"
        "• Never store encrypted files in shared directories or cloud services that don't use E2E encryption\n"
        "• Keep keyfiles on separate physical devices (USB drive) from encrypted files\n"
        "• Consider using both a password AND keyfile for critical data\n"
        "• NEVER share passwords through email, messaging, or unencrypted channels\n\n"
        
        "Encryption Settings:\n"
        "• For highest security, use AES-256-GCM or ChaCha20-Poly1305 ciphers\n"
        "• Enable HMAC for additional integrity protection\n"
        "• Use Argon2 KDF when available or Scrypt as alternative\n"
        "• Use high iteration counts (10+) for sensitive data\n"
        "• Use tamper evidence features for critical files\n\n"
        
        "Safe Computing Practices:\n"
        "• Keep your device secure and updated with latest security patches\n"
        "• Use a secure, up-to-date operating system\n"
        "• Be aware of physical surroundings when entering passwords\n"
        "• Scan files for malware before encryption/decryption\n"
        "• Close the application when not in use\n\n"
        
        "Emergency Preparation:\n"
        "• Keep secure offline backups of critical encryption keys\n"
        "• Document recovery procedures and store securely\n"
        "• Test recovery process periodically to ensure it works\n"
        "• Consider secure key escrow for organizational use\n\n"
        
        "Remember: The security of your data is only as strong as your weakest practice!"
    );

    QMessageBox::information(this, "Security Guide", securityGuideText);
}
