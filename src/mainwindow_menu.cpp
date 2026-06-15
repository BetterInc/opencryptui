// Menu-action slots (Exit, Preferences, About, About Ciphers / KDFs /
// Iterations, Security Guide). Static text dialogs + one QInputDialog -
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
    QString commitHash = QString(GIT_COMMIT_HASH).left(10);
    QString aboutText = QString(
                            "Open Encryption UI\n"
                            "Version: %1\n"
                            "Build: %2\n"
                            "Hardware Acceleration: %3")
                            .arg(GIT_TAG)
                            .arg(commitHash)
                            .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::about(this, "About", aboutText);
}
void MainWindow::on_actionAboutCiphers_triggered()
{
    QString aboutCiphersText = QString(
        "Ciphers Available for Encryption:\n\n"
        "AES-256-GCM (AEAD): strong encryption with built-in authentication - any "
        "tampering is detected. Hardware-accelerated (AES-NI) on most CPUs. A top choice.\n\n"
        "ChaCha20-Poly1305 (AEAD): also authenticated, resistant to timing attacks, and "
        "fast in software - the best pick on devices without AES-NI (e.g. older phones).\n\n"
        "Cipher cascades (e.g. AES-256-GCM + ChaCha20-Poly1305): encrypt through several "
        "AEAD ciphers in sequence, each with an independent key. The file is only broken "
        "if EVERY cipher in the chain is broken - for your highest-value data. Chosen from "
        "the algorithm list like any other option.\n\n"
        "AES-256-CTR / AES-256-CBC: classic modes with NO built-in authentication. "
        "OpenCryptUI adds an Ed25519 tamper-evidence signature, but the AEAD ciphers above "
        "are preferred because authentication is intrinsic.\n\n"
        "(Camellia was removed - it is not on the CNSA 2.0 list and offers no AEAD.)\n\n"
        "Recommendation: AES-256-GCM or ChaCha20-Poly1305 for everyday use; a cascade "
        "when you want defence against a future break of a single cipher.");

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
        "- Argon2: time-cost (t) of 3 or more, with high memory-cost. Argon2 is memory-hard; the iteration count interacts with memory and parallelism settings.\n"
        "- Scrypt: N = 2^20 (1,048,576) or higher. Scrypt is also memory-hard; high N makes it more resistant to GPU/ASIC attacks.\n"
        "- PBKDF2: 600,000 or more iterations (OWASP 2023). PBKDF2 has no memory-hardness, so it relies entirely on high iteration counts.\n\n"
        "Note: the Iterations field maps to each KDF's work-factor parameter, and the "
        "spinbox minimum is pinned to that KDF's enforced floor - Argon2 = 3 (its strength "
        "comes from ~1 GiB of memory, not pass count), Scrypt ~ 2,097,152 opslimit (~100 ms), "
        "PBKDF2 = 600,000. The engine REFUSES anything below the floor rather than silently "
        "raising it, so what you set is what is used.\n\n"
        "For sensitive data, raising the count above the floor only helps if you can afford "
        "the extra unlock time.");

    QMessageBox::information(this, "About Iterations", aboutIterationsText);
}

void MainWindow::on_actionSecurityGuide_triggered()
{
    QString securityGuideText = QString(
        "Security Best Practices Guide\n\n"
        "Secure Password Creation:\n"
        "- Use a MINIMUM of 12 characters, preferably 16+ for highly sensitive data\n"
        "- Include uppercase letters, lowercase letters, numbers, and special characters\n"
        "- Avoid dictionary words, names, dates, or predictable patterns\n"
        "- Consider using a passphrase (multiple words with special characters)\n"
        "- Never reuse passwords from other services or applications\n\n"
        
        "File Security:\n"
        "- Store encrypted files in locations only you have access to\n"
        "- Never store encrypted files in shared directories or cloud services that don't use E2E encryption\n"
        "- Keep keyfiles on separate physical devices (USB drive) from encrypted files\n"
        "- Consider using both a password AND keyfile for critical data\n"
        "- NEVER share passwords through email, messaging, or unencrypted channels\n\n"
        
        "Encryption Settings:\n"
        "- Default to AES-256-GCM or ChaCha20-Poly1305 (authenticated encryption)\n"
        "- Argon2id is the default KDF (memory-hard, ~1 GiB) - keep it unless you\n"
        "  have a specific reason; the work-factor floors are enforced for you\n"
        "- For top-tier data, use a cipher cascade (broken only if every layer is)\n"
        "- Tamper evidence (Ed25519 + per-chunk AEAD) is always on\n\n"

        "Deniability & key splitting:\n"
        "- Use an encrypted container with a HIDDEN volume: one password opens a\n"
        "  decoy, another opens the real data, and the hidden one cannot be proven\n"
        "  to exist. Fill the decoy with believable data.\n"
        "- Split a password into k-of-n key SHARES so no single seized share - or\n"
        "  coerced person - can unlock anything (tolerates losing up to n-k).\n\n"
        
        "Safe Computing Practices:\n"
        "- Keep your device secure and updated with latest security patches\n"
        "- Use a secure, up-to-date operating system\n"
        "- Be aware of physical surroundings when entering passwords\n"
        "- Scan files for malware before encryption/decryption\n"
        "- Close the application when not in use\n\n"
        
        "Emergency Preparation:\n"
        "- Keep secure offline backups of critical encryption keys\n"
        "- Document recovery procedures and store securely\n"
        "- Test recovery process periodically to ensure it works\n"
        "- Consider secure key escrow for organizational use\n\n"
        
        "Remember: The security of your data is only as strong as your weakest practice!"
    );

    QMessageBox::information(this, "Security Guide", securityGuideText);
}
