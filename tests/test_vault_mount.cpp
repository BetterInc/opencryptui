// Integration test for VaultMounter: create a mountable vault, mount it,
// round-trip data through the decrypting layer, confirm no plaintext leaks to
// the backing file, unmount, and reject a wrong password. Drives the real
// opencryptui-mount FUSE driver via VaultMounter.
//
// Returns 77 (ctest SKIP) when FUSE is unavailable in the environment, so it
// never falsely fails in a sandbox.
#include "vault_mount.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <cstdio>

static int s_failures = 0;
static void check(bool ok, const char* label)
{
    std::fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", label);
    std::fflush(stderr);
    if (!ok) s_failures++;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    VaultMounter m;

    QString why;
    if (!m.available(&why)) {
        std::fprintf(stderr, "SKIP: %s\n", qPrintable(why));
        return 77;
    }

    QTemporaryDir work;
    if (!work.isValid()) { std::fprintf(stderr, "FAIL: no temp dir\n"); return 1; }
    const QString vault = work.path() + "/vault.ocui";
    const QString pw = "correct horse battery staple";
    QString err;

    // iter 3 keeps Argon2 fast (its floor); 16 MiB is comfortable for ext4.
    bool ok = m.createMountable(vault, 16, pw, "Argon2", 3, &err);
    check(ok, ok ? "created mountable vault" : qPrintable("create failed: " + err));
    if (!ok) return s_failures;
    check(QFileInfo(vault).size() > 0, "vault backing file is non-empty");

    QString openPath; bool usedFallback = false;
    ok = m.mount(vault, pw, "Argon2", 3, &openPath, &usedFallback, &err);
    check(ok, ok ? "mounted vault" : qPrintable("mount failed: " + err));
    if (ok) {
        check(m.active().size() == 1, "one active mount tracked");

        // Without root the loop mount can't run, so we get the decrypting FUSE
        // image - exactly what proves on-the-fly encryption.
        if (usedFallback) {
            const QString image = openPath + "/disk.img";
            const QByteArray secret = "VAULTMOUNT-ROUNDTRIP-PROOF-0123456789";
            const qint64 at = 1 << 20; // 1 MiB in, clear of the FS superblock

            QFile w(image);
            const bool wrote = w.open(QIODevice::ReadWrite) && w.seek(at)
                               && w.write(secret) == secret.size();
            w.flush(); w.close();
            check(wrote, "wrote plaintext through the mount");

            QFile raw(vault);
            QByteArray backing;
            if (raw.open(QIODevice::ReadOnly)) { backing = raw.readAll(); raw.close(); }
            check(!backing.contains(secret), "no plaintext in backing file (on-the-fly encryption)");

            QFile r(image);
            QByteArray got;
            if (r.open(QIODevice::ReadOnly) && r.seek(at)) got = r.read(secret.size());
            r.close();
            check(got == secret, "read back through the mount matches");
        } else {
            std::fprintf(stderr, "INFO: got a real drive (running as root); skipping raw-image checks\n");
        }

        ok = m.unmount(0, &err);
        check(ok, ok ? "unmounted cleanly" : qPrintable("unmount failed: " + err));
        check(m.active().size() == 0, "no active mounts after unmount");
    }

    QString op2; bool fb2 = false; QString e2;
    const bool bad = m.mount(vault, "definitely not the password", "Argon2", 3, &op2, &fb2, &e2);
    check(!bad, "wrong password rejected (no mount)");
    if (bad) m.unmount(0, &err);

    std::fprintf(stderr, s_failures ? "SOME VAULTMOUNT TESTS FAILED\n" : "ALL VAULTMOUNT TESTS PASSED\n");
    return s_failures;
}
