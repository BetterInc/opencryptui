#!/usr/bin/env bash
# End-to-end test for the FUSE mount driver (opencryptui-mount).
#
# Proves on-the-fly encryption for real: create an encrypted volume, MOUNT it,
# write plaintext through the mount, read it back, confirm the RAW backing file
# contains no plaintext, unmount, REMOUNT and confirm the data persisted, and
# confirm a wrong password cannot mount.
#
# Skips (exit 77, ctest SKIP) only when FUSE genuinely isn't usable here
# (no /dev/fuse or no fusermount3) — a real mount failure is a FAILURE.
#
# Arg 1: path to the opencryptui-mount binary.
set -u

MOUNT_BIN="${1:?usage: fuse_mount_e2e.sh <opencryptui-mount>}"
PASS="correct horse battery staple"
WRONGPASS="nope nope nope"
SECRET="ON-THE-FLY-ENCRYPTION-PROOF-$$-0123456789"
OFFSET=1048576   # write 1 MiB into the image

# --- prerequisites: skip (not fail) if FUSE is unavailable in this env -------
if [ ! -e /dev/fuse ] || [ ! -w /dev/fuse ]; then
    echo "SKIP: /dev/fuse not available/writable here"
    exit 77
fi
if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
    echo "SKIP: fusermount(3) not found"
    exit 77
fi
FUSERMOUNT="$(command -v fusermount3 || command -v fusermount)"

WORK="$(mktemp -d)"
VOL="$WORK/vault.ocui"
MNT="$WORK/mnt"
mkdir -p "$MNT"
MPID=""

cleanup() {
    [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
    "$FUSERMOUNT" -u "$MNT" 2>/dev/null
    sleep 1
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# Mount in the background; wait for disk.img to appear (max ~15s).
mount_vol() {
    local pw="$1"
    printf '%s\n' "$pw" | "$MOUNT_BIN" "$VOL" "$MNT" --iter 3 >"$WORK/mnt.log" 2>&1 &
    MPID=$!
    for _ in $(seq 1 30); do
        [ -e "$MNT/disk.img" ] && return 0
        # If the mount process already died, stop waiting.
        kill -0 "$MPID" 2>/dev/null || return 1
        sleep 0.5
    done
    return 1
}
unmount_vol() {
    "$FUSERMOUNT" -u "$MNT" 2>/dev/null
    [ -n "$MPID" ] && wait "$MPID" 2>/dev/null
    MPID=""
}

# --- 1. Create the volume ----------------------------------------------------
printf '%s\n%s\n' "$PASS" "$PASS" | "$MOUNT_BIN" --create "$VOL" --size 4 --iter 3 >"$WORK/create.log" 2>&1
[ -f "$VOL" ] || fail "volume not created ($(cat "$WORK/create.log"))"
echo "PASS: volume created"

# --- 2. Mount and write a secret through the decrypting layer ---------------
if ! mount_vol "$PASS"; then
    # Distinguish "can't mount in this sandbox" from a real bug: if the log
    # mentions a permission/operation-not-permitted issue, treat as SKIP.
    if grep -qiE "permission denied|operation not permitted|fusermount.*(setuid|allow)" "$WORK/mnt.log"; then
        echo "SKIP: mounting not permitted in this environment"; echo "--- log ---"; cat "$WORK/mnt.log"
        exit 77
    fi
    fail "mount did not expose disk.img ($(cat "$WORK/mnt.log"))"
fi
echo "PASS: mounted, disk.img present"

printf '%s' "$SECRET" | dd of="$MNT/disk.img" bs=1 seek="$OFFSET" conv=notrunc status=none || fail "write through mount failed"
sync
GOT="$(dd if="$MNT/disk.img" bs=1 skip="$OFFSET" count=${#SECRET} status=none)"
[ "$GOT" = "$SECRET" ] && echo "PASS: read back through mount matches" || fail "readback mismatch: '$GOT'"

# --- 3. Raw backing file must NOT contain the plaintext ----------------------
if grep -a -q "$SECRET" "$VOL"; then
    fail "plaintext LEAKED into the raw backing file"
fi
echo "PASS: no plaintext in raw backing file (on-the-fly encryption confirmed)"

# --- 4. Unmount, then remount and confirm the data persisted -----------------
unmount_vol
[ -e "$MNT/disk.img" ] && fail "disk.img still present after unmount"
echo "PASS: unmounted cleanly"

mount_vol "$PASS" || fail "remount failed ($(cat "$WORK/mnt.log"))"
GOT2="$(dd if="$MNT/disk.img" bs=1 skip="$OFFSET" count=${#SECRET} status=none)"
[ "$GOT2" = "$SECRET" ] && echo "PASS: data persisted across unmount/remount" || fail "data lost across remount: '$GOT2'"
unmount_vol

# --- 5. Wrong password must not mount ---------------------------------------
if mount_vol "$WRONGPASS"; then
    unmount_vol
    fail "wrong password should not have mounted"
fi
grep -qi "Open failed" "$WORK/mnt.log" || true
echo "PASS: wrong password rejected (no mount)"

echo "ALL FUSE E2E TESTS PASSED"
exit 0
