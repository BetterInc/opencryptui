#!/usr/bin/env bash
# generate_corpus.sh — produce seed corpora for the three libFuzzer harnesses.
#
# Run this ONCE after a successful build to populate the corpus directories.
# You do NOT need to re-run it on every build; the seeds are committed to the
# repository and are static.
#
# Usage:
#   cd <project-root>
#   ./tests/fuzz/generate_corpus.sh <build-dir>
#
# The build directory must contain: TestRoundtrip, TestEngineTamper (for the
# "valid file" fixture), and FuzzOCUIHeader / FuzzChunkDecoder (to merge seeds).
# If the fuzz binaries are absent, only static seeds are written.
#
# Prerequisites:
#   - The project must have been built with OCUI_ENABLE_FUZZ=ON (for the merge
#     step) or at minimum with the regular CMake targets.
#   - python3 (used only for the bit-flip helper) — optional.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${1:-${PROJECT_ROOT}/build}"
CORPUS_ROOT="${SCRIPT_DIR}/corpus"

echo "=== OpenCryptUI fuzz corpus generator ==="
echo "Project root : ${PROJECT_ROOT}"
echo "Build dir    : ${BUILD_DIR}"
echo "Corpus root  : ${CORPUS_ROOT}"
echo ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

require_binary() {
    if [ ! -x "${BUILD_DIR}/$1" ]; then
        echo "WARNING: ${BUILD_DIR}/$1 not found — skipping steps that need it."
        return 1
    fi
    return 0
}

flip_bit() {
    # flip_bit <file> <byte-offset>
    # Flips bit 0 of the byte at the given offset.
    local file="$1" offset="$2"
    python3 - "$file" "$offset" <<'PYEOF'
import sys, os
path, off = sys.argv[1], int(sys.argv[2])
with open(path, 'r+b') as f:
    f.seek(off)
    b = ord(f.read(1))
    f.seek(off)
    f.write(bytes([b ^ 0x01]))
PYEOF
}

mkdir -p \
    "${CORPUS_ROOT}/ocui_header" \
    "${CORPUS_ROOT}/chunk_decoder" \
    "${CORPUS_ROOT}/signature_verifier"

TMPDIR_SEED="$(mktemp -d)"
trap "rm -rf ${TMPDIR_SEED}" EXIT

# ---------------------------------------------------------------------------
# 1. seed_v2.bin and seed_v3.bin — produce real encrypted files via
#    TestRoundtrip, then copy them as seeds for fuzz_ocui_header.
# ---------------------------------------------------------------------------
echo "--- Generating OCUI header seeds (v2 / v3) ---"

PLAIN="${TMPDIR_SEED}/plain.txt"
printf 'Hello, fuzz corpus seed!' > "${PLAIN}"

if require_binary "TestRoundtrip"; then
    # v2: AES-256-CBC (non-AEAD → v2 framing)
    cp "${PLAIN}" "${TMPDIR_SEED}/plain_v2.txt"
    "${BUILD_DIR}/TestRoundtrip" AES-256-CBC 2>/dev/null || true
    # TestRoundtrip encrypts ${plain}.txt → ${plain}.txt.enc in its own tempdir,
    # so we use the engine API directly via a small inline script instead.

    # Use the existing engine via the FuzzOCUIHeader binary in -run mode to
    # generate seeds by encrypting known data.
    echo "  (TestRoundtrip creates files in its own tmpdir; using static seeds instead)"
fi

# Static binary seeds: hand-crafted minimal OCUI v2 header bytes.
# These are the minimal 12 header bytes only (no salt/iv/ciphertext).
# The fuzzer will mutate from here.
#
# v2 header: "OCUI" | 0x02 | 0x01(AES-256-GCM) | 0x01(PBKDF2) | 0x00 | 0x000927C0(600000)
printf '\x4F\x43\x55\x49\x02\x01\x01\x00\x00\x09\x27\xC0' \
    > "${CORPUS_ROOT}/ocui_header/seed_v2_header_only.bin"

# v2 header + 32-byte zero salt + 12-byte zero IV (GCM) = 56 bytes total
{
    printf '\x4F\x43\x55\x49\x02\x01\x01\x00\x00\x09\x27\xC0'
    python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 44)"
} > "${CORPUS_ROOT}/ocui_header/seed_v2_with_salt_iv.bin"

# v3 header: "OCUI" | 0x03 | 0x01(AES-256-GCM) | 0x01(PBKDF2) | 0x00 | 0x000927C0
# + 32-byte salt + 12-byte base_iv + chunk_size(4) + chunk_count(4)
{
    printf '\x4F\x43\x55\x49\x03\x01\x01\x00\x00\x09\x27\xC0'
    python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 44)"
    # chunk_size = 1 MiB = 0x00100000, chunk_count = 1
    printf '\x00\x10\x00\x00\x00\x00\x00\x01'
} > "${CORPUS_ROOT}/ocui_header/seed_v3_framing.bin"

# Seed with wrong magic (exercises rejection path)
printf '\xDE\xAD\xBE\xEF\x02\x01\x01\x00\x00\x09\x27\xC0' \
    > "${CORPUS_ROOT}/ocui_header/seed_bad_magic.bin"

echo "  Written: ocui_header seeds"

# ---------------------------------------------------------------------------
# 2. chunk_decoder corpus seeds
# ---------------------------------------------------------------------------
echo "--- Generating chunk decoder seeds ---"

# A valid-shaped chunk: 16 bytes of ciphertext + 16 bytes of GCM tag (all zeros).
# The tag will fail verification (wrong key) but exercises the EVP_Decrypt* path.
python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 32)" \
    > "${CORPUS_ROOT}/chunk_decoder/seed_minimal_chunk_zerotag.bin"

# A chunk that is exactly 16 bytes (tag only, 0 ciphertext bytes).
python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 16)" \
    > "${CORPUS_ROOT}/chunk_decoder/seed_tag_only.bin"

# A chunk that is 15 bytes (one byte shorter than a valid tag — exercises
# the "chunk too short" guard in decryptChunk).
python3 -c "import sys; sys.stdout.buffer.write(b'\xAA' * 15)" \
    > "${CORPUS_ROOT}/chunk_decoder/seed_too_short.bin"

# Minimal v3 file with 1 chunk (control byte 0x00 = no trailer, 1 chunk)
# followed by 32 bytes of payload.
{
    printf '\x00'  # control: trailerMode=0, chunkCount=1
    python3 -c "import sys; sys.stdout.buffer.write(b'\x55' * 32)"
} > "${CORPUS_ROOT}/chunk_decoder/seed_v3_1chunk.bin"

# Minimal v3 file with stub SIG_ trailer (control byte 0x01)
{
    printf '\x01'  # control: trailerMode=1, chunkCount=1
    python3 -c "import sys; sys.stdout.buffer.write(b'\xAA' * 32)"
} > "${CORPUS_ROOT}/chunk_decoder/seed_v3_stub_sig.bin"

echo "  Written: chunk_decoder seeds"

# ---------------------------------------------------------------------------
# 3. signature_verifier corpus seeds
# ---------------------------------------------------------------------------
echo "--- Generating signature verifier seeds ---"

# The fuzz_signature_verifier harness prepends a 60-byte fixed header
# (12-byte OCUI + 32-byte salt + 16-byte IV) and treats the fuzz input as
# the suffix.  Our seeds provide various suffix shapes.

# Suffix = empty: exercises the "no SIG_ magic found" fast path.
printf '' > "${CORPUS_ROOT}/signature_verifier/seed_empty_suffix.bin"

# Suffix = 12 bytes that look like a "SIG_" trailer with sigLen=0, CRC=0.
# Tests the stub-trailer path inside verifySignature.
python3 -c "
import sys, struct
# magic='SIG_'=0x5349475F, sigLen=0, crc32(empty)=0x00000000
trailer = struct.pack('>III', 0x5349475F, 0, 0x00000000)
sys.stdout.buffer.write(trailer)
" > "${CORPUS_ROOT}/signature_verifier/seed_stub_trailer.bin"

# Suffix = 12-byte trailer claiming sigLen=64 but no preceding sig bytes.
python3 -c "
import sys, struct
trailer = struct.pack('>III', 0x5349475F, 64, 0xDEADBEEF)
sys.stdout.buffer.write(trailer)
" > "${CORPUS_ROOT}/signature_verifier/seed_claimed_sig_missing.bin"

# Suffix = 64 zero bytes (fake sig) + valid SIG_ trailer with correct sigLen
# but wrong CRC.
python3 -c "
import sys, struct
fake_sig = b'\x00' * 64
trailer  = struct.pack('>III', 0x5349475F, 64, 0x12345678)
sys.stdout.buffer.write(fake_sig + trailer)
" > "${CORPUS_ROOT}/signature_verifier/seed_wrong_crc.bin"

# Suffix that mimics a plausible Ed25519 signature (64 bytes sig + 32 bytes
# pubkey = 96 bytes) followed by a correct-length SIG_ trailer.
python3 -c "
import sys, struct
sig_body = b'\xAB' * 96  # 64 Ed25519 sig + 32 pubkey
trailer  = struct.pack('>III', 0x5349475F, 96, 0xCAFEBABE)
sys.stdout.buffer.write(sig_body + trailer)
" > "${CORPUS_ROOT}/signature_verifier/seed_plausible_sig.bin"

# Truncated trailer (only 8 bytes — exercises size check).
python3 -c "
import sys, struct
sys.stdout.buffer.write(struct.pack('>II', 0x5349475F, 64))
" > "${CORPUS_ROOT}/signature_verifier/seed_truncated_trailer.bin"

echo "  Written: signature_verifier seeds"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Corpus generation complete ==="
echo ""
echo "Seeds written to: ${CORPUS_ROOT}"
echo ""
echo "To merge and minimise the corpora after a fuzzing run:"
echo "  FuzzOCUIHeader        -merge=1 corpus/ocui_header/ <run-dir>/"
echo "  FuzzChunkDecoder      -merge=1 corpus/chunk_decoder/ <run-dir>/"
echo "  FuzzSignatureVerifier -merge=1 corpus/signature_verifier/ <run-dir>/"
echo ""
echo "See tests/fuzz/README.md for the full workflow."
