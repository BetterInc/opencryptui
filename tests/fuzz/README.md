# OpenCryptUI libFuzzer Harnesses

Three libFuzzer harnesses targeting the highest-risk parsing surfaces in the
encryption engine.  They are **development tools only** — production releases
are built without `OCUI_ENABLE_FUZZ`.

---

## What each harness covers

| Binary | Source | APIs driven | Primary attack surface |
|--------|--------|-------------|------------------------|
| `FuzzOCUIHeader` | `fuzz_ocui_header.cpp` | `EncryptionEngine::decryptFile` → `cryptOperation` (decrypt branch) | OCUI magic, format-version, algorithm-id, KDF-id, iteration-floor, salt/IV read for both v2 and v3 |
| `FuzzChunkDecoder` | `fuzz_chunk_decoder.cpp` | `decryptFile` → `cryptOperationV3Decrypt` → `decryptChunk` | v3 chunk-framing (chunk_size, chunk_count), per-chunk GCM tag verification, `buildChunkNonce`, EVP_Decrypt* |
| `FuzzSignatureVerifier` | `fuzz_signature_verifier.cpp` | `decryptFile` → `verifySignature` | Trailer magic/sigLen/CRC parse, Ed25519 public-key derivation, constant-time pubkey comparison, SHA-512 hash-then-verify |

---

## Build locally

Requires **Clang** (the `-fsanitize=fuzzer` driver is Clang-only).

```sh
cmake -S . -B build-fuzz -G Ninja \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DOCUI_ENABLE_FUZZ=ON

cmake --build build-fuzz -j$(nproc)
```

The three fuzzer binaries land in `build-fuzz/`.

> Note: GCC does not support `-fsanitize=fuzzer` (only `-fsanitize=fuzzer-no-link`).
> CMake will emit a `FATAL_ERROR` if `OCUI_ENABLE_FUZZ=ON` is set with a
> non-Clang compiler.

---

## Generate seed corpora (one-time)

```sh
cd <project-root>
chmod +x tests/fuzz/generate_corpus.sh
./tests/fuzz/generate_corpus.sh build-fuzz
```

This writes static seed files to `tests/fuzz/corpus/*/`.  The seeds are
committed to the repository; you only need to regenerate them if you change the
file format.

---

## Run with a corpus

```sh
cd build-fuzz

# OCUI header parser
./FuzzOCUIHeader ../tests/fuzz/corpus/ocui_header/

# v3 chunk decoder
./FuzzChunkDecoder ../tests/fuzz/corpus/chunk_decoder/

# Signature verifier
./FuzzSignatureVerifier ../tests/fuzz/corpus/signature_verifier/
```

Each fuzzer runs until it finds a crash or you interrupt it with `Ctrl-C`.

### Bounded smoke run (60 s per fuzzer)

```sh
cmake --build build-fuzz --target fuzz
```

The `fuzz` target passes `-max_total_time=60` to each fuzzer in sequence and
exits non-zero if any fuzzer produces a `crash-*` artifact.

---

## Interpret a crash

When a crash is found, libFuzzer writes a file named `crash-<sha1>` (or
`crash-header-<sha1>`, etc., depending on the `-artifact_prefix` set in the
`fuzz` target).

1. **Reproduce the crash:**

   ```sh
   ./FuzzOCUIHeader crash-abc123
   # or
   ./FuzzChunkDecoder crash-abc123
   # or
   ./FuzzSignatureVerifier crash-abc123
   ```

2. **Symbolise the stack trace** (ASan prints the trace on crash):

   ```sh
   # Build with debug symbols (already done with -g -O1).
   # The trace contains offsets; resolve them:
   addr2line -e ./FuzzOCUIHeader -f -C 0x<hex-offset>
   # or use llvm-symbolizer (preferred):
   ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer) ./FuzzOCUIHeader crash-abc123
   ```

3. **Minimise the reproducer** (helps with root-cause analysis):

   ```sh
   ./FuzzOCUIHeader -minimize_crash=1 -runs=10000 crash-abc123
   # Produces minimized-from-crash-abc123
   ```

---

## Merge and minimise corpus after a run

After a long fuzzing session the working corpus directory may grow large.
Merge it back into the seed corpus to keep only coverage-unique inputs:

```sh
./FuzzOCUIHeader -merge=1 \
    ../tests/fuzz/corpus/ocui_header/ \
    /tmp/fuzz-run-ocui/
```

---

## CI integration

The optional `fuzz-smoke` CI job (`.github/workflows/build-and-release.yml`)
runs each fuzzer for 60 s when triggered manually with `run_fuzz: true`:

```sh
# Via the GitHub UI: Actions → fuzz-smoke → Run workflow → run_fuzz=true
```

The job fails if any fuzzer exits with a non-zero code or produces a
`crash-*` artifact.  It does **not** run on every push.

---

## Known limitations

1. **KDF cost inside the fuzzer.** `FuzzChunkDecoder` and `FuzzSignatureVerifier`
   use a fixed all-zero salt and the PBKDF2 iteration floor (600 000), which
   means every fuzz iteration that reaches the key-derivation step spends ~
   10 ms on PBKDF2.  This caps throughput at roughly 100 iterations/s on a
   modern core for inputs that pass the header validation.  Inputs rejected at
   the OCUI magic or algorithm-id checks are much faster (< 1 µs).  A future
   optimisation would expose an internal test-only constructor that accepts a
   pre-derived key, bypassing KDF entirely.

2. **No in-process `decryptChunk` access.** Because `decryptChunk` is a
   `private static` method, `FuzzChunkDecoder` cannot call it directly.  It
   drives the full `decryptFile` → `cryptOperationV3Decrypt` → `decryptChunk`
   stack instead, which is actually broader coverage but slower than a direct
   harness would be.

3. **Seed corpus is static.** The seeds were generated by hand and capture
   only a handful of structural shapes.  Running `FuzzOCUIHeader` for an hour
   and then merging back with `-merge=1` will produce a much richer corpus.

---

## Security note

This infrastructure is a **development-time tool**.  Never ship a binary built
with `-fsanitize=fuzzer,address,undefined` — it is significantly larger and
slower than a release build and the fuzzer runtime exposes internal state.
