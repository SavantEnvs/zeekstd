#!/usr/bin/env bash
#
# zeekstd/mayhem/test.sh — RUN the project's own cargo test suite AND a known-answer probe, and
# emit a CTRF summary. exit 0 iff nothing failed.
#
# PATCH-grade oracle (SPEC §6.3). Two parts, and the SECOND is the load-bearing one:
#
#  1) `cargo test --workspace --exclude zeekstd-fuzz` — the crate's own genuine known-answer
#     suite: lib/src/{decode,encode,seek_table}.rs unit tests + proptest property tests assert
#     exact roundtrip/seek-table equality, and cli/tests/integration exercises the real CLI
#     binary end-to-end. So it asserts BEHAVIOUR, not "exits 0".
#
#  2) The KAT probe /mayhem/kat — SPEC §6.3 forbids relying on `cargo test` ALONE as the oracle:
#     its test binaries are ordinary Rust binaries on this target (dynamically linked against
#     glibc, same as any other), so in principle the sabotage shim CAN neuter them -- but we do
#     not rely on that alone, because `cargo test`'s own harness re-links/re-discovers tests in a
#     way that isn't a stable, independently-verifiable target for the shim across toolchain
#     versions. /mayhem/kat is a small, purpose-built, dynamically-linked probe (build.sh asserts
#     `file` reports "dynamically linked", failing the build otherwise) that compresses a FIXED
#     input with a FIXED frame-size policy and decompresses it back through the real seek-table
#     path, panicking on any mismatch and printing exact `KAT_<NAME>=<value>` lines. A neutered
#     binary (verify-repo's LD_PRELOAD shim `_exit(0)`s it before any of this runs) prints
#     nothing, so every `grep -qxF` below fails -- and a patch that stubs a parsing function
#     without literally no-op'ing the whole binary still fails the assert_eq!/panic inside.
#
# This script only RUNS things; mayhem/build.sh did the building.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export RUSTUP_HOME="${RUSTUP_HOME:-/opt/toolchains/rust/rustup}"
export CARGO_HOME="${CARGO_HOME:-/opt/toolchains/rust/cargo}"
export PATH="$CARGO_HOME/bin:$PATH"
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) the project's own cargo test suite (lib unit tests + proptests + cli integration tests +
#       doctests) ───────────────────────────────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test+kat" 0 1 0; exit 2
fi

echo "=== running: cargo test --workspace --exclude zeekstd-fuzz ==="
OUT="$SRC/mayhem-build-test.log"
mkdir -p "$(dirname "$OUT")"
cargo test --workspace --exclude zeekstd-fuzz --no-fail-fast > "$OUT" 2>&1; rc=$?
tail -60 "$OUT" || true

# Every `test result: ok/FAILED. P passed; F failed; I ignored; ...` line (one per test binary +
# one for the merged doctests) reports real counts; sum them.
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); SKIPPED=$(( SKIPPED + i ))
done < <(grep -E '^test result:' "$OUT" | sed -E 's/^test result: [a-zA-Z]+\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;.*/\1 \2 \3/')

if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "FAIL: no 'test result:' lines parsed — the suite did not run (cargo exit $rc)" >&2
  emit_ctrf "cargo-test+kat" 0 1 0; exit 1
fi
# A non-zero cargo exit with zero counted failures means a build/harness error: stay honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=$(( FAILED + 1 )); fi

# ── 2) the KAT probe (sabotage-detecting; see header) ────────────────────────────────────────
# UNCONDITIONAL by design: a missing binary is a FAILURE, never a skip. A `[ -x ... ]` guard here
# is how a probe silently stops running and the oracle quietly degrades.
echo "=== KAT probe: /mayhem/kat (dynamically linked; asserts parsed VALUES) ==="
KAT_OUT="$(/mayhem/kat 2>&1)"; kat_rc=$?
echo "$KAT_OUT"

# Expected values, computed once (offline, by hand) from the probe's fixed input + fixed
# FrameSizePolicy::Uncompressed(90) — see mayhem/kat/src/main.rs:
#   fixed input = 6 repeats of a 77-byte ASCII unit => 462 bytes decompressed
#   frame size 90 (uncompressed) => 6 frames (5 full 90-byte frames + one 12-byte remainder)
#   FNV-1a 64 digest of the roundtripped (== original) bytes = 3e74cdec63def19d
kat_expect() {
  local label="$1" line="$2"
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$line"; then
    echo "KAT PASS: $label"
    PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: $label — expected exact line: $line" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

if [ "$kat_rc" -ne 0 ]; then
  echo "KAT FAIL: /mayhem/kat exited $kat_rc (neutered, missing, or parser broken)" >&2
  FAILED=$(( FAILED + 1 ))
fi
kat_expect "roundtrip digest (FNV-1a64 of decompressed bytes)" 'KAT_ROUNDTRIP_FNV1A64=3e74cdec63def19d'
kat_expect "seek table frame count"                            'KAT_SEEK_TABLE_NUM_FRAMES=6'
kat_expect "seek table decompressed size (from the footer)"    'KAT_SEEK_TABLE_SIZE_DECOMP=462'

emit_ctrf "cargo-test+kat" "$PASSED" "$FAILED" "$SKIPPED"
