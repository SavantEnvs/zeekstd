#!/usr/bin/env bash
#
# zeekstd/mayhem/build.sh — build three sanitized libFuzzer targets plus the project's own test
# suite and the KAT probe used by mayhem/test.sh.
#
# Targets produced (one Mayhemfile each):
#   /mayhem/roundtrip_basic  — upstream's fuzz/fuzz_targets/roundtrip_basic.rs (unmodified;
#                              compresses arbitrary bytes then asserts the roundtrip)
#   /mayhem/roundtrip_seek   — upstream's fuzz/fuzz_targets/roundtrip_seek.rs  (unmodified;
#                              roundtrip + arbitrary-offset seek)
#   /mayhem/decode_only      — mayhem/fuzz/fuzz_targets/decode_only.rs (ADDITIVE): feeds the raw
#                              fuzzer bytes straight into the seekable Decoder, so it is the one
#                              target that actually stresses the seek-table footer / frame-index
#                              parser against a malformed container (the round-trip targets only
#                              ever decode data their OWN encoder just produced).
#   /mayhem/kat              — dynamically-linked known-answer probe used by mayhem/test.sh
#
# Two separate cargo-fuzz crate roots are involved:
#   - fuzz/          is upstream's own cargo-fuzz crate (already a member of the repo's root
#                    workspace; never edited).
#   - mayhem/fuzz/   is our ADDITIVE cargo-fuzz crate (its own, separate cargo workspace — see
#                    the comment in mayhem/fuzz/Cargo.toml for why) holding only decode_only.rs.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs this script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME, INCLUDING
#     zstd-sys's vendored libzstd C sources (it's an ordinary crate download, cached like any
#     other dependency — no separate vendoring step needed).
#   - The PATCH re-run resolves crates from that cache. The rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run, so we do NOT hard-code `--offline` here (that would
#     break this first, online build).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# DWARF<4 gate workaround (SPEC §6.2 item 10; see mayhem/Dockerfile header for the full
# rationale): -Z dwarf-version=3 covers rustc's own CUs; -Clinker=<cc-wrapper> prepends a
# hand-built DWARF3 anchor.o as the FIRST object in every link so it becomes the first CU
# verify-repo's `-m1` check reads, even though the precompiled ASan runtime stays DWARF5 deeper
# in the binary.
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -Z dwarf-version=3 -Clinker=/opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh}"
export RUST_DEBUG_FLAGS

# OSS-Fuzz Rust libFuzzer+ASan flags. cargo-fuzz sets the ASan flag itself, but we pin it
# explicitly. --cfg fuzzing matches libfuzzer-sys; force-frame-pointers aids ASan backtraces.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing $RUST_DEBUG_FLAGS -Zsanitizer=address -Cforce-frame-pointers"

TRIPLE="x86_64-unknown-linux-gnu"

# Rust instrumentation goes through RUSTFLAGS -Zsanitizer=address (rustc ignores the clang-style
# $SANITIZER_FLAGS/$CFLAGS the C/C++ path uses). $SANITIZER_FLAGS still flows through as a build
# ARG (see mayhem/Dockerfile) for parity with the org contract and any cc-invoked deps; cargo-fuzz
# itself just doesn't consume it directly the way `clang $SANITIZER_FLAGS` would.
: "${SANITIZER_FLAGS:=}"

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"

# build_fuzz_target <fuzz-dir> <bin-target-dir> <target-name>
#
# `<bin-target-dir>` is where cargo-fuzz actually writes the release binary. This depends on
# whether `<fuzz-dir>` is a member of the REPO ROOT workspace or its own, separate workspace:
#   - "fuzz" is a declared member of the root Cargo.toml's `members = [...]` (upstream, unedited)
#     workspace, so cargo-fuzz resolves the workspace root at $SRC and writes into $SRC/target/.
#   - "mayhem/fuzz" is deliberately its OWN workspace (see mayhem/fuzz/Cargo.toml), so cargo-fuzz
#     writes into $SRC/mayhem/fuzz/target/ instead.
# (Verified empirically both locally and matches the same pattern documented in the askama
# integration's build.sh for an analogous root-workspace fuzz/ crate.)
build_fuzz_target() {
  local fuzz_dir="$1" bin_target_dir="$2" target="$3"
  echo "--- building fuzz target: $target (--fuzz-dir $fuzz_dir) ---"
  # Use the image's DEFAULT toolchain (the Dockerfile pinned it). A `+toolchain` override would
  # make rustup try to install another channel into the locked /opt/toolchains/rust.
  cargo fuzz build --fuzz-dir "$fuzz_dir" -O --debug-assertions "$target"
  local bin="$SRC/$bin_target_dir/target/$TRIPLE/release/$target"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$target"
  echo "built /mayhem/$target"
}

# Upstream's own two round-trip targets, from upstream's own (unmodified) fuzz/ crate — "fuzz" is
# a root-workspace member, so the binary lands in the ROOT target dir (bin-target-dir = ".").
build_fuzz_target "fuzz" "." "roundtrip_basic"
build_fuzz_target "fuzz" "." "roundtrip_seek"

# Our additive pure-decode target, from the separate mayhem/fuzz/ crate — its own workspace, so
# the binary lands under mayhem/fuzz/target/ (bin-target-dir = "mayhem/fuzz").
build_fuzz_target "mayhem/fuzz" "mayhem/fuzz" "decode_only"

# ── The KAT probe used by mayhem/test.sh (NORMAL flags — it is a functional oracle, not a
#    triage artifact, so no sanitizer/fuzz instrumentation here). ──────────────────────────────
echo "=== building /mayhem/kat (KAT probe, normal flags) ==="
(
  unset RUSTFLAGS
  cd "$SRC/mayhem/kat"
  cargo build --release
)
cp "$SRC/mayhem/kat/target/release/kat" /mayhem/kat
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/kat is not dynamically linked — the sabotage check could not" >&2
  echo "       neuter it, which would make mayhem/test.sh a reward-hackable oracle." >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "built /mayhem/kat (dynamically linked)"

# ── The project's own test suite (NORMAL flags, no RUSTFLAGS/sanitizer) — build only, so
#    mayhem/test.sh just RUNS it. Skip the fuzz crates (fuzz/, mayhem/fuzz/): they carry no
#    #[test]s and fuzz/ needs the nightly -Z flags this normal build deliberately avoids. ────────
echo "=== building the project's own test suite (normal flags) ==="
(
  unset RUSTFLAGS
  cargo test --no-run --workspace --exclude zeekstd-fuzz
)

echo "build.sh complete:"
ls -la /mayhem/roundtrip_basic /mayhem/roundtrip_seek /mayhem/decode_only /mayhem/kat
