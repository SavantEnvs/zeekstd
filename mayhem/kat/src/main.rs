//! zeekstd-mayhem-kat — the known-answer probe used by mayhem/test.sh.
//!
//! Why this exists (SPEC §6.3 / the anti-reward-hacking oracle): `cargo test` links a
//! DYNAMICALLY-linked binary same as any other Rust binary on this target triple, but the spec
//! forbids relying on `cargo test` alone anyway, because it only proves the crate's own (easily
//! stubbed) assertions pass -- it says nothing about a targeted, independently-verifiable KAT.
//! This probe:
//!   1. Compresses a FIXED, hardcoded input with a fixed frame-size policy (so the seek table
//!      shape -- frame count, decompressed size -- is fully deterministic).
//!   2. Decompresses it back through the real `Decoder` / seek-table path and asserts the
//!      output is byte-for-byte identical to the input (panics otherwise).
//!   3. Prints `KAT_<NAME>=<value>` lines for: an FNV-1a digest of the roundtripped bytes, the
//!      frame count read from the seek table, and the decompressed size read from the footer.
//!
//! `mayhem/test.sh` greps for the EXACT expected lines (`grep -qxF`), so a neutered/no-op binary
//! (the verify-repo LD_PRELOAD sabotage shim `_exit(0)`s it before any of this runs) prints
//! nothing and the oracle fails -- this is not reachable by a `cargo test`-only oracle because
//! that test binary can't be told apart from any other Rust binary by the shim, but a stubbed
//! *function* inside the library would still make this probe's assertions fail loudly.
use std::io::{Read, Write};

use zeekstd::{BytesWrapper, Decoder, EncodeOptions, FrameSizePolicy};

/// Fixed, deterministic KAT input. No embedded newlines, so it never breaks the `grep -qxF`
/// single-line matching in test.sh if ever printed directly.
const UNIT: &[u8] =
    b"ZEEKSTD-KAT-PROBE:The quick brown fox jumps over the lazy dog 0123456789 END;";
const REPEAT: usize = 6;
/// Frame size (uncompressed policy) -- small relative to the input so the seek table ends up
/// with multiple, deterministically-countable frames.
const FRAME_SIZE: u32 = 90;

/// FNV-1a 64-bit, hand-rolled (no extra dependency) -- deterministic digest of the roundtripped
/// bytes.
fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn main() {
    let mut fixed_input = Vec::with_capacity(UNIT.len() * REPEAT);
    for _ in 0..REPEAT {
        fixed_input.extend_from_slice(UNIT);
    }

    // ── Compress the fixed input with a fixed, deterministic frame-size policy ──────────────
    let mut compressed: Vec<u8> = Vec::new();
    {
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(FrameSizePolicy::Uncompressed(FRAME_SIZE))
            .into_encoder(&mut compressed)
            .expect("KAT: failed to create encoder");
        encoder
            .write_all(&fixed_input)
            .expect("KAT: failed to compress fixed input");
        encoder.finish().expect("KAT: failed to finish encoder");
    }

    // ── Decompress through the real seekable Decoder / seek-table path ─────────────────────
    let mut decoder =
        Decoder::new(BytesWrapper::new(&compressed)).expect("KAT: failed to create decoder");
    let num_frames = decoder.seek_table().num_frames();
    let size_decomp = decoder.seek_table().size_decomp();

    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("KAT: failed to decompress");

    // ── Assert EXACT values (panics -- nonzero exit -- on any mismatch) ────────────────────
    assert_eq!(
        decompressed, fixed_input,
        "KAT: roundtripped bytes do not match the fixed input"
    );
    assert_eq!(
        size_decomp,
        fixed_input.len() as u64,
        "KAT: seek-table decompressed size does not match the fixed input length"
    );

    let digest = fnv1a64(&decompressed);

    println!("KAT_ROUNDTRIP_FNV1A64={digest:016x}");
    println!("KAT_SEEK_TABLE_NUM_FRAMES={num_frames}");
    println!("KAT_SEEK_TABLE_SIZE_DECOMP={size_decomp}");
}
