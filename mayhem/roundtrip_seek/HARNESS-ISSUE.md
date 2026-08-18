# HARNESS-ISSUE: roundtrip_seek — STARVED (target disabled by QA)

## Defect

`fuzz/fuzz_targets/roundtrip_seek.rs` (upstream's own, unmodified cargo-fuzz
target) parses two little-endian `u32` offsets from the fuzzer bytes, then
compresses the *remaining* bytes and immediately seeks+decompresses that
same, un-mutated archive:

```rust
fuzz_target!(|data: &[u8]| {
    let (offset0, data) = /* first 4 bytes -> offset0 */;
    let (offset1, data) = /* next 4 bytes -> offset1 */;
    if data.is_empty() { return; }

    let mut compressed: Vec<u8> = Vec::new();
    { /* encode `data` into `compressed`, unmutated */ }

    for offset in [offset0, offset1] {
        let offset = offset % data.len();
        let mut decoder = Decoder::new(BytesWrapper::new(&compressed)).unwrap();
        decoder.set_offset(offset as u64).unwrap();
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(&data[offset..], &decompressed);
    }
});
```

Only the *seek offsets* are fuzzer-influenced (and they are clamped
`% data.len()`, so they are always in-range); the container bytes
(`compressed`) are never corrupted. The decoder's seek-table/frame-index
parser never sees anything but a well-formed archive its own encoder just
wrote.

## Evidence

- 120s local libFuzzer session (seed: `mayhem/roundtrip_seek/testsuite/sample_offsets`):
  coverage plateaus at `cov: 418 / ft: 842` (reached early, e.g. by
  execution #74592 of 123,523 total, ~1020 exec/s) with no further growth
  for the rest of the run. No crashes, no timeouts, no OOMs.
- Trivial inputs (empty, 1-byte `A`, 16 random bytes) run cleanly — not an
  always-crasher.
- Compare: the additive `decode_only` target found two real upstream bugs
  in the same QA pass in exactly the seek-table/frame-index parsing surface
  this target's clamped, always-valid offsets never stress: an
  unbounded-allocation OOM (`seek_table.rs` `Entries::with_num_frames`) and
  an infinite-loop hang (`decode.rs` `decompress_with_prefix`).

## Attribution

Not a bug — harness used exactly per its documented API. Wrong fuzzing
mission for "malformed decoder input"; that mission is already covered by
`decode_only`.

## What a fix would look like

To be worth re-enabling, this target would need to mutate `compressed`
(or the seek-table footer specifically) between encode and decode/seek, or
drop the `% data.len()` clamp so out-of-range offsets can reach
`Decoder::set_offset` with a still-unmutated-but-differently-shaped archive.
As shipped, it is redundant with `decode_only` and was disabled via
`mayhem/Mayhemfile_roundtrip_seek` removal (see
`dismissals: dropped-target:roundtrip-seek` in `repos/zeekstd.yaml`).
