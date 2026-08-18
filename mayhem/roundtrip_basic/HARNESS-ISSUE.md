# HARNESS-ISSUE: roundtrip_basic — STARVED (target disabled by QA)

## Defect

`fuzz/fuzz_targets/roundtrip_basic.rs` (upstream's own, unmodified cargo-fuzz
target) is a pure encode-then-decode round trip with **no mutation of the
intermediate compressed bytes**:

```rust
fuzz_target!(|data: &[u8]| {
    let mut compressed: Vec<u8> = Vec::new();
    {
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(zeekstd::FrameSizePolicy::Uncompressed(100))
            .into_encoder(&mut compressed)
            .unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }

    let mut decoder = Decoder::new(BytesWrapper::new(&compressed)).unwrap();
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    assert_eq!(data, &decompressed);
});
```

The fuzzer only ever controls the *plaintext* `data`; the bytes handed to
`Decoder` are always exactly what `zeekstd`'s own encoder just produced —
well-formed by construction. The decoder's seek-table/frame-index parser
(the actual "juicy" attack surface for a seekable-archive format) never sees
a single malformed byte.

## Evidence

- 120s local libFuzzer session (seed: `mayhem/roundtrip_basic/testsuite/sample_text`):
  coverage plateaus at `cov: 390` by execution #1293 and stays flat (only
  `ft:`/feature count creeps 712→895) through the full 115,252 executions
  (952 exec/s). No crashes, no timeouts, no OOMs.
- Trivial inputs (empty, 1-byte `A`, 16 random bytes) run cleanly — not an
  always-crasher, just structurally unable to reach adversarial decoder
  input.
- Compare: the additive `decode_only` target (feeds raw fuzzer bytes
  straight to `Decoder::new`) found two real upstream bugs in the same QA
  pass within the seek-table parser this target never touches — an
  unbounded-allocation OOM (`seek_table.rs` `Entries::with_num_frames`) and
  an infinite-loop hang (`decode.rs` `decompress_with_prefix`).

## Attribution

Not a bug — the harness is upstream's own, used exactly per its documented
API. It is simply the wrong fuzzing mission for the "malformed decoder
input" attack surface this repo's Mayhem integration targets; that mission
is already covered by `decode_only`.

## What a fix would look like

If this target is ever re-enabled, it would need to inject adversarial
mutation into `compressed` between encode and decode (e.g. bit-flip a
random byte, truncate, or splice two encoded streams) before calling
`Decoder::new`, so the decoder actually sees malformed input. As shipped,
it is redundant with `decode_only` and was disabled via
`mayhem/Mayhemfile_roundtrip_basic` removal (see
`dismissals: dropped-target:roundtrip-basic` in `repos/zeekstd.yaml`).
