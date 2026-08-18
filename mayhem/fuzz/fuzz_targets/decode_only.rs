#![no_main]

// PURE-DECODE fuzz target (additive; NOT part of upstream's fuzz/ crate).
//
// Upstream's own fuzz_targets (roundtrip_basic.rs, roundtrip_seek.rs) compress the fuzzer's
// bytes with the encoder and then decompress the freshly-produced archive: the decoder only ever
// sees output the encoder JUST wrote, so a malformed seek-table footer / frame index is never
// exercised. This target instead feeds the raw fuzzer bytes straight into the seekable
// **decoder**, so it is the harness that actually stresses seek-table parsing
// (`SeekTable::from_seekable` in lib/src/seek_table.rs) and the frame walker in
// lib/src/decode.rs against arbitrary, likely-malformed containers.
use libfuzzer_sys::fuzz_target;
use std::io::Read;
use zeekstd::{BytesWrapper, Decoder};

fuzz_target!(|data: &[u8]| {
    let wrapper = BytesWrapper::new(data);
    // Parses the seek-table footer/frame index directly from `data` -- the juicy attack surface
    // (malformed footer, corrupted frame index, bogus frame counts/sizes).
    let Ok(mut decoder) = Decoder::new(wrapper) else {
        return;
    };

    // Drive the frame walker: decompress whatever the (possibly malformed) seek table claims.
    let mut out = Vec::new();
    let _ = decoder.read_to_end(&mut out);
});
