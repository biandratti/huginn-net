//! Differential: the HPACK decoder used by the HTTP/2 parsers must return the same headers
//! and errors as `hpack_patched`, including the dynamic table carried to a second block.
#![no_main]

use huginn_net_http::hpack_internals::Decoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let at = usize::from(split).min(rest.len());
    let mut ours = Decoder::default();
    let mut reference = hpack_patched::Decoder::new();
    for block in [&rest[..at], &rest[at..]] {
        let want = reference.decode(block).ok();
        // hpack_patched names static entry 15 `accept-` (RFC: `accept-charset`).
        if want.as_ref().is_some_and(|h| h.iter().any(|(name, _)| name == b"accept-")) {
            return;
        }
        assert_eq!(ours.decode(block).ok(), want);
    }
});
