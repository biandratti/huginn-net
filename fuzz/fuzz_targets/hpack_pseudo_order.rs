//! Differential: the extractor's pseudo-header order (which skips header values) must equal
//! a full `hpack_patched` decode followed by keeping the UTF-8 names that start with `:`, and
//! both must reject the same header blocks.
#![no_main]

use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::http2_parser::Http2Frame;
use huginn_net_http::{HuginnNetHttpError, PseudoHeader};
use libfuzzer_sys::fuzz_target;

fn reference(block: &[u8]) -> Option<Vec<PseudoHeader>> {
    let headers = hpack_patched::Decoder::new().decode(block).ok()?;
    Some(
        headers
            .into_iter()
            .filter_map(|(name, value)| {
                let name = String::from_utf8(name).ok()?;
                String::from_utf8(value).ok()?;
                name.starts_with(':').then(|| PseudoHeader::from(name.as_str()))
            })
            .collect(),
    )
}

fuzz_target!(|block: &[u8]| {
    let settings = Http2Frame::new(0x4, 0, 0, vec![0, 1, 0, 0, 0x10, 0]);
    let headers = Http2Frame::new(0x1, 0x05, 1, block.to_vec());
    let extracted = match extract_akamai_fingerprint(&[settings, headers]) {
        Ok(fp) => Some(fp.pseudo_header_order),
        Err(HuginnNetHttpError::MalformedPseudoHeaders(_)) => None,
        Err(e) => panic!("unexpected error: {e}"),
    };
    assert_eq!(extracted, reference(block));
});
