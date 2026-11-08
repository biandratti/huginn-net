//! The extractor reads pseudo-header names without decoding header values. Its result must
//! equal a full HPACK decode (`hpack_patched`) followed by keeping the UTF-8 names that start
//! with `:`, and it must reject exactly the blocks the full decoder rejects.

use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::http2_parser::Http2Frame;
use huginn_net_http::{HuginnNetHttpError, PseudoHeader};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap_or_default();
            match u8::from_str_radix(digits, 16) {
                Ok(b) => b,
                Err(e) => panic!("bad hex in test vector: {e}"),
            }
        })
        .collect()
}

/// RFC 7541 Appendix C header blocks. Consecutive blocks of one example share a dynamic
/// table, so each example is concatenated into a single block.
fn rfc_blocks() -> Vec<(&'static str, Vec<u8>)> {
    let c3 = [
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
        "8286 84be 5808 6e6f 2d63 6163 6865",
        "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
    ];
    let c4 = [
        "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
        "8286 84be 5886 a8eb 1064 9cbf",
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
    ];
    // Responses with a 256 byte table (size update first): exercises eviction.
    let c6 = [
        "3fe1 01 4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
         2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        "4883 640e ffc1 c0bf",
        "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 \
         821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 \
         03ed 4ee5 b106 3d50 07",
    ];
    let join = |parts: &[&str]| parts.iter().flat_map(|p| hex(p)).collect::<Vec<u8>>();
    vec![
        ("C.3", join(&c3)),
        ("C.4", join(&c4)),
        ("C.6", join(&c6)),
        ("C.4.1", hex(c4[0])),
        ("C.4.3 alone (dangling dynamic index)", hex(c4[2])),
    ]
}

/// Full decode with `hpack_patched`, then the extractor's filtering rule.
fn reference(block: &[u8]) -> Option<Vec<PseudoHeader>> {
    let headers = hpack_patched::Decoder::new().decode(block).ok()?;
    Some(
        headers
            .into_iter()
            .filter_map(|(name, value)| {
                let name = String::from_utf8(name).ok()?;
                String::from_utf8(value).ok()?;
                name.starts_with(':')
                    .then(|| PseudoHeader::from(name.as_str()))
            })
            .collect(),
    )
}

/// The extractor's pseudo-header order for `block` in a HEADERS frame.
fn extracted(block: &[u8]) -> Option<Vec<PseudoHeader>> {
    let settings = Http2Frame::new(0x4, 0, 0, vec![0, 1, 0, 0, 0x10, 0]);
    let headers = Http2Frame::new(0x1, 0x05, 1, block.to_vec());
    match extract_akamai_fingerprint(&[settings, headers]) {
        Ok(fp) => Some(fp.pseudo_header_order),
        Err(HuginnNetHttpError::MalformedPseudoHeaders(_)) => None,
        Err(e) => panic!("unexpected error: {e}"),
    }
}

fn assert_same(label: &str, block: &[u8]) {
    // `hpack_patched` names static entry 15 `accept-` (the RFC says `accept-charset`), which
    // also changes its dynamic table sizes: no reference for those blocks.
    if let Ok(headers) = hpack_patched::Decoder::new().decode(block) {
        if headers.iter().any(|(name, _)| name == b"accept-") {
            return;
        }
    }
    assert_eq!(extracted(block), reference(block), "{label}: {block:02x?}");
}

#[test]
fn rfc_7541_vectors_match_a_full_decode() {
    for (label, block) in rfc_blocks() {
        if !label.contains("dangling") {
            assert!(reference(&block).is_some(), "{label}: test vector must decode");
        }
        assert_same(label, &block);
    }
}

#[test]
fn every_single_bit_flip_matches_a_full_decode() {
    for (label, block) in rfc_blocks() {
        for byte in 0..block.len() {
            for bit in 0..8 {
                let mut mutated = block.clone();
                mutated[byte] ^= 1 << bit;
                assert_same(&format!("{label} byte {byte} bit {bit}"), &mutated);
            }
        }
    }
}

#[test]
fn every_truncation_matches_a_full_decode() {
    for (label, block) in rfc_blocks() {
        for len in 0..block.len() {
            assert_same(&format!("{label} truncated to {len}"), &block[..len]);
        }
    }
}

#[test]
fn random_mutations_match_a_full_decode() {
    // xorshift64: deterministic, no extra dependency.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let blocks = rfc_blocks();
    for round in 0..2_000 {
        let (label, block) = &blocks[(next() % blocks.len() as u64) as usize];
        let mut mutated = block.clone();
        for _ in 0..(1 + next() % 4) {
            let at = (next() % mutated.len() as u64) as usize;
            match next() % 3 {
                0 => mutated[at] = next() as u8,
                1 => mutated.insert(at, next() as u8),
                _ => {
                    mutated.remove(at);
                }
            }
            if mutated.is_empty() {
                break;
            }
        }
        assert_same(&format!("{label} round {round}"), &mutated);
    }
}

#[test]
fn literal_pseudo_names_and_non_utf8_values_follow_the_full_decoder() {
    let cases: [(&str, Vec<u8>); 4] = [
        // Literal name ":method" (not indexed), value "GET".
        ("literal pseudo name", [&[0x00, 0x07][..], b":method", &[0x03], b"GET"].concat()),
        // :path with a non UTF-8 value: the full decoder drops the header.
        ("non utf8 value", [&[0x04, 0x02][..], &[0xff, 0xfe]].concat()),
        // Unknown pseudo-header name.
        ("unknown pseudo", [&[0x00, 0x04][..], b":foo", &[0x01], b"x"].concat()),
        // Indexed name 0 is invalid.
        ("index zero", vec![0x80]),
    ];
    for (label, block) in cases {
        assert_same(label, &block);
    }
}
