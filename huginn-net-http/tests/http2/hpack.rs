//! The HPACK decoder used by the HTTP/2 parsers must behave exactly like `hpack_patched`:
//! same headers, same errors, and the same dynamic table state across consecutive blocks.

use huginn_net_http::hpack_internals::{Decoder, Header};

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

/// RFC 7541 Appendix C examples: each is a sequence of blocks sharing one decoder.
fn rfc_sequences() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let seq = |blocks: &[&str]| blocks.iter().map(|b| hex(b)).collect::<Vec<_>>();
    vec![
        (
            "C.3 requests",
            seq(&[
                "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
                "8286 84be 5808 6e6f 2d63 6163 6865",
                "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
            ]),
        ),
        (
            "C.4 requests, Huffman",
            seq(&[
                "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
                "8286 84be 5886 a8eb 1064 9cbf",
                "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
            ]),
        ),
        (
            "C.6 responses, Huffman, 256 byte table",
            seq(&[
                "3fe1 01 4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 \
                 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
                "4883 640e ffc1 c0bf",
                "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
                 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
                 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            ]),
        ),
    ]
}

/// `hpack_patched` names static entry 15 `accept-` instead of `accept-charset`.
fn uses_wrong_reference_entry(headers: &[Header]) -> bool {
    headers.iter().any(|(name, _)| name == b"accept-")
}

/// Decodes `blocks` in order with one decoder of each implementation and compares every step.
fn assert_same(label: &str, blocks: &[Vec<u8>]) {
    let mut ours = Decoder::default();
    let mut reference = hpack_patched::Decoder::new();
    for (i, block) in blocks.iter().enumerate() {
        let got: Option<Vec<Header>> = ours.decode(block).ok();
        let want: Option<Vec<Header>> = reference.decode(block).ok();
        if want.as_deref().is_some_and(uses_wrong_reference_entry) {
            // From here on the reference differs from the RFC (and so may its table).
            return;
        }
        assert_eq!(got, want, "{label}, block {i}: {block:02x?}");
    }
}

#[test]
fn rfc_7541_sequences_match_hpack_patched() {
    for (label, blocks) in rfc_sequences() {
        let mut reference = hpack_patched::Decoder::new();
        for block in &blocks {
            assert!(reference.decode(block).is_ok(), "{label}: test vector must decode");
        }
        assert_same(label, &blocks);
    }
}

#[test]
fn mutated_blocks_match_hpack_patched() {
    // xorshift64: deterministic, no extra dependency.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let sequences = rfc_sequences();
    for round in 0..2_000u32 {
        let (label, blocks) = &sequences[(next() % sequences.len() as u64) as usize];
        let mut blocks = blocks.clone();
        let which = (next() % blocks.len() as u64) as usize;
        let block = &mut blocks[which];
        for _ in 0..(1 + next() % 3) {
            if block.is_empty() {
                break;
            }
            let at = (next() % block.len() as u64) as usize;
            match next() % 4 {
                0 => block[at] ^= 1 << (next() % 8),
                1 => block[at] = next() as u8,
                2 => block.insert(at, next() as u8),
                _ => block.truncate(at),
            }
        }
        // Later blocks still decode against the state the mutated block left behind.
        assert_same(&format!("{label} round {round}"), &blocks);
    }
}

#[test]
fn every_single_bit_flip_matches_hpack_patched() {
    for (label, blocks) in rfc_sequences() {
        for which in 0..blocks.len() {
            for byte in 0..blocks[which].len() {
                for bit in 0..8 {
                    let mut mutated = blocks.clone();
                    mutated[which][byte] ^= 1 << bit;
                    assert_same(&format!("{label} block {which} byte {byte} bit {bit}"), &mutated);
                }
            }
        }
    }
}

#[test]
fn static_entry_15_is_accept_charset() {
    // Indexed header field 15 (0x8f), and a literal with indexed name 15.
    let headers =
        Decoder::default().decode(&[0x8f, 0x0f, 0x00, 0x05, b'u', b't', b'f', b'-', b'8']);
    assert_eq!(
        headers.ok(),
        Some(vec![
            (b"accept-charset".to_vec(), Vec::new()),
            (b"accept-charset".to_vec(), b"utf-8".to_vec()),
        ])
    );
}
