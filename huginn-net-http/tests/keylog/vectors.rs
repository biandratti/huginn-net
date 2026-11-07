//! Shared helpers and RFC 8448 test vectors.

pub fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| match u8::from_str_radix(&clean[i..i.saturating_add(2)], 16) {
            Ok(b) => b,
            Err(e) => panic!("bad hex in test vector: {e}"),
        })
        .collect()
}

// RFC 8448 section 3 "Simple 1-RTT Handshake": client handshake traffic secret and the derived
// client handshake write key/IV ("{server} derive read traffic keys for handshake data").
pub const RFC8448_C_HS_SECRET: &str = "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21";
// RFC 8448 section 3: client application traffic secret 0 ("tls13 c ap traffic").
pub const RFC8448_C_AP_SECRET: &str = "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5";
