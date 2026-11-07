use super::vectors::{RFC8448_C_AP_SECRET, RFC8448_C_HS_SECRET, hex};
use huginn_net_http::keylog_internals::{
    CipherSuite, HashAlg, tls12_client_keys, tls12_prf, tls13_traffic_keys,
};

fn suite(id: u16) -> CipherSuite {
    match CipherSuite::from_id(id) {
        Some(s) => s,
        None => panic!("suite {id:#06x} must be supported"),
    }
}

#[test]
fn rfc8448_client_handshake_keys() {
    let keys = match tls13_traffic_keys(&hex(RFC8448_C_HS_SECRET), suite(0x1301)) {
        Ok(k) => k,
        Err(_) => panic!("derivation must succeed"),
    };
    assert_eq!(keys.key.as_slice(), hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01"));
    assert_eq!(keys.iv.as_slice(), hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"));
}

#[test]
fn rfc8448_client_application_keys() {
    let keys = match tls13_traffic_keys(&hex(RFC8448_C_AP_SECRET), suite(0x1301)) {
        Ok(k) => k,
        Err(_) => panic!("derivation must succeed"),
    };
    assert_eq!(keys.key.as_slice(), hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51"));
    assert_eq!(keys.iv.as_slice(), hex("5b 78 92 3d ee 08 57 90 33 e5 23 d9"));
}

#[test]
fn tls13_rejects_secret_length_not_matching_hash() {
    // A 32-byte secret with a SHA-384 suite is a key log / suite mismatch.
    assert!(tls13_traffic_keys(&hex(RFC8448_C_AP_SECRET), suite(0x1302)).is_err());
}

// TLS 1.2 PRF vectors computed with Python's stdlib `hmac` (independent implementation):
// secret = bytes(0..48), label = "key expansion", seed = bytes(0..64).
#[test]
fn tls12_prf_sha256_and_sha384() {
    let secret: Vec<u8> = (0u8..48).collect();
    let seed: Vec<u8> = (0u8..64).collect();
    let out = match tls12_prf(HashAlg::Sha256, &secret, b"key expansion", &seed, 88) {
        Ok(o) => o,
        Err(_) => panic!("prf must succeed"),
    };
    assert_eq!(
        out.as_slice(),
        hex(
            "4ac38c4d46e5ff44538c63cd6644009fd1aa1b19a81b76452615cb3f94ce61ea9f2477bd23b09dfa\
             855a5d720e91e4b20588e7d3c8a7ea09ee756866999714e82ec648155182727f19c882dbc6845bd4\
             b682147c403e2560"
        )
    );
    let out = match tls12_prf(HashAlg::Sha384, &secret, b"key expansion", &seed, 72) {
        Ok(o) => o,
        Err(_) => panic!("prf must succeed"),
    };
    assert_eq!(
        out.as_slice(),
        hex(
            "724152abe2fd4f3af374fb9420892f7f596f6d7ca573a31a50fb435dfd0c431ed62e5d92aa135958\
             dbf9035cf97c343bcdf6f744378ff8bd58030551645fe8cabcfa300b6c3ba5e6"
        )
    );
}

#[test]
fn tls12_key_block_slicing() {
    let master: Vec<u8> = (0u8..48).collect();
    let mut server_random = [0u8; 32];
    let mut client_random = [0u8; 32];
    for (i, b) in server_random.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0);
    }
    for (i, b) in client_random.iter_mut().enumerate() {
        *b = u8::try_from(i.saturating_add(32)).unwrap_or(0);
    }
    // Same seed as the PRF vector above: server_random || client_random = bytes(0..64).
    let keys = match tls12_client_keys(&master, &client_random, &server_random, suite(0xC02F)) {
        Ok(k) => k,
        Err(_) => panic!("derivation must succeed"),
    };
    assert_eq!(keys.key.as_slice(), hex("4ac38c4d46e5ff44538c63cd6644009f"));
    // client IV follows both 16-byte keys: bytes 32..36 of the block.
    assert_eq!(keys.iv.as_slice(), hex("9f2477bd"));
}
