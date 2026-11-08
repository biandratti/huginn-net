//! Arbitrary bytes as a TLS record stream, opened with a fixed dummy key for each
//! supported AEAD. Decryption is expected to fail; it must never panic.
#![no_main]

use huginn_net_http::keylog_internals::{CipherSuite, RecordDecryptor, TrafficKeys, split_records};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const SUITES: [u16; 6] = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA8];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let Ok((records, used)) = split_records(stream) else {
        return;
    };
    assert!(used <= stream.len());
    let Some(suite) = CipherSuite::from_id(SUITES[usize::from(selector) % SUITES.len()]) else {
        return;
    };
    let keys = TrafficKeys {
        key: Zeroizing::new(vec![0x42; suite.aead.key_len()]),
        iv: Zeroizing::new(vec![0x24; suite.iv_len()]),
    };
    let Ok(decryptor) = RecordDecryptor::new(suite, &keys) else {
        panic!("dummy keys have the right length");
    };
    let mut decryptor = decryptor.with_seq(u64::from(selector));
    for record in &records {
        let _ = decryptor.open(record);
    }
});
