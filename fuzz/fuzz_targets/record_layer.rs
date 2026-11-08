//! Arbitrary bytes as a TLS record stream, opened with a fixed dummy key for each
//! supported AEAD. Decryption is expected to fail; it must never panic.
#![no_main]

use huginn_net_http::TlsVersion;
use huginn_net_http::keylog_internals::{
    AeadAlg, CipherSuite, RecordDecryptor, TrafficKeys, split_records,
};
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
    // TLS 1.2 GCM uses a 4 byte implicit IV, everything else a 12 byte IV.
    let iv_len = match (suite.version, suite.aead) {
        (TlsVersion::Tls12, AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm) => 4,
        _ => 12,
    };
    let keys = TrafficKeys {
        key: Zeroizing::new(vec![0x42; suite.aead.key_len()]),
        iv: Zeroizing::new(vec![0x24; iv_len]),
    };
    let Ok(decryptor) = RecordDecryptor::new(suite, &keys) else {
        panic!("dummy keys have the right length");
    };
    let mut decryptor = decryptor.with_seq(u64::from(selector));
    for record in &records {
        let _ = decryptor.open(record);
    }
});
