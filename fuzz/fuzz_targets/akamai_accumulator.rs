//! Arbitrary client bytes after a valid HTTP/2 preface, fed in two pieces into the
//! accumulator that builds the Akamai fingerprint.
#![no_main]

use huginn_net_http::keylog_internals::AkamaiAccumulator;
use libfuzzer_sys::fuzz_target;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    let mut acc = AkamaiAccumulator::new(64 * 1024);
    if !matches!(acc.push(PREFACE), Ok(None)) {
        return;
    }
    let mid = data.len() / 2;
    if let Ok(None) = acc.push(&data[..mid]) {
        let _ = acc.push(&data[mid..]);
    }
});
