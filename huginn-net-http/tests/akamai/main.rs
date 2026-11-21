#![cfg(feature = "akamai")]

#[path = "../common/mod.rs"]
mod common;
mod extractor;
mod fingerprint;
mod paper_golden;
mod pcap_golden;

struct ActualFingerprint<'a> {
    signature: &'a str,
    hash: &'a str,
    settings_count: usize,
    window_update: u32,
    priority_count: usize,
    pseudo_headers_count: usize,
}
