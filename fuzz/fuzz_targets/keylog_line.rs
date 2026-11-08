//! Arbitrary bytes as key log input: one line through the parser, and the same bytes
//! through the line splitter used when following a file.
#![no_main]

use huginn_net_http::KeyLogStore;
use huginn_net_http::keylog_internals::LineSplitter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let store = KeyLogStore::new(16);
    let _ = store.insert_line_bytes(data);

    let mut splitter = LineSplitter::default();
    let mid = data.len() / 2;
    splitter.feed(&data[..mid], &store);
    splitter.feed(&data[mid..], &store);
    splitter.finish(&store);
    assert!(store.len() <= 16);
});
