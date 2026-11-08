//! A random sequence of TCP segments pushed into the stream reassembler. Checks that the
//! buffered bytes stay within the limit and that consuming never panics.
#![no_main]

use huginn_net_http::keylog_internals::StreamReassembler;
use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let mut reassembler = StreamReassembler::new(LIMIT);
    let mut input = data;
    if let Some((isn, rest)) = input.split_first_chunk::<4>() {
        reassembler.set_isn(u32::from_be_bytes(*isn));
        input = rest;
    }
    // Each step: 4 byte seq, 1 byte length, 1 byte consume amount, then the payload.
    while let Some((head, rest)) = input.split_first_chunk::<6>() {
        let seq = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let len = usize::from(head[4]).min(rest.len());
        let (payload, rest) = rest.split_at(len);
        input = rest;
        if reassembler.push(seq, payload).is_err() {
            return;
        }
        assert!(reassembler.ready_bytes().len() <= LIMIT);
        let take = usize::from(head[5]).min(reassembler.ready_bytes().len());
        reassembler.consume(take);
        let _ = reassembler.has_gap();
    }
});
