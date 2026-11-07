use huginn_net_http::keylog_internals::{OverLimit, StreamReassembler};

fn ready(r: &StreamReassembler) -> Vec<u8> {
    r.ready_bytes().to_vec()
}

#[test]
fn in_order_segments() {
    let mut r = StreamReassembler::new(1024);
    r.set_isn(99);
    assert_eq!(r.push(100, b"hello "), Ok(()));
    assert_eq!(r.push(106, b"world"), Ok(()));
    assert_eq!(ready(&r), b"hello world");
    assert!(!r.has_gap());
}

#[test]
fn out_of_order_and_duplicates() {
    let mut r = StreamReassembler::new(1024);
    r.set_isn(0);
    assert_eq!(r.push(7, b"world"), Ok(()));
    assert!(r.has_gap());
    assert_eq!(r.push(1, b"hello "), Ok(()));
    assert_eq!(r.push(1, b"hello "), Ok(()));
    assert_eq!(r.push(7, b"world"), Ok(()));
    assert_eq!(ready(&r), b"hello world");
    assert!(!r.has_gap());
}

#[test]
fn partial_overlaps_are_trimmed() {
    let mut r = StreamReassembler::new(1024);
    r.set_isn(0);
    assert_eq!(r.push(1, b"abcdef"), Ok(()));
    assert_eq!(r.push(4, b"defghi"), Ok(()));
    assert_eq!(r.push(9, b"ijk"), Ok(()));
    assert_eq!(ready(&r), b"abcdefghijk");
}

#[test]
fn consume_then_continue() {
    let mut r = StreamReassembler::new(1024);
    assert_eq!(r.push(500, b"abc"), Ok(()));
    r.consume(2);
    assert_eq!(r.push(503, b"de"), Ok(()));
    assert_eq!(ready(&r), b"cde");
    // A retransmission of consumed bytes is ignored.
    assert_eq!(r.push(500, b"abc"), Ok(()));
    assert_eq!(ready(&r), b"cde");
}

#[test]
fn sequence_wraparound() {
    let mut r = StreamReassembler::new(1024);
    r.set_isn(u32::MAX - 10);
    let first = u32::MAX - 9;
    assert_eq!(r.push(first, &[1u8; 8]), Ok(()));
    assert_eq!(r.push(first.wrapping_add(8), &[2u8; 8]), Ok(()));
    assert_eq!(r.push(first.wrapping_add(16), &[3u8; 4]), Ok(()));
    let mut expected = vec![1u8; 8];
    expected.extend([2u8; 8]);
    expected.extend([3u8; 4]);
    assert_eq!(ready(&r), expected);
}

#[test]
fn segment_before_base_is_trimmed() {
    let mut r = StreamReassembler::new(1024);
    r.set_isn(99);
    assert_eq!(r.push(98, b"xxabc"), Ok(()));
    assert_eq!(ready(&r), b"abc");
}

#[test]
fn over_limit() {
    let mut r = StreamReassembler::new(8);
    r.set_isn(0);
    assert_eq!(r.push(1, b"12345678"), Ok(()));
    assert_eq!(r.push(9, b"9"), Err(OverLimit));
    let mut far = StreamReassembler::new(8);
    far.set_isn(0);
    assert_eq!(far.push(1_000, b"x"), Err(OverLimit));
}
