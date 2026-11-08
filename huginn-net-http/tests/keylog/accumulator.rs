use huginn_net_http::HTTP2_CONNECTION_PREFACE;
use huginn_net_http::keylog_internals::{AccumulatorError, AkamaiAccumulator};

const LIMIT: usize = 64 * 1024;
use huginn_net_http::extract_akamai_fingerprint_from_bytes;

fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], ftype, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn client_bytes() -> (Vec<u8>, Vec<u8>) {
    let mut first = HTTP2_CONNECTION_PREFACE.to_vec();
    first.extend(frame(4, 0, 0, &[0, 1, 0, 1, 0, 0, 0, 4, 0, 0x60, 0, 0]));
    first.extend(frame(8, 0, 0, &[0, 0xEF, 0, 1]));
    // :method GET, :path /, :scheme https, :authority (literal, indexed name 1)
    let mut block = vec![0x82, 0x84, 0x87, 0x41, 4];
    block.extend_from_slice(b"host");
    let headers = frame(1, 0x05, 1, &block);
    (first, headers)
}

#[test]
fn waits_for_headers_then_matches_standalone_extractor() {
    let (first, headers) = client_bytes();
    let mut acc = AkamaiAccumulator::new(LIMIT);
    assert_eq!(acc.push(&first), Ok(None), "no HEADERS yet");
    let fp = match acc.push(&headers) {
        Ok(Some(fp)) => fp,
        other => panic!("expected a fingerprint, got {other:?}"),
    };
    let mut all = first.clone();
    all.extend_from_slice(&headers);
    let standalone = match extract_akamai_fingerprint_from_bytes(&all) {
        Ok(fp) => fp,
        Err(e) => panic!("standalone must succeed: {e}"),
    };
    assert_eq!(fp, standalone);
    assert!(fp.fingerprint.ends_with("|m,p,s,a"), "{}", fp.fingerprint);
}

#[test]
fn byte_by_byte_gives_same_result() {
    let (first, headers) = client_bytes();
    let mut all = first;
    all.extend_from_slice(&headers);
    let mut acc = AkamaiAccumulator::new(LIMIT);
    let mut result = None;
    for b in &all {
        if let Ok(Some(fp)) = acc.push(std::slice::from_ref(b)) {
            result = Some(fp);
        }
    }
    assert_eq!(
        result.map(|f| f.fingerprint),
        extract_akamai_fingerprint_from_bytes(&all)
            .ok()
            .map(|f| f.fingerprint)
    );
}

#[test]
fn rejects_non_http2_and_oversized_input() {
    let mut acc = AkamaiAccumulator::new(LIMIT);
    assert_eq!(acc.push(b"GET / HTTP/1.1\r\n"), Err(AccumulatorError::NotHttp2));
    let mut small = AkamaiAccumulator::new(30);
    let (first, _) = client_bytes();
    assert_eq!(small.push(&first), Err(AccumulatorError::TooLarge));
    assert!(small.len() > 30);
}
