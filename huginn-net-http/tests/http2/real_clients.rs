//! Client streams recorded from real browsers and curl (`tests/data/h2-clients/`).

use huginn_net_http::hpack_internals::Decoder;
use huginn_net_http::http2_parser::{Http2FrameType, Http2Parser};

struct Client {
    file: &'static str,
    user_agent: &'static str,
    headers: usize,
    akamai: &'static str,
}

const CLIENTS: &[Client] = &[
    Client {
        file: "curl-8.5.bin",
        user_agent: "curl/8.5.0",
        headers: 2,
        akamai: "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    },
    Client {
        file: "chrome-157.bin",
        user_agent: "HeadlessChrome/157.0.0.0",
        headers: 13,
        akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    Client {
        file: "chromium-156.bin",
        user_agent: "HeadlessChrome/156.0.0.0",
        headers: 13,
        akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    Client {
        file: "firefox-159.bin",
        user_agent: "Firefox/159.0",
        headers: 10,
        akamai: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    },
];

fn stream(file: &str) -> Vec<u8> {
    let path = format!("tests/data/h2-clients/{file}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn p0f_parser_reads_real_browser_requests() {
    for client in CLIENTS {
        let request = match Http2Parser::new().parse_request(&stream(client.file)) {
            Ok(Some(request)) => request,
            other => panic!("{}: {other:?}", client.file),
        };
        assert_eq!(request.method, "GET", "{}", client.file);
        assert_eq!(request.path, "/", "{}", client.file);
        assert_eq!(request.authority.as_deref(), Some("localhost:8443"), "{}", client.file);
        let ua = request
            .headers
            .iter()
            .find(|h| h.name == "user-agent")
            .and_then(|h| h.value.as_deref())
            .unwrap_or_default();
        assert!(ua.contains(client.user_agent), "{}: {ua}", client.file);
        assert_eq!(request.headers.len(), client.headers, "{}", client.file);
    }
}

#[test]
fn hpack_decoder_matches_hpack_patched_on_real_header_blocks() {
    for client in CLIENTS {
        let bytes = stream(client.file);
        let parser = Http2Parser::new();
        let frames = match parser.parse_frames_skip_preface(&bytes) {
            Ok((frames, _)) => frames,
            Err(e) => panic!("{}: {e}", client.file),
        };
        let Some(headers) = frames
            .iter()
            .find(|f| f.frame_type == Http2FrameType::Headers)
        else {
            panic!("{}: no HEADERS frame", client.file);
        };
        // Strip PADDED / PRIORITY (browsers set PRIORITY) to get the header block.
        let mut block = headers.payload.as_slice();
        if headers.flags & 0x08 != 0 {
            let pad = usize::from(block[0]);
            block = &block[1..block.len() - pad];
        }
        if headers.flags & 0x20 != 0 {
            block = &block[5..];
        }
        let ours = Decoder::default().decode(block).ok();
        let reference = hpack_patched::Decoder::new().decode(block).ok();
        assert!(ours.is_some(), "{}: must decode", client.file);
        assert_eq!(ours, reference, "{}", client.file);
    }
}

#[cfg(feature = "akamai")]
#[test]
fn akamai_fingerprints_match_huginn_proxy() {
    use huginn_net_http::akamai_extractor::extract_akamai_fingerprint_from_bytes;
    for client in CLIENTS {
        match extract_akamai_fingerprint_from_bytes(&stream(client.file)) {
            Ok(fp) => assert_eq!(fp.fingerprint, client.akamai, "{}", client.file),
            Err(e) => panic!("{}: {e}", client.file),
        }
    }
}

#[test]
fn signature_drops_user_agent_value_and_marks_optional_headers() {
    use huginn_net_http::http2_process::parse_http2_request;

    // Real Chrome request: user-agent is in the signature without its value.
    let chrome = match parse_http2_request(&stream("chrome-157.bin"), &Http2Parser::new()) {
        Ok(Some(req)) => req.matching,
        other => panic!("{other:?}"),
    };
    let Some(ua) = chrome.horder.iter().find(|h| h.name == "user-agent") else {
        panic!("user-agent missing from the signature");
    };
    assert_eq!(ua.value, None);

    // Hand-made request with cache-control, which must be optional like in HTTP/1.
    let mut block = vec![0x82, 0x84, 0x87, 0x41, 0x09];
    block.extend_from_slice(b"localhost");
    block.extend_from_slice(&[0x0f, 0x09, 0x08]); // cache-control (static index 24)
    block.extend_from_slice(b"no-cache");
    block.extend_from_slice(&[0x0f, 0x2b, 0x04]); // user-agent (static index 58)
    block.extend_from_slice(b"test");
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]); // empty SETTINGS
    let len = u8::try_from(block.len()).unwrap_or(u8::MAX);
    bytes.extend_from_slice(&[0, 0, len, 0x01, 0x05, 0, 0, 0, 1]); // HEADERS, stream 1
    bytes.extend_from_slice(&block);
    let observation = match parse_http2_request(&bytes, &Http2Parser::new()) {
        Ok(Some(req)) => req.matching,
        other => panic!("{other:?}"),
    };
    let Some(cache_control) = observation
        .horder
        .iter()
        .find(|h| h.name == "cache-control")
    else {
        panic!("cache-control missing from the signature");
    };
    assert!(cache_control.optional, "cache-control must be optional");
    assert_eq!(cache_control.value, None);
}

/// Offsets where each frame ends, after the connection preface.
#[cfg(feature = "akamai")]
fn frame_ends(bytes: &[u8]) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut pos = 24usize; // connection preface
    while let Some(header) = bytes.get(pos..pos.saturating_add(9)) {
        let len =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        pos = pos.saturating_add(9).saturating_add(len);
        ends.push(pos.min(bytes.len()));
    }
    ends
}

/// Feeds `bytes` to the incremental extractor in pieces ending at `cuts`.
#[cfg(feature = "akamai")]
fn incremental(bytes: &[u8], cuts: &[usize]) -> Option<String> {
    use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;
    let mut extractor = Http2FingerprintExtractor::new();
    let mut start = 0usize;
    for &end in cuts.iter().chain(std::iter::once(&bytes.len())) {
        if end <= start {
            continue;
        }
        if let Err(e) = extractor.add_bytes(&bytes[start..end]) {
            panic!("add_bytes failed after {end} bytes: {e}");
        }
        start = end;
    }
    extractor.get_fingerprint().map(|fp| fp.fingerprint.clone())
}

#[cfg(feature = "akamai")]
#[test]
fn incremental_extractor_gives_the_same_result_when_frames_arrive_separately() {
    for client in CLIENTS {
        let bytes = stream(client.file);
        let ends = frame_ends(&bytes);
        // Everything up to the frame before HEADERS, then HEADERS: one TLS record each, as
        // browsers write them.
        let before_headers = ends.len().checked_sub(2).map(|i| ends[i]).unwrap_or(0);
        let cases: [(&str, Vec<usize>); 3] = [
            ("one piece per frame", ends.clone()),
            ("settings first, then headers", vec![before_headers]),
            ("byte by byte", (1..bytes.len()).collect()),
        ];
        for (how, cuts) in cases {
            assert_eq!(
                incremental(&bytes, &cuts).as_deref(),
                Some(client.akamai),
                "{}: {how}",
                client.file
            );
        }
    }
}
