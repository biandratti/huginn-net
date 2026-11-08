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
