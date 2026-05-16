//! End-to-end integration smoke tests for `HuginnNet`.
//!
//! These tests run the full pipeline (TCP + HTTP simultaneously) and
//! spot-check concrete values. The per-crate layer tests in `huginn-net-db`
//! cover exhaustive golden assertions; the role of these tests is to verify
//! that the umbrella crate correctly wires and combines both protocols in a
//! single `FingerprintResult`.

#![cfg(feature = "db")]

use huginn_net::{Database, HuginnNet, TcpMatchQuality};
use huginn_net_http::output::MatchQuality as HttpMatchQuality;
use std::path::Path;
use std::sync::mpsc;

const TCP_PCAP_PATH: &str = "../pcap/macos_tcp_flags.pcap";
const HTTP_PCAP_PATH: &str = "../pcap/http-simple-get.pcap";

fn collect_results(pcap_path: &str) -> Vec<huginn_net::output::FingerprintResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");
    let db = Database::load_default().unwrap_or_else(|e| panic!("load embedded p0f database: {e}"));
    let mut analyzer = HuginnNet::new(Some(&db), 1000, None)
        .unwrap_or_else(|e| panic!("construct HuginnNet: {e}"));
    let (tx, rx) = mpsc::channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .unwrap_or_else(|e| panic!("analyze pcap {pcap_path}: {e}"));
    rx.into_iter().collect()
}

#[test]
fn e2e_tcp_syn_and_mtu_are_identified() {
    let results = collect_results(TCP_PCAP_PATH);

    let first_syn = results
        .iter()
        .find(|r| r.tcp_syn.is_some())
        .and_then(|r| r.tcp_syn.as_ref())
        .unwrap_or_else(|| panic!("expected at least one SYN in macos_tcp_flags.pcap"));

    assert_eq!(
        first_syn.sig.to_string(),
        "4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1,eol+0:df,ecn:0",
        "first SYN raw signature"
    );
    assert!(
        matches!(first_syn.os_matched.quality, TcpMatchQuality::NotMatched),
        "macOS SYN is not in p0f.fp, matcher must run and return NotMatched, got {:?}",
        first_syn.os_matched.quality
    );

    let first_mtu = results
        .iter()
        .find(|r| r.tcp_mtu.is_some())
        .and_then(|r| r.tcp_mtu.as_ref())
        .unwrap_or_else(|| panic!("expected at least one MTU observation"));

    assert_eq!(first_mtu.mtu, 1504, "first MTU value");
    assert!(
        matches!(first_mtu.link.quality, TcpMatchQuality::NotMatched),
        "MTU 1504 is not in p0f.fp, matcher must return NotMatched, got {:?}",
        first_mtu.link.quality
    );
}

#[test]
fn e2e_http_pcap_produces_both_tcp_and_http_results() {
    let results = collect_results(HTTP_PCAP_PATH);

    assert!(
        results.iter().any(|r| r.tcp_syn.is_some()),
        "expected TCP SYN results alongside HTTP in http-simple-get.pcap"
    );

    let req = results
        .iter()
        .find(|r| r.http_request.is_some())
        .and_then(|r| r.http_request.as_ref())
        .unwrap_or_else(|| panic!("expected an HTTP request result"));

    let browser = req
        .browser_matched
        .browser
        .as_ref()
        .unwrap_or_else(|| panic!("expected a browser match for curl request"));
    assert_eq!(browser.name, "curl", "browser name");
    assert!(
        matches!(req.browser_matched.quality, HttpMatchQuality::Matched(_)),
        "browser quality must be Matched, got {:?}",
        req.browser_matched.quality
    );

    let resp = results
        .iter()
        .find(|r| r.http_response.is_some())
        .and_then(|r| r.http_response.as_ref())
        .unwrap_or_else(|| panic!("expected an HTTP response result"));

    let server = resp
        .web_server_matched
        .web_server
        .as_ref()
        .unwrap_or_else(|| panic!("expected a web server match"));
    assert_eq!(server.name, "Apache", "web server name");
    assert!(
        matches!(resp.web_server_matched.quality, HttpMatchQuality::Matched(_)),
        "web server quality must be Matched, got {:?}",
        resp.web_server_matched.quality
    );
}
