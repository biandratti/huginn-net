//! Layer 3 golden test: feed a PCAP through `HuginnNetHttp` with a real
//! `SharedHttpSignatureMatcher` and verify browser/server identification
//! against known-good JSON snapshots.
//!
//! The snapshots in `tests/snapshots/` extend the Layer 1 shape (raw HTTP
//! fields) with matcher fields (`browser`, `web_server`, `quality`).

#![cfg(feature = "http")]

use huginn_net_db::{Database, SharedHttpSignatureMatcher};
use huginn_net_http::output::{HttpAnalysisResult, MatchQuality};
use huginn_net_http::HuginnNetHttp;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct PcapSnapshot {
    pcap_path: String,
    expected_connections: usize,
    connections: Vec<ConnectionSnapshot>,
}

#[derive(Deserialize, Debug)]
struct ConnectionSnapshot {
    source: EndpointSnapshot,
    destination: EndpointSnapshot,
    http_request: Option<HttpRequestSnapshot>,
    http_response: Option<HttpResponseSnapshot>,
}

#[derive(Deserialize, Debug)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Deserialize, Debug)]
struct HttpRequestSnapshot {
    browser: Option<String>,
    quality: Option<String>,
    lang: Option<String>,
    user_agent: Option<String>,
    method: Option<String>,
    uri: Option<String>,
}

#[derive(Deserialize, Debug)]
struct HttpResponseSnapshot {
    web_server: Option<String>,
    quality: Option<String>,
    status_code: Option<u16>,
    headers_count: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_snapshot(name: &str) -> PcapSnapshot {
    let path = format!("tests/snapshots/{name}.json");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("failed to read snapshot: {path}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse snapshot {path}: {e}"))
}

fn run_pcap_with_matcher(pcap_path: &str) -> Vec<HttpAnalysisResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP not found: {pcap_path}");

    let db = Database::load_default().unwrap_or_else(|e| panic!("failed to load database: {e}"));
    let matcher = Arc::new(SharedHttpSignatureMatcher::from_database(&db));

    let mut analyzer = HuginnNetHttp::new(1000)
        .unwrap_or_else(|e| panic!("failed to create analyzer: {e}"))
        .with_matcher(matcher);

    let (tx, rx) = channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .unwrap_or_else(|e| panic!("PCAP analysis failed: {e}"));

    let mut results = Vec::new();
    while let Ok(r) = rx.try_recv() {
        if r.http_request.is_some() || r.http_response.is_some() {
            results.push(r);
        }
    }
    results
}

fn assert_quality(actual: &MatchQuality, expected: &str, ctx: &str) {
    match actual {
        MatchQuality::Matched(q) => {
            let expected_q: f32 = expected
                .strip_prefix("Matched(")
                .and_then(|s| s.strip_suffix(")"))
                .unwrap_or_else(|| panic!("{ctx}: unexpected quality format: {expected}"))
                .parse()
                .unwrap_or_else(|_| panic!("{ctx}: cannot parse quality float from: {expected}"));
            assert!(
                (q - expected_q).abs() < 0.01,
                "{ctx}: quality mismatch — expected {expected_q}, got {q}"
            );
        }
        MatchQuality::NotMatched => {
            assert_eq!(expected, "NotMatched", "{ctx}: expected NotMatched")
        }
        MatchQuality::Disabled => {
            assert_eq!(expected, "Disabled", "{ctx}: expected Disabled")
        }
    }
}

fn assert_connection(actual: &HttpAnalysisResult, expected: &ConnectionSnapshot, idx: usize) {
    if let Some(exp_req) = &expected.http_request {
        let req = actual
            .http_request
            .as_ref()
            .unwrap_or_else(|| panic!("connection {idx}: expected HTTP request, found none"));

        assert_eq!(
            req.source.ip.to_string(),
            expected.source.ip,
            "connection {idx}: request source IP"
        );
        assert_eq!(req.source.port, expected.source.port, "connection {idx}: request source port");
        assert_eq!(
            req.destination.ip.to_string(),
            expected.destination.ip,
            "connection {idx}: request destination IP"
        );
        assert_eq!(
            req.destination.port, expected.destination.port,
            "connection {idx}: request destination port"
        );

        if let Some(expected_browser) = &exp_req.browser {
            let browser =
                req.browser_matched.browser.as_ref().unwrap_or_else(|| {
                    panic!("connection {idx}: expected browser match, got None")
                });
            assert_eq!(&browser.name, expected_browser, "connection {idx}: browser name");
        }

        if let Some(expected_quality) = &exp_req.quality {
            assert_quality(
                &req.browser_matched.quality,
                expected_quality,
                &format!("connection {idx} request"),
            );
        }

        if let Some(expected_lang) = &exp_req.lang {
            assert_eq!(
                req.lang
                    .as_ref()
                    .unwrap_or_else(|| panic!("connection {idx}: expected lang")),
                expected_lang,
                "connection {idx}: lang"
            );
        }

        if let Some(expected_ua) = &exp_req.user_agent {
            assert_eq!(
                req.sig
                    .user_agent
                    .as_ref()
                    .unwrap_or_else(|| panic!("connection {idx}: expected user_agent")),
                expected_ua,
                "connection {idx}: user_agent"
            );
        }

        if let Some(expected_method) = &exp_req.method {
            assert_eq!(
                req.sig
                    .method
                    .as_ref()
                    .unwrap_or_else(|| panic!("connection {idx}: expected method")),
                expected_method,
                "connection {idx}: method"
            );
        }

        if let Some(expected_uri) = &exp_req.uri {
            assert_eq!(
                req.sig
                    .uri
                    .as_ref()
                    .unwrap_or_else(|| panic!("connection {idx}: expected uri")),
                expected_uri,
                "connection {idx}: uri"
            );
        }
    }

    if let Some(exp_resp) = &expected.http_response {
        let resp = actual
            .http_response
            .as_ref()
            .unwrap_or_else(|| panic!("connection {idx}: expected HTTP response, found none"));

        assert_eq!(
            resp.source.ip.to_string(),
            expected.source.ip,
            "connection {idx}: response source IP"
        );
        assert_eq!(
            resp.source.port, expected.source.port,
            "connection {idx}: response source port"
        );
        assert_eq!(
            resp.destination.ip.to_string(),
            expected.destination.ip,
            "connection {idx}: response destination IP"
        );
        assert_eq!(
            resp.destination.port, expected.destination.port,
            "connection {idx}: response destination port"
        );

        if let Some(expected_server) = &exp_resp.web_server {
            let server = resp
                .web_server_matched
                .web_server
                .as_ref()
                .unwrap_or_else(|| panic!("connection {idx}: expected web_server match, got None"));
            assert_eq!(&server.name, expected_server, "connection {idx}: web_server name");
        }

        if let Some(expected_quality) = &exp_resp.quality {
            assert_quality(
                &resp.web_server_matched.quality,
                expected_quality,
                &format!("connection {idx} response"),
            );
        }

        if let Some(expected_status) = exp_resp.status_code {
            assert_eq!(
                resp.sig
                    .status_code
                    .unwrap_or_else(|| panic!("connection {idx}: expected status_code")),
                expected_status,
                "connection {idx}: status_code"
            );
        }

        assert_eq!(
            resp.sig.headers.len(),
            exp_resp.headers_count,
            "connection {idx}: headers_count"
        );
    }
}

// ---------------------------------------------------------------------------
// Golden test driver
// ---------------------------------------------------------------------------

fn run_golden_test(snapshot_name: &str) {
    let snapshot = load_snapshot(snapshot_name);
    let results = run_pcap_with_matcher(&snapshot.pcap_path);

    assert_eq!(
        results.len(),
        snapshot.expected_connections,
        "{snapshot_name}: expected {} connections, got {}",
        snapshot.expected_connections,
        results.len()
    );

    for (i, (actual, expected)) in results.iter().zip(snapshot.connections.iter()).enumerate() {
        assert_connection(actual, expected, i);
    }
}

#[test]
fn test_golden_http_pcap_with_matcher() {
    let cases = [
        "http-simple-get",
        // add more snapshot names here as pcap files are added
    ];
    for name in cases {
        run_golden_test(name);
    }
}
