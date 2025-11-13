use huginn_net_db::Database;
use huginn_net_http::{HttpAnalysisResult, HuginnNetHttp};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;

// Snapshot structures for JSON serialization
#[derive(Serialize, Deserialize, Debug)]
struct PcapSnapshot {
    pcap_file: String,
    pcap_path: String,
    expected_connections: usize,
    connections: Vec<ConnectionSnapshot>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionSnapshot {
    source: EndpointSnapshot,
    destination: EndpointSnapshot,
    http_request: Option<HttpRequestSnapshot>,
    http_response: Option<HttpResponseSnapshot>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct HttpRequestSnapshot {
    browser: Option<String>,
    lang: Option<String>,
    quality: String,
    user_agent: Option<String>,
    method: Option<String>,
    uri: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct HttpResponseSnapshot {
    web_server: Option<String>,
    quality: String,
    status_code: Option<u16>,
    headers_count: usize,
}

fn load_snapshot(pcap_file: &str) -> PcapSnapshot {
    let snapshot_path = format!("tests/snapshots/{pcap_file}.json");
    let snapshot_content = fs::read_to_string(&snapshot_path)
        .unwrap_or_else(|_| panic!("Failed to read snapshot file: {snapshot_path}"));

    serde_json::from_str(&snapshot_content)
        .unwrap_or_else(|e| panic!("Failed to parse snapshot JSON: {e}"))
}

fn analyze_pcap_file(pcap_path: &str) -> Vec<HttpAnalysisResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");

    let db = Database::load_default().unwrap_or_else(|e| panic!("Failed to load database: {e}"));
    let mut analyzer = HuginnNetHttp::new(Some(Arc::new(db)), 1000)
        .unwrap_or_else(|e| panic!("Failed to create analyzer: {e}"));

    let (sender, receiver) = channel();

    // Run PCAP analysis in the same thread to avoid lifetime issues
    if let Err(e) = analyzer.analyze_pcap(pcap_path, sender, None) {
        panic!("PCAP analysis failed: {e}");
    }

    // Collect all results
    let mut results = Vec::new();
    while let Ok(result) = receiver.try_recv() {
        // Only collect results that have meaningful HTTP data
        if has_meaningful_http_data(&result) {
            results.push(result);
        }
    }

    results
}

fn has_meaningful_http_data(result: &HttpAnalysisResult) -> bool {
    result.http_request.is_some() || result.http_response.is_some()
}

fn assert_connection_matches_snapshot(
    actual: &HttpAnalysisResult,
    expected: &ConnectionSnapshot,
    connection_index: usize,
) {
    // Check HTTP Request
    if let Some(expected_request) = &expected.http_request {
        if let Some(actual_request) = &actual.http_request {
            // Check source and destination
            assert_eq!(
                actual_request.source.ip.to_string(),
                expected.source.ip,
                "Connection {connection_index}: Request source IP mismatch"
            );
            assert_eq!(
                actual_request.source.port, expected.source.port,
                "Connection {connection_index}: Request source port mismatch"
            );
            assert_eq!(
                actual_request.destination.ip.to_string(),
                expected.destination.ip,
                "Connection {connection_index}: Request destination IP mismatch"
            );
            assert_eq!(
                actual_request.destination.port, expected.destination.port,
                "Connection {connection_index}: Request destination port mismatch"
            );

            // Check browser matching
            if let Some(expected_browser) = &expected_request.browser {
                if let Some(actual_browser) = &actual_request.browser_matched.browser {
                    assert_eq!(
                        actual_browser.name, *expected_browser,
                        "Connection {connection_index}: HTTP browser mismatch"
                    );
                }
            }

            // Check language
            if let Some(expected_lang) = &expected_request.lang {
                assert_eq!(
                    actual_request.lang.as_ref().unwrap_or_else(|| panic!(
                        "Connection {connection_index}: Expected language but found none"
                    )),
                    expected_lang,
                    "Connection {connection_index}: HTTP language mismatch"
                );
            }

            // Check quality
            assert_eq!(
                format!("{:?}", actual_request.browser_matched.quality),
                expected_request.quality,
                "Connection {connection_index}: HTTP request quality mismatch"
            );

            // Check user agent
            if let Some(expected_ua) = &expected_request.user_agent {
                assert_eq!(
                    actual_request
                        .sig
                        .user_agent
                        .as_ref()
                        .unwrap_or_else(|| panic!(
                            "Connection {connection_index}: Expected user agent but found none"
                        )),
                    expected_ua,
                    "Connection {connection_index}: User agent mismatch"
                );
            }

            // Check method
            if let Some(expected_method) = &expected_request.method {
                assert_eq!(
                    actual_request.sig.method.as_ref().unwrap_or_else(|| panic!(
                        "Connection {connection_index}: Expected method but found none"
                    )),
                    expected_method,
                    "Connection {connection_index}: HTTP method mismatch"
                );
            }

            // Check URI
            if let Some(expected_uri) = &expected_request.uri {
                assert_eq!(
                    actual_request.sig.uri.as_ref().unwrap_or_else(|| panic!(
                        "Connection {connection_index}: Expected URI but found none"
                    )),
                    expected_uri,
                    "Connection {connection_index}: HTTP URI mismatch"
                );
            }
        } else {
            panic!("Connection {connection_index}: Expected HTTP request but found none");
        }
    }

    // Check HTTP Response
    if let Some(expected_response) = &expected.http_response {
        if let Some(actual_response) = &actual.http_response {
            // Check source and destination
            assert_eq!(
                actual_response.source.ip.to_string(),
                expected.source.ip,
                "Connection {connection_index}: Response source IP mismatch"
            );
            assert_eq!(
                actual_response.source.port, expected.source.port,
                "Connection {connection_index}: Response source port mismatch"
            );
            assert_eq!(
                actual_response.destination.ip.to_string(),
                expected.destination.ip,
                "Connection {connection_index}: Response destination IP mismatch"
            );
            assert_eq!(
                actual_response.destination.port, expected.destination.port,
                "Connection {connection_index}: Response destination port mismatch"
            );

            // Check web server matching
            if let Some(expected_server) = &expected_response.web_server {
                if let Some(actual_server) = &actual_response.web_server_matched.web_server {
                    assert_eq!(
                        actual_server.name, *expected_server,
                        "Connection {connection_index}: HTTP web server mismatch"
                    );
                }
            }

            // Check quality
            assert_eq!(
                format!("{:?}", actual_response.web_server_matched.quality),
                expected_response.quality,
                "Connection {connection_index}: HTTP response quality mismatch"
            );

            // Check status code
            if let Some(expected_status) = expected_response.status_code {
                assert_eq!(
                    actual_response.sig.status_code.unwrap_or_else(|| panic!(
                        "Connection {connection_index}: Expected status code but found none"
                    )),
                    expected_status,
                    "Connection {connection_index}: HTTP status code mismatch"
                );
            }

            // Check headers count
            assert_eq!(
                actual_response.sig.headers.len(),
                expected_response.headers_count,
                "Connection {connection_index}: Headers count mismatch"
            );
        } else {
            panic!("Connection {connection_index}: Expected HTTP response but found none");
        }
    }
}

/// Golden test: compares PCAP analysis output against known-good JSON snapshots
fn test_pcap_with_snapshot(pcap_file: &str) {
    let snapshot = load_snapshot(pcap_file);
    let results = analyze_pcap_file(&snapshot.pcap_path);

    assert_eq!(
        results.len(),
        snapshot.expected_connections,
        "Expected {} connections in {}, found {}",
        snapshot.expected_connections,
        pcap_file,
        results.len()
    );

    for (i, (actual, expected)) in results.iter().zip(snapshot.connections.iter()).enumerate() {
        assert_connection_matches_snapshot(actual, expected, i);
    }
}

#[test]
fn test_golden_http_snapshots() {
    let golden_test_cases = [
        "http-simple-get",
        // Add more PCAP files here as golden tests:
        // "http-post",
        // "http-headers",
    ];

    for pcap_file in golden_test_cases {
        println!("Running golden test for: {pcap_file}");
        test_pcap_with_snapshot(pcap_file);
    }
}
