use huginn_net_tls::{HuginnNetTls, TlsClientOutput, TlsVersion};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::thread;

#[derive(Debug, Deserialize, Serialize)]
struct PcapSnapshot {
    pcap_file: String,
    pcap_path: String,
    expected_connections: usize,
    connections: Vec<ConnectionSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConnectionSnapshot {
    source: EndpointSnapshot,
    destination: EndpointSnapshot,
    tls: TlsSnapshot,
}

#[derive(Debug, Deserialize, Serialize)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
struct TlsSnapshot {
    version: String,
    sni: String,
    alpn: String,
    cipher_suites_count: usize,
    extensions_count: usize,
    has_signature_algorithms: bool,
    has_elliptic_curves: bool,
    ja4: Ja4Snapshot,
    ja4_original: Ja4Snapshot,
}

#[derive(Debug, Deserialize, Serialize)]
struct Ja4Snapshot {
    full: String,
    ja4_a: String,
    ja4_b: String,
    ja4_c: String,
    raw: String,
}

fn load_snapshot(pcap_file: &str) -> PcapSnapshot {
    let snapshot_path = format!("tests/snapshots/{pcap_file}.json");
    let snapshot_content = fs::read_to_string(&snapshot_path)
        .unwrap_or_else(|_| panic!("Failed to read snapshot file: {snapshot_path}"));

    serde_json::from_str(&snapshot_content)
        .unwrap_or_else(|e| panic!("Failed to parse snapshot JSON: {e}"))
}

fn analyze_pcap_file(pcap_path: &str) -> Vec<TlsClientOutput> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");

    let mut analyzer = HuginnNetTls::new(10000);
    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();

    let pcap_file = pcap_path.to_string();
    let handle = thread::spawn(move || analyzer.analyze_pcap(&pcap_file, sender, None));

    let mut results = Vec::new();
    for tls_output in receiver {
        results.push(tls_output);
    }

    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            panic!("PCAP analysis failed: {e}");
        }
        Err(e) => {
            panic!("Thread join failed: {e:?}");
        }
    }

    results
}

fn assert_connection_matches_snapshot(
    actual: &TlsClientOutput,
    expected: &ConnectionSnapshot,
    connection_index: usize,
) {
    assert_eq!(
        actual.source.ip.to_string(),
        expected.source.ip,
        "Connection {connection_index}: Source IP mismatch"
    );
    assert_eq!(
        actual.source.port, expected.source.port,
        "Connection {connection_index}: Source port mismatch"
    );

    assert_eq!(
        actual.destination.ip.to_string(),
        expected.destination.ip,
        "Connection {connection_index}: Destination IP mismatch"
    );

    assert_eq!(
        actual.destination.port, expected.destination.port,
        "Connection {connection_index}: Destination port mismatch"
    );

    let expected_version = match expected.tls.version.as_str() {
        "V1_3" => TlsVersion::V1_3,
        "V1_2" => TlsVersion::V1_2,
        "V1_1" => TlsVersion::V1_1,
        "V1_0" => TlsVersion::V1_0,
        _ => panic!("Unknown TLS version: {}", expected.tls.version),
    };

    assert_eq!(
        actual.sig.version, expected_version,
        "Connection {connection_index}: TLS version mismatch"
    );

    assert_eq!(
        actual.sig.sni,
        Some(expected.tls.sni.clone()),
        "Connection {connection_index}: SNI mismatch"
    );

    assert_eq!(
        actual.sig.alpn,
        Some(expected.tls.alpn.clone()),
        "Connection {connection_index}: ALPN mismatch"
    );

    assert_eq!(
        actual.sig.cipher_suites.len(),
        expected.tls.cipher_suites_count,
        "Connection {connection_index}: Cipher suites count mismatch"
    );

    assert_eq!(
        actual.sig.extensions.len(),
        expected.tls.extensions_count,
        "Connection {connection_index}: Extensions count mismatch"
    );

    assert_eq!(
        !actual.sig.signature_algorithms.is_empty(),
        expected.tls.has_signature_algorithms,
        "Connection {connection_index}: Signature algorithms presence mismatch"
    );

    // Elliptic curves presence
    assert_eq!(
        !actual.sig.elliptic_curves.is_empty(),
        expected.tls.has_elliptic_curves,
        "Connection {connection_index}: Elliptic curves presence mismatch"
    );

    assert_eq!(
        actual.sig.ja4.full.to_string(),
        expected.tls.ja4.full,
        "Connection {connection_index}: JA4 full fingerprint mismatch"
    );

    assert_eq!(
        actual.sig.ja4.ja4_a, expected.tls.ja4.ja4_a,
        "Connection {connection_index}: JA4_a mismatch"
    );

    assert_eq!(
        actual.sig.ja4.ja4_b, expected.tls.ja4.ja4_b,
        "Connection {connection_index}: JA4_b mismatch"
    );

    assert_eq!(
        actual.sig.ja4.ja4_c, expected.tls.ja4.ja4_c,
        "Connection {connection_index}: JA4_c mismatch"
    );

    assert_eq!(
        actual.sig.ja4.raw.to_string(),
        expected.tls.ja4.raw,
        "Connection {connection_index}: JA4 raw mismatch"
    );

    assert_eq!(
        actual.sig.ja4_original.full.to_string(),
        expected.tls.ja4_original.full,
        "Connection {connection_index}: JA4 original full fingerprint mismatch"
    );

    assert_eq!(
        actual.sig.ja4_original.ja4_a, expected.tls.ja4_original.ja4_a,
        "Connection {connection_index}: JA4 original ja4_a mismatch"
    );

    assert_eq!(
        actual.sig.ja4_original.ja4_b, expected.tls.ja4_original.ja4_b,
        "Connection {connection_index}: JA4 original ja4_b mismatch"
    );

    assert_eq!(
        actual.sig.ja4_original.ja4_c, expected.tls.ja4_original.ja4_c,
        "Connection {connection_index}: JA4 original ja4_c mismatch"
    );

    assert_eq!(
        actual.sig.ja4_original.raw.to_string(),
        expected.tls.ja4_original.raw,
        "Connection {connection_index}: JA4 original raw mismatch"
    );
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
fn test_golden_pcap_snapshots() {
    let golden_test_cases = [
        "tls12.pcap",
        "tls-alpn-h2.pcap", // IPv6 TLS 1.2 with NULL datalink format
    ];

    for pcap_file in golden_test_cases {
        println!("Running golden test for: {pcap_file}");
        test_pcap_with_snapshot(pcap_file);
    }
}
