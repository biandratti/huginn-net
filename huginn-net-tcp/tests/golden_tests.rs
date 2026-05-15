//! Golden tests for raw TCP fingerprint extraction.
//!
//! **This is the "Layer 1" golden test**: it only checks that
//! `huginn-net-tcp` extracts the same raw signature / MTU / uptime values
//! from a given PCAP that it always has *without* any database matching.
//!
//! The matching half of what used to be in this file lives in
//! `huginn-net-db/tests/golden_tcp_matching.rs`, where each captured
//! `raw_signature` is fed through `TcpSignatureMatcher` and the resulting
//! OS/quality is verified.

use huginn_net_tcp::{HuginnNetTcp, HuginnNetTcpError, TcpAnalysisResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::mpsc;

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
    tcp_analysis: TcpAnalysisSnapshot,
}

#[derive(Debug, Deserialize, Serialize)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
struct TcpAnalysisSnapshot {
    syn: Option<SynSnapshot>,
    syn_ack: Option<SynAckSnapshot>,
    mtu: Option<MtuSnapshot>,
    client_uptime: Option<UptimeSnapshot>,
    server_uptime: Option<UptimeSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SynSnapshot {
    raw_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SynAckSnapshot {
    raw_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct MtuSnapshot {
    raw_mtu: u16,
}

#[derive(Debug, Deserialize, Serialize)]
struct UptimeSnapshot {
    uptime_days: u32,
    uptime_hours: u32,
    uptime_minutes: u32,
    modulo_days: u32,
    raw_frequency: f64,
}

fn load_snapshot(pcap_file: &str) -> PcapSnapshot {
    let snapshot_path = format!("tests/snapshots/{pcap_file}.json");
    let snapshot_content = fs::read_to_string(&snapshot_path)
        .unwrap_or_else(|_| panic!("Failed to read snapshot file: {snapshot_path}"));

    serde_json::from_str(&snapshot_content)
        .unwrap_or_else(|e| panic!("Failed to parse snapshot JSON: {e}"))
}

fn analyze_pcap_file(pcap_path: &str) -> Result<Vec<TcpAnalysisResult>, HuginnNetTcpError> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");

    let mut analyzer = HuginnNetTcp::new(1000)?;
    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();

    analyzer.analyze_pcap(pcap_path, sender, None)?;

    let mut results = Vec::new();
    for tcp_output in receiver {
        if has_meaningful_tcp_data(&tcp_output) {
            results.push(tcp_output);
        }
    }

    Ok(results)
}

/// Check if a TCP analysis result has meaningful data for golden tests.
fn has_meaningful_tcp_data(result: &TcpAnalysisResult) -> bool {
    result.syn.is_some()
        || result.syn_ack.is_some()
        || result.mtu.is_some()
        || result.client_uptime.is_some()
        || result.server_uptime.is_some()
}

fn assert_connection_matches_snapshot(
    actual: &TcpAnalysisResult,
    expected: &ConnectionSnapshot,
    connection_index: usize,
) {
    if let (Some(actual_syn), Some(expected_syn)) = (&actual.syn, &expected.tcp_analysis.syn) {
        assert_eq!(
            actual_syn.source.ip.to_string(),
            expected.source.ip,
            "Connection {connection_index}: SYN source IP mismatch"
        );
        assert_eq!(
            actual_syn.source.port, expected.source.port,
            "Connection {connection_index}: SYN source port mismatch"
        );
        assert_eq!(
            actual_syn.destination.ip.to_string(),
            expected.destination.ip,
            "Connection {connection_index}: SYN destination IP mismatch"
        );
        assert_eq!(
            actual_syn.destination.port, expected.destination.port,
            "Connection {connection_index}: SYN destination port mismatch"
        );
        assert_eq!(
            actual_syn.sig.to_string(),
            expected_syn.raw_signature,
            "Connection {connection_index}: SYN raw signature mismatch"
        );
    }

    if let (Some(actual_syn_ack), Some(expected_syn_ack)) =
        (&actual.syn_ack, &expected.tcp_analysis.syn_ack)
    {
        assert_eq!(
            actual_syn_ack.source.ip.to_string(),
            expected.source.ip,
            "Connection {connection_index}: SYN-ACK source IP mismatch"
        );
        assert_eq!(
            actual_syn_ack.source.port, expected.source.port,
            "Connection {connection_index}: SYN-ACK source port mismatch"
        );
        assert_eq!(
            actual_syn_ack.sig.to_string(),
            expected_syn_ack.raw_signature,
            "Connection {connection_index}: SYN-ACK raw signature mismatch"
        );
    }

    if let (Some(actual_mtu), Some(expected_mtu)) = (&actual.mtu, &expected.tcp_analysis.mtu) {
        assert_eq!(
            actual_mtu.mtu, expected_mtu.raw_mtu,
            "Connection {connection_index}: MTU raw value mismatch"
        );
    }

    if let (Some(actual_uptime), Some(expected_uptime)) =
        (&actual.client_uptime, &expected.tcp_analysis.client_uptime)
    {
        assert_eq!(
            actual_uptime.freq, expected_uptime.raw_frequency,
            "Connection {connection_index}: Client uptime raw frequency mismatch"
        );
        assert_eq!(
            actual_uptime.days, expected_uptime.uptime_days,
            "Connection {connection_index}: Client uptime days mismatch"
        );
    }

    if let (Some(actual_uptime), Some(expected_uptime)) =
        (&actual.server_uptime, &expected.tcp_analysis.server_uptime)
    {
        assert_eq!(
            actual_uptime.freq, expected_uptime.raw_frequency,
            "Connection {connection_index}: Server uptime raw frequency mismatch"
        );
        assert_eq!(
            actual_uptime.days, expected_uptime.uptime_days,
            "Connection {connection_index}: Server uptime days mismatch"
        );
    }
}

/// Golden test: compares PCAP analysis output against known-good JSON snapshots.
fn test_pcap_with_snapshot(pcap_file: &str) {
    let snapshot = load_snapshot(pcap_file);
    let results = analyze_pcap_file(&snapshot.pcap_path)
        .unwrap_or_else(|e| panic!("Failed to analyze PCAP file: {e}"));

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
fn test_golden_tcp_snapshots() {
    let golden_test_cases = [
        "macos_tcp_flags.pcap",
        // Add more PCAP files here as golden tests:
        // "linux_syn.pcap",
        // "windows_tcp.pcap",
    ];

    for pcap_file in golden_test_cases {
        println!("Running golden test for: {pcap_file}");
        test_pcap_with_snapshot(pcap_file);
    }
}

#[test]
fn test_macos_tcp_flags_pcap_snapshot() {
    test_pcap_with_snapshot("macos_tcp_flags.pcap");
}
