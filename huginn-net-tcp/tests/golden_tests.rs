use huginn_net_db::Database;
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
    uptime: Option<UptimeSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SynSnapshot {
    os_name: Option<String>,
    os_family: Option<String>,
    os_variant: Option<String>,
    quality: String,
    raw_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SynAckSnapshot {
    os_name: Option<String>,
    os_family: Option<String>,
    os_variant: Option<String>,
    quality: String,
    raw_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct MtuSnapshot {
    link_type: String,
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
    assert!(
        Path::new(pcap_path).exists(),
        "PCAP file must exist: {pcap_path}"
    );

    // Load the default database for TCP analysis
    let db = Database::load_default()
        .map_err(|e| HuginnNetTcpError::Parse(format!("Failed to load database: {e}")))?;

    let mut analyzer = HuginnNetTcp::new(Some(&db), 1000)?;
    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();

    let pcap_file_str = pcap_path.to_string();

    // Run analysis in the same thread to avoid lifetime issues
    analyzer.analyze_pcap(&pcap_file_str, sender, None)?;

    let mut results = Vec::new();
    for tcp_output in receiver {
        // Only include results that have meaningful TCP data
        if has_meaningful_tcp_data(&tcp_output) {
            results.push(tcp_output);
        }
    }

    Ok(results)
}

/// Check if a TCP analysis result has meaningful data
fn has_meaningful_tcp_data(result: &TcpAnalysisResult) -> bool {
    result.syn.is_some()
        || result.syn_ack.is_some()
        || result.mtu.is_some()
        || result.uptime.is_some()
}

fn assert_connection_matches_snapshot(
    actual: &TcpAnalysisResult,
    expected: &ConnectionSnapshot,
    connection_index: usize,
) {
    // Check SYN data if present
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

        // Check OS matching
        if let Some(expected_os_name) = &expected_syn.os_name {
            assert!(
                actual_syn.os_matched.os.is_some(),
                "Connection {connection_index}: Expected OS match but found none"
            );
            if let Some(actual_os) = &actual_syn.os_matched.os {
                assert_eq!(
                    actual_os.name, *expected_os_name,
                    "Connection {connection_index}: SYN OS name mismatch"
                );
            }
        }

        assert_eq!(
            format!("{:?}", actual_syn.os_matched.quality),
            expected_syn.quality,
            "Connection {connection_index}: SYN quality mismatch"
        );

        assert_eq!(
            actual_syn.sig.to_string(),
            expected_syn.raw_signature,
            "Connection {connection_index}: SYN raw signature mismatch"
        );
    }

    // Check SYN-ACK data if present
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

        // Check OS matching
        if let Some(expected_os_name) = &expected_syn_ack.os_name {
            assert!(
                actual_syn_ack.os_matched.os.is_some(),
                "Connection {connection_index}: Expected SYN-ACK OS match but found none"
            );
            if let Some(actual_os) = &actual_syn_ack.os_matched.os {
                assert_eq!(
                    actual_os.name, *expected_os_name,
                    "Connection {connection_index}: SYN-ACK OS name mismatch"
                );
            }
        }

        assert_eq!(
            format!("{:?}", actual_syn_ack.os_matched.quality),
            expected_syn_ack.quality,
            "Connection {connection_index}: SYN-ACK quality mismatch"
        );
    }

    // Check MTU data if present
    if let (Some(actual_mtu), Some(expected_mtu)) = (&actual.mtu, &expected.tcp_analysis.mtu) {
        assert_eq!(
            actual_mtu.mtu, expected_mtu.raw_mtu,
            "Connection {connection_index}: MTU raw value mismatch"
        );
    }

    // Check uptime data if present
    if let (Some(actual_uptime), Some(expected_uptime)) =
        (&actual.uptime, &expected.tcp_analysis.uptime)
    {
        assert_eq!(
            actual_uptime.freq, expected_uptime.raw_frequency,
            "Connection {connection_index}: Uptime raw frequency mismatch"
        );
    }
}

/// Golden test: compares PCAP analysis output against known-good JSON snapshots
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
