//! Layer 3 golden test: feed a PCAP through `HuginnNetTcp` with a real
//! `SharedTcpSignatureMatcher` and verify OS identification and MTU matching
//! against known-good JSON snapshots.
//!
//! The snapshots in `tests/snapshots/` extend the Layer 1 shape (raw TCP
//! signatures / MTU) with matcher fields (`os_name`, `os_family`,
//! `os_variant`, `quality`, `link_type`).

#![cfg(feature = "tcp")]

use huginn_net_db::{Database, SharedTcpSignatureMatcher};
use huginn_net_tcp::output::{MatchQuality, TcpAnalysisResult};
use huginn_net_tcp::HuginnNetTcp;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::mpsc;
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
    tcp_analysis: TcpAnalysisSnapshot,
}

#[derive(Deserialize, Debug)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Deserialize, Debug)]
struct TcpAnalysisSnapshot {
    syn: Option<TcpSignalSnapshot>,
    syn_ack: Option<TcpSignalSnapshot>,
    mtu: Option<MtuSnapshot>,
    client_uptime: Option<UptimeSnapshot>,
    server_uptime: Option<UptimeSnapshot>,
}

#[derive(Deserialize, Debug)]
struct TcpSignalSnapshot {
    os_name: Option<String>,
    os_family: Option<String>,
    os_variant: Option<String>,
    quality: Option<String>,
    raw_signature: String,
}

#[derive(Deserialize, Debug)]
struct MtuSnapshot {
    link_type: Option<String>,
    raw_mtu: u16,
}

#[derive(Deserialize, Debug)]
struct UptimeSnapshot {
    uptime_days: u32,
    raw_frequency: f64,
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

fn run_pcap_with_matcher(pcap_path: &str) -> Vec<TcpAnalysisResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP not found: {pcap_path}");

    let db = Database::load_default().unwrap_or_else(|e| panic!("failed to load database: {e}"));
    let matcher = Arc::new(SharedTcpSignatureMatcher::from_database(&db));

    let mut analyzer = HuginnNetTcp::new(1000).with_matcher(matcher);

    let (tx, rx) = mpsc::channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .unwrap_or_else(|e| panic!("PCAP analysis failed: {e}"));

    rx.into_iter()
        .filter(|r| {
            r.syn.is_some()
                || r.syn_ack.is_some()
                || r.mtu.is_some()
                || r.client_uptime.is_some()
                || r.server_uptime.is_some()
        })
        .collect()
}

fn assert_quality(actual: &MatchQuality, expected: &str, ctx: &str) {
    match actual {
        MatchQuality::Matched(q) => {
            let expected_q: f32 = expected
                .strip_prefix("Matched(")
                .and_then(|s| s.strip_suffix(")"))
                .unwrap_or_else(|| panic!("{ctx}: unexpected quality format: {expected}"))
                .parse()
                .unwrap_or_else(|_| panic!("{ctx}: cannot parse quality float: {expected}"));
            assert!(
                (q - expected_q).abs() < 0.01,
                "{ctx}: quality mismatch — expected {expected_q}, got {q}"
            );
        }
        MatchQuality::NotMatched => assert_eq!(expected, "NotMatched", "{ctx}"),
        MatchQuality::Disabled => assert_eq!(expected, "Disabled", "{ctx}"),
    }
}

fn assert_connection(actual: &TcpAnalysisResult, expected: &ConnectionSnapshot, idx: usize) {
    if let (Some(actual_syn), Some(exp_syn)) = (&actual.syn, &expected.tcp_analysis.syn) {
        assert_eq!(
            actual_syn.source.ip.to_string(),
            expected.source.ip,
            "connection {idx}: SYN source IP"
        );
        assert_eq!(
            actual_syn.source.port, expected.source.port,
            "connection {idx}: SYN source port"
        );
        assert_eq!(
            actual_syn.destination.ip.to_string(),
            expected.destination.ip,
            "connection {idx}: SYN destination IP"
        );
        assert_eq!(
            actual_syn.destination.port, expected.destination.port,
            "connection {idx}: SYN destination port"
        );
        assert_eq!(
            actual_syn.sig.to_string(),
            exp_syn.raw_signature,
            "connection {idx}: SYN raw signature"
        );

        if let Some(expected_name) = &exp_syn.os_name {
            let os =
                actual_syn.os_matched.os.as_ref().unwrap_or_else(|| {
                    panic!("connection {idx}: expected OS match for SYN, got None")
                });
            assert_eq!(&os.name, expected_name, "connection {idx}: SYN os_name");
        } else {
            assert!(
                actual_syn.os_matched.os.is_none(),
                "connection {idx}: expected no OS match for SYN, got {:?}",
                actual_syn.os_matched.os.as_ref().map(|os| &os.name)
            );
        }

        if let Some(expected_family) = &exp_syn.os_family {
            let os = actual_syn
                .os_matched
                .os
                .as_ref()
                .unwrap_or_else(|| panic!("connection {idx}: expected OS for SYN family"));
            assert_eq!(
                os.family.as_deref(),
                Some(expected_family.as_str()),
                "connection {idx}: SYN os_family"
            );
        }

        if let Some(expected_variant) = &exp_syn.os_variant {
            let os = actual_syn
                .os_matched
                .os
                .as_ref()
                .unwrap_or_else(|| panic!("connection {idx}: expected OS for SYN variant"));
            assert_eq!(
                os.variant.as_deref(),
                Some(expected_variant.as_str()),
                "connection {idx}: SYN os_variant"
            );
        }

        if let Some(expected_quality) = &exp_syn.quality {
            assert_quality(
                &actual_syn.os_matched.quality,
                expected_quality,
                &format!("connection {idx} SYN"),
            );
        }
    }

    if let (Some(actual_syn_ack), Some(exp_syn_ack)) =
        (&actual.syn_ack, &expected.tcp_analysis.syn_ack)
    {
        assert_eq!(
            actual_syn_ack.source.ip.to_string(),
            expected.source.ip,
            "connection {idx}: SYN-ACK source IP"
        );
        assert_eq!(
            actual_syn_ack.source.port, expected.source.port,
            "connection {idx}: SYN-ACK source port"
        );
        assert_eq!(
            actual_syn_ack.sig.to_string(),
            exp_syn_ack.raw_signature,
            "connection {idx}: SYN-ACK raw signature"
        );

        if let Some(expected_name) = &exp_syn_ack.os_name {
            let os = actual_syn_ack.os_matched.os.as_ref().unwrap_or_else(|| {
                panic!("connection {idx}: expected OS match for SYN-ACK, got None")
            });
            assert_eq!(&os.name, expected_name, "connection {idx}: SYN-ACK os_name");
        } else {
            assert!(
                actual_syn_ack.os_matched.os.is_none(),
                "connection {idx}: expected no OS match for SYN-ACK, got {:?}",
                actual_syn_ack.os_matched.os.as_ref().map(|os| &os.name)
            );
        }

        if let Some(expected_quality) = &exp_syn_ack.quality {
            assert_quality(
                &actual_syn_ack.os_matched.quality,
                expected_quality,
                &format!("connection {idx} SYN-ACK"),
            );
        }
    }

    if let (Some(actual_mtu), Some(exp_mtu)) = (&actual.mtu, &expected.tcp_analysis.mtu) {
        assert_eq!(actual_mtu.mtu, exp_mtu.raw_mtu, "connection {idx}: MTU raw value");

        if let Some(expected_link_type) = &exp_mtu.link_type {
            assert_eq!(
                format!("{:?}", actual_mtu.link),
                *expected_link_type,
                "connection {idx}: MTU link_type"
            );
        }
    }

    if let (Some(actual_uptime), Some(exp_uptime)) =
        (&actual.client_uptime, &expected.tcp_analysis.client_uptime)
    {
        assert_eq!(
            actual_uptime.days, exp_uptime.uptime_days,
            "connection {idx}: client uptime days"
        );
        assert!(
            (actual_uptime.freq - exp_uptime.raw_frequency).abs() < 0.001,
            "connection {idx}: client uptime frequency"
        );
    }

    if let (Some(actual_uptime), Some(exp_uptime)) =
        (&actual.server_uptime, &expected.tcp_analysis.server_uptime)
    {
        assert_eq!(
            actual_uptime.days, exp_uptime.uptime_days,
            "connection {idx}: server uptime days"
        );
        assert!(
            (actual_uptime.freq - exp_uptime.raw_frequency).abs() < 0.001,
            "connection {idx}: server uptime frequency"
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
fn test_golden_tcp_pcap_with_matcher() {
    let cases = [
        "macos_tcp_flags.pcap",
        // add more snapshot names here as pcap files are added
    ];
    for name in cases {
        run_golden_test(name);
    }
}
