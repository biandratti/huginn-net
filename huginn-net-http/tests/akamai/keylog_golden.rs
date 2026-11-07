//! End-to-end: captured HTTP/2-over-TLS + key log → one Akamai result per connection.
//!
//! Fixtures come from `scripts/gen-akamai-fixtures.py` (real OpenSSL handshakes, synthetic
//! client profiles); the expected fingerprints are computed by the generator from the frames
//! it sent, independently of huginn's decryption code.

use huginn_net_http::{
    AkamaiOutput, AkamaiTransport, HttpAnalysisResult, HuginnNetHttp, KeylogConfig, KeylogSource,
    KeylogStats, TlsVersion,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

#[derive(Deserialize)]
struct Snapshot {
    pcap: String,
    keys: Option<String>,
    connections: Vec<Expected>,
    not_http2: u64,
}

#[derive(Deserialize)]
struct Expected {
    source: Endpoint,
    destination: Endpoint,
    tls_version: Option<String>,
    cipher_suite: Option<u16>,
    fingerprint: String,
    hash: String,
}

#[derive(Deserialize)]
struct Endpoint {
    ip: String,
    port: u16,
}

fn snapshot(name: &str) -> Snapshot {
    let path = format!("tests/snapshots/{name}.pcap.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn pcap_dir() -> PathBuf {
    Path::new("..").join("pcap")
}

fn run(pcap: &str, keylog: Option<KeylogConfig>) -> (Vec<AkamaiOutput>, KeylogStats) {
    let mut analyzer = HuginnNetHttp::new(1000);
    if let Some(config) = keylog {
        analyzer = analyzer
            .with_keylog(config)
            .unwrap_or_else(|e| panic!("with_keylog: {e}"));
    }
    let (tx, rx) = mpsc::channel::<HttpAnalysisResult>();
    let path = pcap_dir().join(pcap);
    let path = path.to_str().unwrap_or_else(|| panic!("non-UTF-8 path"));
    analyzer
        .analyze_pcap(path, tx, None)
        .unwrap_or_else(|e| panic!("analyze_pcap: {e}"));
    let outputs = rx.try_iter().filter_map(|r| r.http_akamai).collect();
    (outputs, analyzer.keylog_stats())
}

fn keys_config(snap: &Snapshot) -> KeylogConfig {
    let keys = snap
        .keys
        .as_deref()
        .unwrap_or_else(|| panic!("fixture has no key log"));
    KeylogConfig::new(KeylogSource::File(pcap_dir().join(keys)))
}

fn assert_matches(outputs: &[AkamaiOutput], snap: &Snapshot) {
    assert_eq!(
        outputs.len(),
        snap.connections.len(),
        "one result per HTTP/2 connection in {}",
        snap.pcap
    );
    for want in &snap.connections {
        let Some(got) = outputs.iter().find(|o| o.source.port == want.source.port) else {
            panic!("no result for client port {} in {}", want.source.port, snap.pcap);
        };
        assert_eq!(got.source.ip.to_string(), want.source.ip);
        assert_eq!(got.destination.ip.to_string(), want.destination.ip);
        assert_eq!(got.destination.port, want.destination.port);
        assert_eq!(got.fingerprint.fingerprint, want.fingerprint, "{}", snap.pcap);
        assert_eq!(got.fingerprint.hash, want.hash, "{}", snap.pcap);
        let want_version = match want.tls_version.as_deref() {
            Some("tls1.3") => TlsVersion::Tls13,
            Some("tls1.2") => TlsVersion::Tls12,
            other => panic!("unexpected tls_version {other:?}"),
        };
        assert_eq!(
            got.transport,
            AkamaiTransport::TlsDecrypted {
                version: want_version,
                cipher_suite: want
                    .cipher_suite
                    .unwrap_or_else(|| panic!("missing cipher_suite")),
            }
        );
    }
}

const HTTP2_FIXTURES: &[&str] = &[
    "akamai-tls13-aes128-chrome",
    "akamai-tls13-aes256-firefox",
    "akamai-tls13-chacha-curl",
    "akamai-tls12-aes128-curl",
    "akamai-tls12-aes256-prio",
    "akamai-tls12-chacha-chrome",
    "akamai-tls13-resume",
    "akamai-tls12-resume",
];

#[test]
fn every_suite_and_version_matches_the_snapshot() {
    for name in HTTP2_FIXTURES {
        let snap = snapshot(name);
        let (outputs, stats) = run(&snap.pcap, Some(keys_config(&snap)));
        assert_matches(&outputs, &snap);
        assert_eq!(stats.decrypted, u64::try_from(snap.connections.len()).unwrap_or(0), "{name}");
        assert_eq!(stats.auth_failed + stats.malformed + stats.reassembly, 0, "{name}: {stats:?}");
    }
}

#[test]
fn without_a_key_log_there_are_no_akamai_results() {
    let snap = snapshot("akamai-tls13-aes128-chrome");
    let (outputs, _) = run(&snap.pcap, None);
    assert!(outputs.is_empty());
}

#[test]
fn connections_missing_from_the_key_log_count_as_no_secret() {
    let snap = snapshot("akamai-tls13-resume");
    let keys = std::fs::read_to_string(pcap_dir().join(snap.keys.as_deref().unwrap_or_default()))
        .unwrap_or_else(|e| panic!("read keys: {e}"));
    // Keep only the first connection's secrets (first client random seen).
    let first_random = keys
        .lines()
        .find_map(|l| l.split_whitespace().nth(1).filter(|_| !l.starts_with('#')))
        .unwrap_or_else(|| panic!("no key line"))
        .to_string();
    let partial: String = keys
        .lines()
        .filter(|l| l.contains(&first_random))
        .map(|l| format!("{l}\n"))
        .collect();
    let dir = std::env::temp_dir().join(format!("huginn-partial-keys-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("partial.keys");
    std::fs::write(&path, partial).unwrap_or_else(|e| panic!("write: {e}"));

    let (outputs, stats) = run(&snap.pcap, Some(KeylogConfig::new(KeylogSource::File(path))));
    assert_eq!(outputs.len(), 1, "only the keyed connection is fingerprinted");
    assert_eq!(stats.decrypted, 1);
    assert_eq!(stats.no_secret, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tls13_without_handshake_secret_uses_trial_alignment() {
    let snap = snapshot("akamai-tls13-aes256-firefox");
    let keys = std::fs::read_to_string(pcap_dir().join(snap.keys.as_deref().unwrap_or_default()))
        .unwrap_or_else(|e| panic!("read keys: {e}"));
    let app_only: String = keys
        .lines()
        .filter(|l| l.starts_with("CLIENT_TRAFFIC_SECRET_0"))
        .map(|l| format!("{l}\n"))
        .collect();
    let dir = std::env::temp_dir().join(format!("huginn-app-only-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("app.keys");
    std::fs::write(&path, app_only).unwrap_or_else(|e| panic!("write: {e}"));
    let (outputs, _) = run(&snap.pcap, Some(KeylogConfig::new(KeylogSource::File(path))));
    assert_matches(&outputs, &snap);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn http11_over_tls_is_not_http2() {
    let snap = snapshot("akamai-tls13-http11");
    let (outputs, stats) = run(&snap.pcap, Some(keys_config(&snap)));
    assert!(outputs.is_empty());
    assert_eq!(stats.not_http2, snap.not_http2);
}
