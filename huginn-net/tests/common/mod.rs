//! Helpers shared by the integration-test targets of this crate.
//!
//! Each target includes this file with `#[path = "../common/mod.rs"] mod common;`
//! (same pattern as `examples/support`).

use huginn_net::{Database, HuginnNet};
use std::path::Path;
use std::sync::mpsc;

/// Result type for test helpers: errors propagate with `?` and fail the test with a message.
pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Run the full umbrella analyzer over a pcap and collect every emitted result.
pub(crate) fn collect_results(
    pcap_path: &str,
) -> Result<Vec<huginn_net::output::FingerprintResult>, Box<dyn std::error::Error>> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");
    let db = Database::load_default().map_err(|e| format!("load embedded p0f database: {e}"))?;
    let mut analyzer =
        HuginnNet::new(Some(&db), 1000, None).map_err(|e| format!("construct HuginnNet: {e}"))?;
    let (tx, rx) = mpsc::channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .map_err(|e| format!("analyze pcap {pcap_path}: {e}"))?;
    Ok(rx.into_iter().collect())
}
