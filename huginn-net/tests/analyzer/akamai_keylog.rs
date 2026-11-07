//! The unified analyzer reports the decrypted Akamai fingerprint next to the TLS result of
//! the same connection (FR-015).

use huginn_net::{AnalysisConfig, FingerprintResult, HuginnNet, KeylogConfig, KeylogSource};
use std::path::Path;
use std::sync::mpsc;

#[test]
fn akamai_result_can_be_correlated_with_the_tls_result() {
    let pcap = Path::new("..")
        .join("pcap")
        .join("akamai-tls13-aes128-chrome.pcap");
    let keys = Path::new("..")
        .join("pcap")
        .join("akamai-tls13-aes128-chrome.keys");
    let expected = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

    let config = AnalysisConfig { matcher_enabled: false, ..AnalysisConfig::default() };
    let mut analyzer = HuginnNet::new(None, 1000, Some(config))
        .unwrap_or_else(|e| panic!("analyzer: {e}"))
        .with_keylog(KeylogConfig::new(KeylogSource::File(keys)))
        .unwrap_or_else(|e| panic!("with_keylog: {e}"));
    let (tx, rx) = mpsc::channel::<FingerprintResult>();
    let path = pcap.to_str().unwrap_or_else(|| panic!("non UTF-8 path"));
    analyzer
        .analyze_pcap(path, tx, None)
        .unwrap_or_else(|e| panic!("analyze_pcap: {e}"));
    let results: Vec<FingerprintResult> = rx.try_iter().collect();

    let akamai: Vec<_> = results
        .iter()
        .filter_map(|r| r.http_akamai.as_ref())
        .collect();
    assert_eq!(akamai.len(), 1);
    assert_eq!(akamai[0].fingerprint.fingerprint, expected);

    let tls = results
        .iter()
        .filter_map(|r| r.tls_client.as_ref())
        .find(|t| t.source.port == akamai[0].source.port)
        .unwrap_or_else(|| panic!("no TLS result for the same connection"));
    assert_eq!(tls.source.ip, akamai[0].source.ip);
    assert_eq!(tls.destination.ip, akamai[0].destination.ip);
    assert_eq!(tls.destination.port, akamai[0].destination.port);
    assert_eq!(analyzer.keylog_stats().decrypted, 1);
}
