//! The unified analyzer reports the Akamai fingerprint of cleartext HTTP/2 (h2c) connections.

use huginn_net::{AkamaiTransport, AnalysisConfig, FingerprintResult, HuginnNet};
use std::path::Path;
use std::sync::mpsc;

fn akamai_results(pcap: &str) -> Vec<huginn_net::AkamaiOutput> {
    let pcap = Path::new("..").join("pcap").join(pcap);
    let config = AnalysisConfig { matcher_enabled: false, ..AnalysisConfig::default() };
    let mut analyzer =
        HuginnNet::new(None, 1000, Some(config)).unwrap_or_else(|e| panic!("analyzer: {e}"));
    let (tx, rx) = mpsc::channel::<FingerprintResult>();
    let path = pcap.to_str().unwrap_or_else(|| panic!("non UTF-8 path"));
    analyzer
        .analyze_pcap(path, tx, None)
        .unwrap_or_else(|e| panic!("analyze_pcap: {e}"));
    rx.try_iter().filter_map(|r| r.http_akamai).collect()
}

#[test]
fn h2c_prior_knowledge_and_upgrade_report_one_cleartext_result() {
    for (pcap, expected) in [
        ("akamai-h2c-prior.pcap", "3:100;4:10485760;2:0|1048510465|0|m,p,s,a"),
        ("akamai-h2c-upgrade.pcap", "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"),
    ] {
        let akamai = akamai_results(pcap);
        assert_eq!(akamai.len(), 1, "{pcap}");
        assert_eq!(akamai[0].transport, AkamaiTransport::Cleartext, "{pcap}");
        assert_eq!(akamai[0].fingerprint.fingerprint, expected, "{pcap}");
        assert_eq!(akamai[0].source.port, 50000, "{pcap}");
    }
}
