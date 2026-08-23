use huginn_net::{Database, HuginnNet, TcpMatchQuality};
use huginn_net_http::output::MatchQuality as HttpMatchQuality;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::mpsc;

#[derive(Deserialize, Debug)]
struct PcapSnapshot {
    pcap_path: String,
    syn_os: String,
    http_request: HttpRequestSnapshot,
}

#[derive(Deserialize, Debug)]
struct HttpRequestSnapshot {
    browser: String,
    params: String,
    ua_os: String,
    user_agent: String,
}

fn load_snapshot(name: &str) -> PcapSnapshot {
    let path = format!("tests/snapshots/{name}.json");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("failed to read snapshot: {path}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse snapshot {path}: {e}"))
}

fn collect_results(pcap_path: &str) -> Vec<huginn_net::output::FingerprintResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP not found: {pcap_path}");
    let db = Database::load_default().unwrap_or_else(|e| panic!("load embedded p0f database: {e}"));
    let mut analyzer = HuginnNet::new(Some(&db), 1000, None)
        .unwrap_or_else(|e| panic!("construct HuginnNet: {e}"));
    let (tx, rx) = mpsc::channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .unwrap_or_else(|e| panic!("analyze pcap {pcap_path}: {e}"));
    rx.into_iter().collect()
}

fn run_golden_test(name: &str) {
    let snapshot = load_snapshot(name);
    let results = collect_results(&snapshot.pcap_path);

    let syn = results
        .iter()
        .find(|r| r.tcp_syn.is_some())
        .and_then(|r| r.tcp_syn.as_ref())
        .unwrap_or_else(|| panic!("{name}: expected a TCP SYN"));
    let os = syn.os_matched.os.as_ref().unwrap_or_else(|| {
        panic!("{name}: expected a SYN OS match, got {:?}", syn.os_matched.quality)
    });
    assert!(
        matches!(syn.os_matched.quality, TcpMatchQuality::Matched { .. }),
        "{name}: SYN quality must be Matched, got {:?}",
        syn.os_matched.quality
    );
    assert_eq!(os.name, snapshot.syn_os, "{name}: SYN OS");

    let req = results
        .iter()
        .find(|r| r.http_request.is_some())
        .and_then(|r| r.http_request.as_ref())
        .unwrap_or_else(|| panic!("{name}: expected an HTTP request"));
    let browser = req
        .browser_matched
        .browser
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: expected a browser match"));
    assert_eq!(browser.name, snapshot.http_request.browser, "{name}: browser");
    assert!(
        browser.family.is_none(),
        "{name}: Chrome must be userland (no OS class), got {:?}",
        browser.family
    );
    assert!(
        matches!(req.browser_matched.quality, HttpMatchQuality::Matched(_)),
        "{name}: browser quality must be Matched, got {:?}",
        req.browser_matched.quality
    );
    assert_eq!(req.params.to_string(), snapshot.http_request.params, "{name}: params");
    assert_eq!(
        req.sig
            .user_agent
            .as_deref()
            .unwrap_or_else(|| panic!("{name}: expected a User-Agent")),
        snapshot.http_request.user_agent,
        "{name}: user_agent"
    );
    assert_eq!(req.ua_os.to_string(), snapshot.http_request.ua_os, "{name}: ua_os");
}

#[test]
fn test_golden_ua_os_pcap() {
    let cases = ["ua-os-divergent-linux-syn-windows-ua", "ua-os-consistent-linux-syn-linux-ua"];
    for name in cases {
        run_golden_test(name);
    }
}
