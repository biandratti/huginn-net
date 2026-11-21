use huginn_net::{Database, HuginnNet, TcpMatchQuality};
use huginn_net_http::output::MatchQuality as HttpMatchQuality;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::mpsc;

use crate::TestResult;

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
    http_request: Option<HttpRequestSnapshot>,
    http_response: Option<HttpResponseSnapshot>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
}

#[derive(Deserialize, Debug)]
struct TcpAnalysisSnapshot {
    syn: Option<SynSnapshot>,
    syn_ack: Option<SynAckSnapshot>,
    mtu: Option<MtuSnapshot>,
    #[allow(dead_code)]
    client_uptime: Option<serde_json::Value>,
    #[allow(dead_code)]
    server_uptime: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct SynSnapshot {
    os_name: String,
    raw_signature: String,
}

#[derive(Deserialize, Debug)]
struct SynAckSnapshot {
    raw_signature: String,
}

#[derive(Deserialize, Debug)]
struct MtuSnapshot {
    raw_mtu: u16,
}

#[derive(Deserialize, Debug)]
struct HttpRequestSnapshot {
    browser: String,
    params: String,
    ua_os: String,
    user_agent: String,
    raw_signature: String,
}

#[derive(Deserialize, Debug)]
struct HttpResponseSnapshot {
    status_code: u16,
    headers_count: usize,
}

fn load_snapshot(name: &str) -> Result<PcapSnapshot, Box<dyn std::error::Error>> {
    let path = format!("tests/snapshots/{name}.json");
    let content =
        fs::read_to_string(&path).map_err(|e| format!("failed to read snapshot {path}: {e}"))?;
    let snapshot = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse snapshot {path}: {e}"))?;
    Ok(snapshot)
}

fn collect_results(
    pcap_path: &str,
) -> Result<Vec<huginn_net::output::FingerprintResult>, Box<dyn std::error::Error>> {
    assert!(Path::new(pcap_path).exists(), "PCAP not found: {pcap_path}");
    let db = Database::load_default().map_err(|e| format!("load embedded p0f database: {e}"))?;
    let mut analyzer =
        HuginnNet::new(Some(&db), 1000, None).map_err(|e| format!("construct HuginnNet: {e}"))?;
    let (tx, rx) = mpsc::channel();
    analyzer
        .analyze_pcap(pcap_path, tx, None)
        .map_err(|e| format!("analyze pcap {pcap_path}: {e}"))?;
    Ok(rx.into_iter().filter(|r| !r.is_empty()).collect())
}

fn endpoint(ip: impl ToString, port: u16) -> EndpointSnapshot {
    EndpointSnapshot { ip: ip.to_string(), port }
}

fn assert_endpoints(
    actual_src: EndpointSnapshot,
    actual_dst: EndpointSnapshot,
    expected: &ConnectionSnapshot,
    ctx: &str,
) {
    assert_eq!(actual_src, expected.source, "{ctx} source");
    assert_eq!(actual_dst, expected.destination, "{ctx} destination");
}

fn assert_connection(
    name: &str,
    idx: usize,
    actual: &huginn_net::output::FingerprintResult,
    expected: &ConnectionSnapshot,
) -> TestResult {
    if let Some(expected_syn) = &expected.tcp_analysis.syn {
        let syn = actual
            .tcp_syn
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected a TCP SYN"))?;
        assert_endpoints(
            endpoint(syn.source.ip, syn.source.port),
            endpoint(syn.destination.ip, syn.destination.port),
            expected,
            &format!("{name}[{idx}]: SYN"),
        );
        let os = syn.os_matched.os.as_ref().ok_or_else(|| {
            format!("{name}[{idx}]: expected a SYN OS match, got {:?}", syn.os_matched.quality)
        })?;
        assert!(
            matches!(syn.os_matched.quality, TcpMatchQuality::Matched { .. }),
            "{name}[{idx}]: SYN quality must be Matched, got {:?}",
            syn.os_matched.quality
        );
        assert_eq!(os.name, expected_syn.os_name, "{name}[{idx}]: SYN OS");
        assert_eq!(
            syn.sig.to_string(),
            expected_syn.raw_signature,
            "{name}[{idx}]: SYN raw_signature"
        );
    }

    if let Some(expected_syn_ack) = &expected.tcp_analysis.syn_ack {
        let syn_ack = actual
            .tcp_syn_ack
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected a TCP SYN+ACK"))?;
        assert_eq!(
            syn_ack.sig.to_string(),
            expected_syn_ack.raw_signature,
            "{name}[{idx}]: SYN+ACK raw_signature"
        );
    }

    if let Some(expected_mtu) = &expected.tcp_analysis.mtu {
        let mtu = actual
            .tcp_mtu
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected MTU"))?;
        assert_eq!(mtu.mtu, expected_mtu.raw_mtu, "{name}[{idx}]: MTU");
    }

    if let Some(expected_req) = &expected.http_request {
        let req = actual
            .http_request
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected an HTTP request"))?;
        assert_endpoints(
            endpoint(req.source.ip, req.source.port),
            endpoint(req.destination.ip, req.destination.port),
            expected,
            &format!("{name}[{idx}]: HTTP"),
        );
        let browser = req
            .browser_matched
            .browser
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected a browser match"))?;
        assert_eq!(browser.name, expected_req.browser, "{name}[{idx}]: browser");
        assert!(
            browser.family.is_none(),
            "{name}[{idx}]: Chrome must be userland (no OS class), got {:?}",
            browser.family
        );
        assert!(
            matches!(req.browser_matched.quality, HttpMatchQuality::Matched(_)),
            "{name}[{idx}]: browser quality must be Matched, got {:?}",
            req.browser_matched.quality
        );
        assert_eq!(req.params.to_string(), expected_req.params, "{name}[{idx}]: params");
        let user_agent = req
            .sig
            .user_agent
            .as_deref()
            .ok_or_else(|| format!("{name}[{idx}]: expected a User-Agent"))?;
        assert_eq!(user_agent, expected_req.user_agent, "{name}[{idx}]: user_agent");
        assert_eq!(req.ua_os.to_string(), expected_req.ua_os, "{name}[{idx}]: ua_os");
        assert_eq!(
            req.sig.to_string(),
            expected_req.raw_signature,
            "{name}[{idx}]: HTTP raw_signature"
        );
    }

    if let Some(expected_resp) = &expected.http_response {
        let resp = actual
            .http_response
            .as_ref()
            .ok_or_else(|| format!("{name}[{idx}]: expected an HTTP response"))?;
        let status_code = resp
            .sig
            .status_code
            .ok_or_else(|| format!("{name}[{idx}]: expected status_code"))?;
        assert_eq!(status_code, expected_resp.status_code, "{name}[{idx}]: status_code");
        assert_eq!(
            resp.sig.headers.len(),
            expected_resp.headers_count,
            "{name}[{idx}]: headers_count"
        );
    }
    Ok(())
}

fn run_golden_test(name: &str) -> TestResult {
    let snapshot = load_snapshot(name)?;
    let results = collect_results(&snapshot.pcap_path)?;

    assert_eq!(
        results.len(),
        snapshot.expected_connections,
        "{name}: expected {} connections, got {}",
        snapshot.expected_connections,
        results.len()
    );

    for (i, (actual, expected)) in results.iter().zip(snapshot.connections.iter()).enumerate() {
        assert_connection(name, i, actual, expected)?;
    }
    Ok(())
}

#[test]
fn test_golden_ua_os_pcap() -> TestResult {
    let cases = ["ua-os-divergent-linux-syn-windows-ua", "ua-os-consistent-linux-syn-linux-ua"];
    for name in cases {
        run_golden_test(name)?;
    }
    Ok(())
}
