#![cfg(feature = "db")]

use std::path::Path;
use std::sync::mpsc;

use huginn_net::{Database, HuginnNet, TcpMatchQuality};
use huginn_net_http::output::MatchQuality as HttpMatchQuality;

const TCP_PCAP_PATH: &str = "../pcap/macos_tcp_flags.pcap";
const HTTP_PCAP_PATH: &str = "../pcap/http-simple-get.pcap";

fn collect_results(pcap_path: &str) -> Vec<huginn_net::output::FingerprintResult> {
    assert!(Path::new(pcap_path).exists(), "PCAP file must exist: {pcap_path}");

    let database = match Database::load_default() {
        Ok(db) => db,
        Err(e) => panic!("load embedded p0f database: {e}"),
    };
    let mut analyzer = match HuginnNet::new(Some(&database), 1000, None) {
        Ok(analyzer) => analyzer,
        Err(e) => panic!("construct HuginnNet with default config: {e}"),
    };

    let (sender, receiver) = mpsc::channel();
    if let Err(e) = analyzer.analyze_pcap(pcap_path, sender, None) {
        panic!("analyze pcap {pcap_path}: {e}");
    }

    let mut out = Vec::new();
    for result in receiver {
        out.push(result);
    }
    out
}

#[test]
fn e2e_macos_tcp_flags_yields_tcp_matches() {
    let results = collect_results(TCP_PCAP_PATH);

    // Same expectation as the Layer 1 (raw extraction) golden test. If the
    // umbrella ever stops producing connections for known-good PCAPs we want
    // to find out here as well as in the per-crate tests.
    let meaningful = results
        .iter()
        .filter(|r| {
            r.tcp_syn.is_some()
                || r.tcp_syn_ack.is_some()
                || r.tcp_mtu.is_some()
                || r.tcp_client_uptime.is_some()
                || r.tcp_server_uptime.is_some()
        })
        .count();
    assert!(
        meaningful > 0,
        "expected at least one TCP-bearing connection in {TCP_PCAP_PATH}",
    );

    // The first connection of `macos_tcp_flags.pcap` carries an MTU of 1504,
    // which is *not* one of the canonical p0f.fp link entries, so a healthy
    // pipeline must surface it as `NotMatched` (matcher ran, no entry hit).
    // We use this as a positive signal that the matcher is wired in (i.e.
    // never falls back to `Disabled` when a database is present).
    let mtu_count = results.iter().filter_map(|r| r.tcp_mtu.as_ref()).count();
    assert!(mtu_count > 0, "expected at least one MTU observation");

    // No result should silently regress to `Disabled` quality when we did
    // pass a real database in.
    for r in &results {
        if let Some(syn) = &r.tcp_syn {
            assert!(
                !matches!(syn.os_matched.quality, TcpMatchQuality::Disabled),
                "SYN OS matched quality must not be Disabled when database is provided",
            );
        }
        if let Some(syn_ack) = &r.tcp_syn_ack {
            assert!(
                !matches!(syn_ack.os_matched.quality, TcpMatchQuality::Disabled),
                "SYN-ACK OS matched quality must not be Disabled when database is provided",
            );
        }
        if let Some(mtu) = &r.tcp_mtu {
            assert!(
                !matches!(mtu.link.quality, TcpMatchQuality::Disabled),
                "MTU link quality must not be Disabled when database is provided",
            );
        }
    }
}

#[test]
fn e2e_http_simple_get_yields_http_matches() {
    let results = collect_results(HTTP_PCAP_PATH);

    let http_results: Vec<_> = results
        .iter()
        .filter(|r| r.http_request.is_some() || r.http_response.is_some())
        .collect();
    assert!(
        !http_results.is_empty(),
        "expected at least one HTTP-bearing connection in {HTTP_PCAP_PATH}",
    );

    // No HTTP result should silently fall back to `Disabled` quality when a
    // database was provided.
    for r in &http_results {
        if let Some(req) = &r.http_request {
            assert!(
                !matches!(req.browser_matched.quality, HttpMatchQuality::Disabled),
                "HTTP request browser quality must not be Disabled when database is provided",
            );
        }
        if let Some(resp) = &r.http_response {
            assert!(
                !matches!(resp.web_server_matched.quality, HttpMatchQuality::Disabled),
                "HTTP response web_server quality must not be Disabled when database is provided",
            );
        }
    }
}
