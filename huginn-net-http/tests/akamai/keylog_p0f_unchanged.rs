//! Decrypted bytes only feed the Akamai fingerprint: p0f HTTP outputs are identical with and
//! without a key log (FR-008a).

use super::pcap_util::{keys_config, pcap_dir, run_all, snapshot};
use huginn_net_http::HttpAnalysisResult;

fn p0f_text(results: &[HttpAnalysisResult]) -> Vec<String> {
    let mut out = Vec::new();
    for r in results {
        if let Some(req) = &r.http_request {
            out.push(req.to_string());
        }
        if let Some(resp) = &r.http_response {
            out.push(resp.to_string());
        }
    }
    out
}

#[test]
fn p0f_outputs_do_not_change_with_a_key_log() {
    let keyed = snapshot("akamai-tls13-aes128-chrome");
    for pcap in [
        "http-simple-get.pcap",
        "akamai-tls13-aes128-chrome.pcap",
        "akamai-tls13-http11.pcap",
    ] {
        let path = pcap_dir().join(pcap);
        let (plain, _) = run_all(&path, None);
        let (with_keys, _) = run_all(&path, Some(keys_config(&keyed)));
        assert_eq!(p0f_text(&plain), p0f_text(&with_keys), "{pcap}");
    }
}
