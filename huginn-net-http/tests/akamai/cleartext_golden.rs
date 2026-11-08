//! End-to-end: cleartext HTTP/2 (h2c) captures -> one Akamai result per connection.
//!
//! Fixtures come from `scripts/gen-akamai-fixtures.py`; the expected fingerprints are
//! computed by the generator from the frames it sent.

use super::pcap_util::{
    Snapshot, akamai_plain, client_data_indices, payload, pcap_dir, read_frames, scratch_dir, seq,
    snapshot, with_payload, write_frames,
};
use huginn_net_http::{AkamaiOutput, AkamaiTransport};
use std::path::PathBuf;

const PRIOR: &str = "akamai-h2c-prior";
const UPGRADE: &str = "akamai-h2c-upgrade";

fn assert_cleartext_matches(outputs: &[AkamaiOutput], snap: &Snapshot) {
    assert_eq!(
        outputs.len(),
        snap.connections.len(),
        "one result per connection in {}",
        snap.pcap
    );
    for want in &snap.connections {
        let Some(got) = outputs.iter().find(|o| o.source.port == want.source.port) else {
            panic!("no result for client port {} in {}", want.source.port, snap.pcap);
        };
        assert_eq!(got.source.ip.to_string(), want.source.ip);
        assert_eq!(got.destination.ip.to_string(), want.destination.ip);
        assert_eq!(got.destination.port, want.destination.port);
        assert_eq!(got.transport, AkamaiTransport::Cleartext);
        assert_eq!(got.fingerprint.fingerprint, want.fingerprint, "{}", snap.pcap);
    }
}

fn fixture(name: &str) -> (Snapshot, PathBuf) {
    let snap = snapshot(name);
    let path = pcap_dir().join(&snap.pcap);
    (snap, path)
}

/// Writes `frames` to a scratch pcap and returns the Akamai results.
fn run_frames(test: &str, frames: &[Vec<u8>]) -> Vec<AkamaiOutput> {
    let path = scratch_dir(test).join("capture.pcap");
    write_frames(frames, &path);
    akamai_plain(&path, false)
}

#[test]
fn cleartext_prior_knowledge_matches_the_snapshot() {
    let (snap, path) = fixture(PRIOR);
    assert_cleartext_matches(&akamai_plain(&path, false), &snap);
}

#[test]
fn cleartext_upgrade_matches_the_snapshot() {
    let (snap, path) = fixture(UPGRADE);
    assert_cleartext_matches(&akamai_plain(&path, false), &snap);
}

#[test]
fn cleartext_parallel_mode_matches_the_snapshot() {
    for name in [PRIOR, UPGRADE] {
        let (snap, path) = fixture(name);
        assert_cleartext_matches(&akamai_plain(&path, true), &snap);
    }
}

#[test]
fn cleartext_reordered_and_duplicated_segments_give_the_same_result() {
    for name in [PRIOR, UPGRADE] {
        let (snap, path) = fixture(name);
        let mut frames = read_frames(&path);
        let data = client_data_indices(&frames);
        let (Some(&first), Some(&last)) = (data.first(), data.last()) else {
            panic!("{name}: no client data");
        };
        // Last client segment first, then every client segment again.
        frames.swap(first, last);
        let again: Vec<Vec<u8>> = data.iter().map(|&i| frames[i].clone()).collect();
        let fin = frames.len().saturating_sub(3);
        frames.splice(fin..fin, again);
        assert_cleartext_matches(&run_frames(&format!("h2c-reorder-{name}"), &frames), &snap);
    }
}

#[test]
fn cleartext_tiny_segments_give_the_same_result() {
    for name in [PRIOR, UPGRADE] {
        let (snap, path) = fixture(name);
        let frames = read_frames(&path);
        let data = client_data_indices(&frames);
        let mut out = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            if !data.contains(&i) {
                out.push(frame.clone());
                continue;
            }
            let base = seq(frame);
            for (n, chunk) in payload(frame).chunks(7).enumerate() {
                let offset = u32::try_from(n.saturating_mul(7)).unwrap_or(u32::MAX);
                out.push(with_payload(frame, base.wrapping_add(offset), chunk));
            }
        }
        assert_cleartext_matches(&run_frames(&format!("h2c-tiny-{name}"), &out), &snap);
    }
}

/// The upgrade fixture with every client byte replaced by `client` in one segment.
fn upgrade_with_client_bytes(client: &[u8]) -> Vec<Vec<u8>> {
    let (_, path) = fixture(UPGRADE);
    let frames = read_frames(&path);
    let data = client_data_indices(&frames);
    let Some(&first) = data.first() else {
        panic!("upgrade fixture has no client data");
    };
    let mut out = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        if i == first {
            out.push(with_payload(frame, seq(frame), client));
        } else if !data.contains(&i) {
            out.push(frame.clone());
        }
    }
    out
}

/// The HTTP/2 client bytes of the upgrade fixture (preface onwards).
fn upgrade_h2_bytes() -> Vec<u8> {
    let (_, path) = fixture(UPGRADE);
    let frames = read_frames(&path);
    client_data_indices(&frames)
        .into_iter()
        .skip(1)
        .flat_map(|i| payload(&frames[i]).to_vec())
        .collect()
}

#[test]
fn cleartext_upgrade_request_with_a_body_is_skipped() {
    let (snap, _) = fixture(UPGRADE);
    let mut client =
        b"POST /form HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\n\
        upgrade: websocket, H2C\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
        Content-Length: 5\r\n\r\nhello"
            .to_vec();
    client.extend_from_slice(&upgrade_h2_bytes());
    let outputs = run_frames("h2c-upgrade-body", &upgrade_with_client_bytes(&client));
    assert_cleartext_matches(&outputs, &snap);
}

#[test]
fn cleartext_http1_without_upgrade_gives_no_result() {
    let mut client = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
    client.extend_from_slice(&upgrade_h2_bytes());
    assert!(run_frames("h2c-no-upgrade", &upgrade_with_client_bytes(&client)).is_empty());
}

#[test]
fn cleartext_upgrade_not_followed_by_the_preface_gives_no_result() {
    let client = b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: h2c\r\n\r\n\
        GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert!(run_frames("h2c-no-preface", &upgrade_with_client_bytes(client)).is_empty());
}

#[test]
fn cleartext_tls_capture_gives_no_result_without_a_key_log() {
    let (_, path) = fixture("akamai-tls13-aes128-chrome");
    assert!(akamai_plain(&path, false).is_empty());
}

#[cfg(feature = "p0f-request")]
#[test]
fn cleartext_p0f_request_output_is_still_emitted() {
    use super::pcap_util::run_plain;
    use huginn_net_http::http::Version;
    for (name, version) in [(PRIOR, Version::V20), (UPGRADE, Version::V11)] {
        let (_, path) = fixture(name);
        let results = run_plain(&path, false);
        let requests: Vec<_> = results
            .iter()
            .filter_map(|r| r.http_request.as_ref())
            .collect();
        assert_eq!(requests.len(), 1, "{name}: one p0f request");
        assert_eq!(requests[0].sig.matching.version, version, "{name}");
        assert_eq!(results.iter().filter(|r| r.http_akamai.is_some()).count(), 1, "{name}");
    }
}
