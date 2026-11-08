//! Malformed or hostile input never panics, never produces a result and is counted.

use super::pcap_util::{
    client_data_indices, keys_config, keys_path, payload, pcap_dir, read_frames, run, scratch_dir,
    seq, server_data_indices, snapshot, with_payload, write_frames,
};
use huginn_net_http::{KeylogConfig, KeylogSource, KeylogStats};
use std::path::Path;

fn run_variant(
    dir: &Path,
    fixture: &str,
    label: &str,
    edit: impl Fn(&mut Vec<Vec<u8>>),
) -> KeylogStats {
    let snap = snapshot(fixture);
    let mut frames = read_frames(&pcap_dir().join(&snap.pcap));
    edit(&mut frames);
    let path = dir.join(format!("{label}.pcap"));
    write_frames(&frames, &path);
    let (outputs, stats) = run(&path, Some(keys_config(&snap)));
    assert!(outputs.is_empty(), "{label}: no fingerprint expected, got {outputs:?}");
    stats
}

fn edit_payload(frames: &mut [Vec<u8>], index: usize, edit: impl Fn(&mut Vec<u8>)) {
    let mut body = payload(&frames[index]).to_vec();
    edit(&mut body);
    frames[index] = with_payload(&frames[index], seq(&frames[index]), &body);
}

#[test]
fn malformed_tls_input_is_counted_and_never_fingerprinted() {
    let dir = scratch_dir("malformed");
    let tls13 = "akamai-tls13-aes128-chrome";

    // Truncated ClientHello: the rest of the client stream is never contiguous.
    let stats = run_variant(&dir, tls13, "truncated-client-hello", |frames| {
        let first = client_data_indices(frames)[0];
        edit_payload(frames, first, |b| b.truncate(20));
    });
    assert_eq!(stats.reassembly, 1, "{stats:?}");

    // One flipped bit in the last client record: authentication fails.
    let stats = run_variant(&dir, tls13, "flipped-bit", |frames| {
        let last = *client_data_indices(frames)
            .last()
            .unwrap_or_else(|| panic!("no data"));
        edit_payload(frames, last, |b| {
            if let Some(byte) = b.last_mut() {
                *byte ^= 0x01;
            }
        });
    });
    assert_eq!(stats.auth_failed, 1, "{stats:?}");

    // Record length 0xFFFF exceeds the TLS maximum.
    let stats = run_variant(&dir, tls13, "oversized-record", |frames| {
        let third = client_data_indices(frames)[2];
        edit_payload(frames, third, |b| {
            b[3] = 0xFF;
            b[4] = 0xFF;
        });
    });
    assert_eq!(stats.malformed, 1, "{stats:?}");

    // A client segment that never arrives leaves a permanent gap.
    let stats = run_variant(&dir, tls13, "permanent-gap", |frames| {
        let third = client_data_indices(frames)[2];
        frames.remove(third);
    });
    assert_eq!(stats.reassembly, 1, "{stats:?}");

    // A segment far beyond the buffer limit.
    let stats = run_variant(&dir, tls13, "far-ahead", |frames| {
        let last = *client_data_indices(frames)
            .last()
            .unwrap_or_else(|| panic!("no data"));
        let far = seq(&frames[last]).wrapping_add(10_000_000);
        let injected = with_payload(&frames[last], far, b"junk");
        frames.insert(last, injected);
    });
    assert_eq!(stats.reassembly, 1, "{stats:?}");

    // Unsupported cipher suite: patch the TLS 1.2 ServerHello to TLS_RSA_WITH_AES_128_CBC_SHA.
    let stats = run_variant(&dir, "akamai-tls12-aes128-curl", "unsupported-suite", |frames| {
        let first = server_data_indices(frames)[0];
        edit_payload(frames, first, |b| {
            // record header (5) + handshake header (4) + version (2) + random (32)
            let sid_len = usize::from(b[43]);
            let at = 44 + sid_len;
            b[at] = 0x00;
            b[at + 1] = 0x2F;
        });
    });
    assert_eq!(stats.unsupported, 1, "{stats:?}");

    // Capture starting mid-connection: no ClientHello, so nothing is tracked.
    let stats = run_variant(&dir, tls13, "mid-stream", |frames| {
        let first = client_data_indices(frames)[0];
        frames.drain(..=first);
    });
    assert_eq!(
        stats,
        KeylogStats {
            keylog_lines_accepted: stats.keylog_lines_accepted,
            ..KeylogStats::default()
        }
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_key_log_lines_are_rejected_and_counted() {
    let snap = snapshot("akamai-tls13-aes128-chrome");
    let dir = scratch_dir("bad-keylines");
    let random = "aa".repeat(32);
    let mut content = std::fs::read(keys_path(&snap)).unwrap_or_else(|e| panic!("keys: {e}"));
    for bad in [
        format!("NOT_A_LABEL {random} {}\n", "bb".repeat(32)),
        format!("CLIENT_RANDOM {random} abc\n"),
        format!("CLIENT_RANDOM {random} {}\n", "bb".repeat(32)),
        format!("CLIENT_RANDOM {random} {}\n", "b".repeat(600)),
        format!("CLIENT_RANDOM {random}\n"),
    ] {
        content.extend_from_slice(bad.as_bytes());
    }
    content.extend_from_slice(b"CLIENT_RANDOM \xff\xfe\n");
    let path = dir.join("bad.keys");
    std::fs::write(&path, content).unwrap_or_else(|e| panic!("write: {e}"));

    let (outputs, stats) =
        run(&pcap_dir().join(&snap.pcap), Some(KeylogConfig::new(KeylogSource::File(path))));
    assert_eq!(outputs.len(), 1, "valid lines still work next to bad ones");
    assert_eq!(stats.keylog_lines_rejected, 6);
    let _ = std::fs::remove_dir_all(&dir);
}
