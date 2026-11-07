//! Reordered, duplicated and split client segments give the same result as the original
//! capture (SC-003).
//!
//! Sessions start at the ClientHello segment, so the reordering keeps the ClientHello first
//! and shuffles the client segments after it.

use super::keylog_golden::{HTTP2_FIXTURES, assert_matches};
use super::pcap_util::{
    client_data_indices, keys_config, payload, pcap_dir, read_frames, run, scratch_dir, seq,
    snapshot, with_payload, write_frames,
};

/// Rewrites a capture into a replay variant.
type Transform = fn(&[Vec<u8>]) -> Vec<Vec<u8>>;

fn client_port(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[34], frame[35]])
}

/// Reverses each connection's client data segments after its ClientHello.
fn reversed_after_client_hello(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let data = client_data_indices(frames);
    let mut ports: Vec<u16> = data.iter().map(|&i| client_port(&frames[i])).collect();
    ports.dedup();
    let mut out = frames.to_vec();
    for port in ports {
        let tail: Vec<usize> = data
            .iter()
            .copied()
            .filter(|&i| client_port(&frames[i]) == port)
            .skip(1)
            .collect();
        let mut reversed = tail.clone();
        reversed.reverse();
        for (slot, source) in tail.iter().zip(reversed.iter()) {
            out[*slot] = frames[*source].clone();
        }
    }
    out
}

fn duplicated(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let data = client_data_indices(frames);
    let mut out = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        out.push(frame.clone());
        if data.contains(&i) {
            out.push(frame.clone());
        }
    }
    out
}

fn split_in_two(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let data = client_data_indices(frames);
    let mut out = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let body = payload(frame);
        if data.contains(&i) && body.len() > 1 {
            let mid = body.len() / 2;
            let second_seq = seq(frame).wrapping_add(u32::try_from(mid).unwrap_or(0));
            out.push(with_payload(frame, seq(frame), &body[..mid]));
            out.push(with_payload(frame, second_seq, &body[mid..]));
        } else {
            out.push(frame.clone());
        }
    }
    out
}

#[test]
fn reordered_duplicated_and_split_segments_give_identical_results() {
    let dir = scratch_dir("replay");
    let variants: [(&str, Transform); 3] = [
        ("reversed", reversed_after_client_hello),
        ("duplicated", duplicated),
        ("split", split_in_two),
    ];
    for name in HTTP2_FIXTURES {
        let snap = snapshot(name);
        let frames = read_frames(&pcap_dir().join(&snap.pcap));
        for (variant, transform) in variants {
            let path = dir.join(format!("{name}-{variant}.pcap"));
            write_frames(&transform(&frames), &path);
            let (outputs, stats) = run(&path, Some(keys_config(&snap)));
            assert_matches(&outputs, &snap);
            assert_eq!(
                stats.reassembly + stats.auth_failed + stats.malformed,
                0,
                "{name}/{variant}: {stats:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
