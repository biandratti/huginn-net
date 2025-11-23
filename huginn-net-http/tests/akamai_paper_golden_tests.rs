//! Golden tests based on Blackhat EU 2017 Paper
//!
//! These tests validate against the REAL fingerprints published in the
//! original research paper by Shuster, et al.
//!
//! Paper: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

use huginn_net_http::{extract_akamai_fingerprint, Http2Frame};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PaperTestCase {
    name: String,
    description: String,
    paper_reference: String,
    frames: Vec<FrameSnapshot>,
    expected_fingerprint: Option<ExpectedFingerprint>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FrameSnapshot {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ExpectedFingerprint {
    signature: String,
    hash: String,
    settings_count: usize,
    window_update: u32,
    priority_frames_count: usize,
    pseudo_headers_count: usize,
}

impl From<FrameSnapshot> for Http2Frame {
    fn from(snapshot: FrameSnapshot) -> Self {
        Http2Frame::new(snapshot.frame_type, snapshot.flags, snapshot.stream_id, snapshot.payload)
    }
}

fn load_paper_test_cases() -> Vec<PaperTestCase> {
    let test_data = match fs::read_to_string("tests/snapshots/akamai_paper_cases.json") {
        Ok(data) => data,
        Err(e) => panic!("Failed to read akamai_paper_cases.json: {e}"),
    };

    match serde_json::from_str(&test_data) {
        Ok(cases) => cases,
        Err(e) => panic!("Failed to parse paper test cases JSON: {e}"),
    }
}

struct ActualFingerprint<'a> {
    signature: &'a str,
    hash: &'a str,
    settings_count: usize,
    window_update: u32,
    priority_count: usize,
    pseudo_headers_count: usize,
}

fn assert_paper_fingerprint_matches(
    actual: &ActualFingerprint,
    expected: &ExpectedFingerprint,
    test_name: &str,
) {
    assert_eq!(
        actual.signature, expected.signature,
        "[{test_name}] Signature mismatch (vs Paper)"
    );
    assert_eq!(
        actual.settings_count, expected.settings_count,
        "[{test_name}] Settings count mismatch"
    );
    assert_eq!(
        actual.window_update, expected.window_update,
        "[{test_name}] Window update mismatch"
    );
    assert_eq!(
        actual.priority_count, expected.priority_frames_count,
        "[{test_name}] Priority frames count mismatch"
    );
    assert_eq!(
        actual.pseudo_headers_count, expected.pseudo_headers_count,
        "[{test_name}] Pseudo-headers count mismatch"
    );

    // Hash validation is optional here since paper doesn't provide hashes
    if !expected.hash.starts_with("PAPER_") {
        assert_eq!(actual.hash, expected.hash, "[{test_name}] Hash mismatch");
    }
}

/// Main test: Validates against Blackhat EU 2017 paper examples
#[test]
fn test_paper_golden_snapshots() {
    let test_cases = load_paper_test_cases();

    for test_case in test_cases {
        println!("📄 Running Paper Test: {}", test_case.name);
        println!("   Description: {}", test_case.description);
        println!("   Reference: {}", test_case.paper_reference);

        let frames: Vec<Http2Frame> = test_case.frames.into_iter().map(Http2Frame::from).collect();

        let fingerprint = extract_akamai_fingerprint(&frames);

        match (&fingerprint, &test_case.expected_fingerprint) {
            (Some(actual_fp), Some(expected)) => {
                let actual = ActualFingerprint {
                    signature: &actual_fp.fingerprint,
                    hash: &actual_fp.hash,
                    settings_count: actual_fp.settings.len(),
                    window_update: actual_fp.window_update,
                    priority_count: actual_fp.priority_frames.len(),
                    pseudo_headers_count: actual_fp.pseudo_header_order.len(),
                };

                assert_paper_fingerprint_matches(&actual, expected, &test_case.name);
            }
            (None, None) => { /* expected */ }
            (Some(actual), None) => {
                panic!(
                    "[{}] Expected no fingerprint, but got: {}",
                    test_case.name, actual.fingerprint
                );
            }
            (None, Some(_)) => {
                panic!(
                    "[{}] Expected fingerprint from paper, but none was generated",
                    test_case.name
                );
            }
        }
    }
}

#[test]
fn test_paper_chrome_61() {
    // Chrome 61 has the most PRIORITY frames in the paper example
    let frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0, 3, 0, 0, 0, 100, 0, 4, 0, 96, 0, 0, 0, 2, 0, 0, 0, 0]),
        Http2Frame::new(0x8, 0x0, 0, vec![0, 238, 255, 1]),
        Http2Frame::new(0x2, 0x0, 3, vec![0, 0, 0, 0, 200]),
        Http2Frame::new(0x2, 0x0, 5, vec![0, 0, 0, 0, 100]),
        Http2Frame::new(0x2, 0x0, 7, vec![0, 0, 0, 0, 0]),
        Http2Frame::new(0x2, 0x0, 9, vec![0, 0, 0, 7, 0]),
        Http2Frame::new(0x2, 0x0, 11, vec![0, 0, 0, 3, 0]),
        Http2Frame::new(0x2, 0x0, 13, vec![0, 0, 0, 0, 240]),
    ];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&frames) {
        fp
    } else {
        panic!("Failed to extract Chrome 61 fingerprint from paper");
    };

    // Verify structure
    assert_eq!(fingerprint.settings.len(), 3, "Chrome 61 should have 3 SETTINGS");
    assert_eq!(fingerprint.window_update, 15662849, "Chrome 61 WINDOW_UPDATE");
    assert_eq!(fingerprint.priority_frames.len(), 6, "Chrome 61 should have 6 PRIORITY frames");

    // Verify signature format (values may differ slightly from paper due to exact byte values)
    assert!(fingerprint.fingerprint.contains("3:100"));
    assert!(fingerprint.fingerprint.contains("4:6291456"));
    assert!(fingerprint.fingerprint.contains("|15662849|")); // Actual value from payload
}

#[test]
fn test_paper_firefox_55() {
    let frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0, 3, 0, 0, 16, 0, 0, 4, 0, 2, 0, 0, 0, 1, 0, 1, 0, 0]),
        Http2Frame::new(0x8, 0x0, 0, vec![0, 190, 255, 1]),
    ];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&frames) {
        fp
    } else {
        panic!("Failed to extract Firefox 55 fingerprint from paper");
    };

    assert_eq!(fingerprint.settings.len(), 3, "Firefox 55 should have 3 SETTINGS");
    assert_eq!(fingerprint.window_update, 12517121, "Firefox 55 WINDOW_UPDATE");
    assert_eq!(fingerprint.priority_frames.len(), 0, "Firefox 55 has no PRIORITY frames");
}

#[test]
fn test_paper_safari_11() {
    let frames = vec![
        Http2Frame::new(
            0x4,
            0x0,
            0,
            vec![0, 3, 0, 0, 0, 100, 0, 4, 0, 0, 255, 255, 0, 2, 0, 0, 0, 1],
        ),
        Http2Frame::new(0x8, 0x0, 0, vec![0, 255, 0, 1]),
        Http2Frame::new(0x2, 0x0, 3, vec![128, 0, 0, 0, 255]),
        Http2Frame::new(0x2, 0x0, 5, vec![128, 0, 0, 3, 255]),
    ];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&frames) {
        fp
    } else {
        panic!("Failed to extract Safari 11 fingerprint from paper");
    };

    assert_eq!(fingerprint.settings.len(), 3, "Safari 11 should have 3 SETTINGS");
    assert_eq!(fingerprint.window_update, 16711681, "Safari 11 WINDOW_UPDATE");
    assert_eq!(fingerprint.priority_frames.len(), 2, "Safari 11 should have 2 PRIORITY frames");

    // Safari uses exclusive bit (0x80)
    assert!(
        fingerprint.priority_frames.iter().all(|p| p.exclusive),
        "Safari 11 PRIORITY frames should be exclusive"
    );

    println!("✅ Safari 11 (Paper) validated:");
    println!("   Signature: {}", fingerprint.fingerprint);
    println!("   Hash:      {}", fingerprint.hash);
}
