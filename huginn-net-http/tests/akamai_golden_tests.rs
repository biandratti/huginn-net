//! Golden tests for Akamai HTTP/2 fingerprinting
use huginn_net_http::{extract_akamai_fingerprint, Http2Frame};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AkamaiTestCase {
    name: String,
    description: String,
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

fn load_test_cases() -> Vec<AkamaiTestCase> {
    let test_data = match fs::read_to_string("tests/snapshots/akamai_test_cases.json") {
        Ok(data) => data,
        Err(e) => panic!("Failed to read akamai_test_cases.json: {e}"),
    };

    match serde_json::from_str(&test_data) {
        Ok(cases) => cases,
        Err(e) => panic!("Failed to parse test cases JSON: {e}"),
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

fn assert_fingerprint_matches(
    actual: &ActualFingerprint,
    expected: &ExpectedFingerprint,
    test_name: &str,
) {
    assert_eq!(actual.signature, expected.signature, "[{test_name}] Signature mismatch");
    assert_eq!(actual.hash, expected.hash, "[{test_name}] Hash mismatch");
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
}

#[test]
fn test_akamai_golden_snapshots() {
    let test_cases = load_test_cases();

    for test_case in test_cases {
        println!("Running Akamai golden test: {}", test_case.name);
        println!("  Description: {}", test_case.description);

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
                assert_fingerprint_matches(&actual, expected, &test_case.name);
            }
            (None, None) => { /* expected */ }
            (Some(actual), None) => {
                panic!(
                    "[{}] Expected no fingerprint, but got: {}",
                    test_case.name, actual.fingerprint
                );
            }
            (None, Some(_)) => {
                panic!("[{}] Expected fingerprint, but none was generated", test_case.name);
            }
        }
    }
}

#[test]
fn test_chrome_fingerprint() {
    let chrome_frames = vec![
        Http2Frame::new(
            0x4, // SETTINGS
            0x0,
            0,
            vec![
                0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // HEADER_TABLE_SIZE = 100
                0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 6291456
            ],
        ),
        Http2Frame::new(
            0x8, // WINDOW_UPDATE
            0x0,
            0,
            vec![0x00, 0xEE, 0xFF, 0x01], // increment = 15663105
        ),
        Http2Frame::new(
            0x2, // PRIORITY
            0x0,
            3,
            vec![
                0x00, 0x00, 0x00, 0x00, // stream dependency = 0
                0xC8, // weight = 200
            ],
        ),
    ];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&chrome_frames) {
        fp
    } else {
        panic!("Failed to extract Chrome fingerprint");
    };

    assert_eq!(fingerprint.settings.len(), 2);
    assert_eq!(fingerprint.window_update, 15662849);
    assert_eq!(fingerprint.priority_frames.len(), 1);

    // Verify signature format
    assert!(fingerprint.fingerprint.contains('|'));
    assert!(!fingerprint.hash.is_empty());
    assert_eq!(fingerprint.hash.len(), 32); // SHA-256 truncated to 32 hex chars (like JA3)
}

#[test]
fn test_firefox_fingerprint() {
    let firefox_frames = vec![
        Http2Frame::new(
            0x4, // SETTINGS
            0x0,
            0,
            vec![
                0x00, 0x03, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
                0x00, 0x04, 0x00, 0x00, 0x00, 0x64, // INITIAL_WINDOW_SIZE = 100
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
            ],
        ),
        Http2Frame::new(
            0x8, // WINDOW_UPDATE
            0x0,
            0,
            vec![0x00, 0xBE, 0xFF, 0x01], // increment = 12517377
        ),
    ];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&firefox_frames) {
        fp
    } else {
        panic!("Failed to extract Firefox fingerprint");
    };

    assert_eq!(fingerprint.settings.len(), 3);
    assert_eq!(fingerprint.window_update, 12517121);
    assert_eq!(fingerprint.priority_frames.len(), 0);

    // Verify signature format
    assert!(fingerprint.fingerprint.contains('|'));
    assert!(!fingerprint.hash.is_empty());
    assert_eq!(fingerprint.hash.len(), 32); // SHA-256 truncated to 32 hex chars
}

#[test]
fn test_fingerprint_deterministic() {
    let frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]),
        Http2Frame::new(0x8, 0x0, 0, vec![0x00, 0xEE, 0xFF, 0x01]),
    ];

    let fp1 = if let Some(fp) = extract_akamai_fingerprint(&frames) {
        fp
    } else {
        panic!("First fingerprint extraction failed");
    };

    let fp2 = if let Some(fp) = extract_akamai_fingerprint(&frames) {
        fp
    } else {
        panic!("Second fingerprint extraction failed");
    };

    assert_eq!(fp1.fingerprint, fp2.fingerprint, "Signatures must be deterministic");
    assert_eq!(fp1.hash, fp2.hash, "Hashes must be deterministic");
}

#[test]
fn test_different_browsers_different_fingerprints() {
    let chrome_frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]),
        Http2Frame::new(0x8, 0x0, 0, vec![0x00, 0xEE, 0xFF, 0x01]),
    ];

    let firefox_frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x10, 0x00]),
        Http2Frame::new(0x8, 0x0, 0, vec![0x00, 0xBE, 0xFF, 0x01]),
    ];

    let chrome_fp = if let Some(fp) = extract_akamai_fingerprint(&chrome_frames) {
        fp
    } else {
        panic!("Chrome fingerprint failed");
    };

    let firefox_fp = if let Some(fp) = extract_akamai_fingerprint(&firefox_frames) {
        fp
    } else {
        panic!("Firefox fingerprint failed");
    };

    assert_ne!(
        chrome_fp.fingerprint, firefox_fp.fingerprint,
        "Different browsers must produce different signatures"
    );
    assert_ne!(
        chrome_fp.hash, firefox_fp.hash,
        "Different browsers must produce different hashes"
    );
}

#[test]
fn test_minimal_frames() {
    // Only SETTINGS frame (minimum required)
    let minimal_frames =
        vec![Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64])];

    let fingerprint = if let Some(fp) = extract_akamai_fingerprint(&minimal_frames) {
        fp
    } else {
        panic!("Should generate fingerprint with minimal frames");
    };

    assert_eq!(fingerprint.settings.len(), 1);
    assert_eq!(fingerprint.window_update, 0);
    assert_eq!(fingerprint.priority_frames.len(), 0);
}

#[test]
fn test_no_settings_frame_returns_none() {
    let no_settings_frames = vec![
        Http2Frame::new(0x8, 0x0, 0, vec![0x00, 0xEE, 0xFF, 0x01]),
        Http2Frame::new(0x2, 0x0, 3, vec![0x00, 0x00, 0x00, 0x00, 0xC8]),
    ];

    let fingerprint = extract_akamai_fingerprint(&no_settings_frames);
    assert!(fingerprint.is_none(), "Should return None without SETTINGS frame");
}
