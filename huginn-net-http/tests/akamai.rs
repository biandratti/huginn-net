use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::{Http2Frame, Http2Priority, PseudoHeader, SettingId};

// Helper: build a minimal SETTINGS frame from raw setting bytes
fn settings_frame(payload: Vec<u8>) -> Http2Frame {
    Http2Frame::new(0x4, 0x00, 0, payload)
}

// Helper: build a HEADERS frame with HPACK-encoded pseudo-headers (no flags)
fn headers_frame(hpack: Vec<u8>) -> Http2Frame {
    Http2Frame::new(0x1, 0x04, 1, hpack)
}

#[test]
fn test_akamai_fingerprint_chrome() {
    // SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000,
    //           INITIAL_WINDOW_SIZE=6291456, MAX_FRAME_SIZE=16384, MAX_HEADER_LIST_SIZE=262144
    let frame = settings_frame(vec![
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65536
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
        0x00, 0x03, 0x00, 0x00, 0x03, 0xE8, // MAX_CONCURRENT_STREAMS = 1000
        0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 6291456
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE = 16384
        0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 262144
    ]);
    // HPACK static: :method GET(2), :path /(4), :authority(1 literal), :scheme https(7)
    let hpack = vec![0x82, 0x84, 0x01, 0x00, 0x87];
    let fp = extract_akamai_fingerprint(&[frame, headers_frame(hpack)])
        .unwrap_or_else(|e| panic!("should extract fingerprint: {e}"));

    assert_eq!(fp.settings.len(), 6);
    assert_eq!(fp.settings[0].id, SettingId::HeaderTableSize);
    assert_eq!(fp.settings[1].id, SettingId::EnablePush);
    assert!(fp
        .fingerprint
        .starts_with("1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|"));
    assert!(!fp.hash.is_empty());
    assert_eq!(fp.hash.len(), 32);
}

#[test]
fn test_akamai_fingerprint_firefox() {
    // SETTINGS: HEADER_TABLE_SIZE=65536, INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384
    let frame = settings_frame(vec![
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65536
        0x00, 0x04, 0x00, 0x02, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 131072
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE = 16384
    ]);
    let fp = extract_akamai_fingerprint(&[frame])
        .unwrap_or_else(|e| panic!("should extract fingerprint: {e}"));

    assert_eq!(fp.settings.len(), 3);
    assert!(fp.fingerprint.starts_with("1:65536;4:131072;5:16384|"));
}

#[test]
fn test_akamai_fingerprint_with_priorities() {
    let settings = settings_frame(vec![
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65536
        0x00, 0x02, 0x00, 0x00, 0x00, 0x01, // ENABLE_PUSH = 1
    ]);
    // Two PRIORITY frames: stream 1 (weight=220) and stream 3 (weight=200)
    let p1 = Http2Frame::new(0x2, 0x00, 1, vec![0x00, 0x00, 0x00, 0x00, 220]);
    let p2 = Http2Frame::new(0x2, 0x00, 3, vec![0x00, 0x00, 0x00, 0x00, 200]);
    let fp = extract_akamai_fingerprint(&[settings, p1, p2])
        .unwrap_or_else(|e| panic!("should extract fingerprint: {e}"));

    assert_eq!(fp.priority_frames.len(), 2);
    assert!(fp.fingerprint.contains("|1:0:0:221,3:0:0:201|"));
}

#[test]
fn test_fingerprint_hash_consistency() {
    let frame = settings_frame(vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    let fp1 = extract_akamai_fingerprint(std::slice::from_ref(&frame))
        .unwrap_or_else(|e| panic!("should extract: {e}"));
    let fp2 = extract_akamai_fingerprint(std::slice::from_ref(&frame))
        .unwrap_or_else(|e| panic!("should extract: {e}"));
    assert_eq!(fp1.hash, fp2.hash);
}

#[test]
fn test_fingerprint_hash_differs_for_different_settings() {
    let frame1 = settings_frame(vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x00]); // 65536
    let frame2 = settings_frame(vec![0x00, 0x01, 0x00, 0x00, 0x10, 0x00]); // 4096
    let fp1 =
        extract_akamai_fingerprint(&[frame1]).unwrap_or_else(|e| panic!("should extract: {e}"));
    let fp2 =
        extract_akamai_fingerprint(&[frame2]).unwrap_or_else(|e| panic!("should extract: {e}"));
    assert_ne!(fp1.hash, fp2.hash);
}

#[test]
fn test_priority_weight_display() {
    let priority = Http2Priority { stream_id: 1, exclusive: false, depends_on: 0, weight: 220 };
    assert!(format!("{priority}").contains("weight=221"));
}

#[test]
fn test_setting_id_conversion() {
    assert_eq!(SettingId::from(1), SettingId::HeaderTableSize);
    assert_eq!(SettingId::from(2), SettingId::EnablePush);
    assert_eq!(SettingId::from(9), SettingId::NoRfc7540Priorities);
    assert_eq!(SettingId::from(255), SettingId::Unknown(255));
}

#[test]
fn test_pseudo_header_display() {
    assert_eq!(PseudoHeader::Method.to_string(), "m");
    assert_eq!(PseudoHeader::Path.to_string(), "p");
    assert_eq!(PseudoHeader::Authority.to_string(), "a");
    assert_eq!(PseudoHeader::Scheme.to_string(), "s");
    assert_eq!(PseudoHeader::Status.to_string(), "st");
}

#[test]
fn test_no_settings_returns_error() {
    use huginn_net_http::HuginnNetHttpError;
    let result = extract_akamai_fingerprint(&[]);
    assert!(matches!(result, Err(HuginnNetHttpError::NoSettingsFrame)));
}

#[test]
fn test_malformed_headers_returns_error() {
    use huginn_net_http::HuginnNetHttpError;
    let settings = settings_frame(vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    // HEADERS frame with FLAG_PRIORITY (0x20) but only 2 bytes — truncated, needs 5
    let bad_headers = Http2Frame::new(0x1, 0x20, 1, vec![0x00, 0x00]);
    let result = extract_akamai_fingerprint(&[settings, bad_headers]);
    assert!(matches!(result, Err(HuginnNetHttpError::MalformedPseudoHeaders(_))));
}
