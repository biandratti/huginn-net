use huginn_net_http::akamai_extractor::{
    extract_akamai_fingerprint, parse_priority_payload, parse_settings_payload,
    parse_window_update_payload,
};
use huginn_net_http::{Http2Frame, SettingId, SettingParameter};

#[test]
fn test_parse_settings_payload() {
    let payload = vec![
        0x00, 0x01, // ID: HEADER_TABLE_SIZE (1)
        0x00, 0x00, 0x10, 0x00, // Value: 4096
        0x00, 0x02, // ID: ENABLE_PUSH (2)
        0x00, 0x00, 0x00, 0x00, // Value: 0
    ];

    let settings = parse_settings_payload(&payload);

    assert_eq!(settings.len(), 2);
    assert_eq!(settings[0].id, SettingId::HeaderTableSize);
    assert_eq!(settings[0].value, 4096);
    assert_eq!(settings[1].id, SettingId::EnablePush);
    assert_eq!(settings[1].value, 0);
}

#[test]
fn test_parse_settings_payload_chrome() {
    let payload = vec![
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE: 65536
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH: 0
        0x00, 0x03, 0x00, 0x00, 0x03, 0xE8, // MAX_CONCURRENT_STREAMS: 1000
        0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE: 6291456 (0x600000)
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE: 16384
        0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE: 262144
    ];

    let settings = parse_settings_payload(&payload);

    assert_eq!(settings.len(), 6);
    assert_eq!(settings[0], SettingParameter { id: SettingId::HeaderTableSize, value: 65536 });
    assert_eq!(settings[1], SettingParameter { id: SettingId::EnablePush, value: 0 });
    assert_eq!(
        settings[2],
        SettingParameter { id: SettingId::MaxConcurrentStreams, value: 1000 }
    );
    assert_eq!(
        settings[3],
        SettingParameter { id: SettingId::InitialWindowSize, value: 6291456 }
    );
    assert_eq!(settings[4], SettingParameter { id: SettingId::MaxFrameSize, value: 16384 });
    assert_eq!(
        settings[5],
        SettingParameter { id: SettingId::MaxHeaderListSize, value: 262144 }
    );
}

#[test]
fn test_parse_window_update_payload() {
    let payload = vec![0x00, 0xEF, 0x00, 0x01]; // 15663105 = 0xEF0001
    let result = parse_window_update_payload(&payload);
    assert!(result.is_some(), "Failed to parse valid WINDOW_UPDATE payload");
    if let Some(increment) = result {
        assert_eq!(increment, 15663105);
    }
}

#[test]
fn test_parse_window_update_payload_firefox() {
    let payload = vec![0x00, 0xBF, 0x00, 0x01]; // 12517377 = 0xBF0001
    let result = parse_window_update_payload(&payload);
    assert!(result.is_some(), "Failed to parse valid Firefox WINDOW_UPDATE payload");
    if let Some(increment) = result {
        assert_eq!(increment, 12517377);
    }
}

#[test]
fn test_parse_window_update_payload_too_short() {
    let payload = vec![0x00, 0xEE, 0xFC];
    let result = parse_window_update_payload(&payload);
    assert!(result.is_none());
}

#[test]
fn test_parse_priority_payload() {
    let payload = vec![
        0x00, 0x00, 0x00, 0x00, // depends_on: 0 (no exclusive bit)
        220,  // weight: 220
    ];

    let result = parse_priority_payload(1, &payload);
    assert!(result.is_some(), "Failed to parse valid PRIORITY payload");
    if let Some(priority) = result {
        assert_eq!(priority.stream_id, 1);
        assert!(!priority.exclusive);
        assert_eq!(priority.depends_on, 0);
        assert_eq!(priority.weight, 220);
    }
}

#[test]
fn test_parse_priority_payload_exclusive() {
    let payload = vec![
        0x80, 0x00, 0x00, 0x03, // depends_on: 3 with exclusive bit set
        200,  // weight: 200
    ];

    let result = parse_priority_payload(5, &payload);
    assert!(result.is_some(), "Failed to parse valid PRIORITY payload with exclusive bit");
    if let Some(priority) = result {
        assert_eq!(priority.stream_id, 5);
        assert!(priority.exclusive);
        assert_eq!(priority.depends_on, 3);
        assert_eq!(priority.weight, 200);
    }
}

#[test]
fn test_parse_priority_payload_too_short() {
    let payload = vec![0x00, 0x00, 0x00];
    let result = parse_priority_payload(1, &payload);
    assert!(result.is_none());
}

#[test]
fn test_headers_priority_flag_pseudo_headers_not_empty_regression() {
    // SETTINGS frame (type=0x4, flags=0, stream_id=0)
    // Encodes MAX_CONCURRENT_STREAMS=100
    let settings_frame = Http2Frame::new(0x4, 0x00, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);

    // HEADERS frame with FLAG_PRIORITY (0x20) | FLAG_END_HEADERS (0x04) on stream 1.
    // RFC 7540 §6.2 payload layout when PRIORITY flag is set:
    //   [E(1b) + StreamDep(31b) = 4 bytes] [Weight(1 byte)] [HPACK block...]
    //
    // HPACK static table:
    //   index 2 → :method GET   (0x82)
    //   index 4 → :path  /      (0x84)
    //   index 6 → :scheme https (0x86)
    //   index 1 → :authority "" (0x41 + literal)

    let headers_payload = vec![
        // priority data (5 bytes, RFC 7540 §6.3)
        0x00, 0x00, 0x00, 0x00, // E=0, StreamDep=0
        0xFF, // Weight=255
        // HPACK indexed header fields
        0x82, // :method  = GET   (static index 2)
        0x84, // :path    = /     (static index 4)
        0x86, // :scheme  = https (static index 6)
    ];
    let headers_frame = Http2Frame::new(0x1, 0x24, 1, headers_payload);

    let Some(fp) = extract_akamai_fingerprint(&[settings_frame, headers_frame]) else {
        panic!("fingerprint must be produced from SETTINGS + HEADERS");
    };

    assert!(
        !fp.pseudo_header_order.is_empty(),
        "pseudo-header segment must not be empty (bug: priority bytes consumed as HPACK); \
         fingerprint='{}'",
        fp.fingerprint
    );
    assert!(
        !fp.fingerprint.ends_with('|'),
        "fingerprint must not end with '|' (empty pseudo-headers); \
         fingerprint='{}'",
        fp.fingerprint
    );

    // :method must be the first pseudo-header decoded
    use huginn_net_http::PseudoHeader;
    assert_eq!(
        fp.pseudo_header_order[0],
        PseudoHeader::Method,
        "first pseudo-header must be :method; fingerprint='{}'",
        fp.fingerprint
    );
}

#[test]
fn test_headers_no_priority_flag_pseudo_headers_decoded() {
    let settings_frame = Http2Frame::new(0x4, 0x00, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);

    // Pure HPACK, no priority prefix
    let headers_frame = Http2Frame::new(
        0x1,
        0x04, // FLAG_END_HEADERS only
        1,
        vec![0x82, 0x84, 0x86], // :method GET, :path /, :scheme https
    );

    let Some(fp) = extract_akamai_fingerprint(&[settings_frame, headers_frame]) else {
        panic!("fingerprint must be produced");
    };

    assert!(!fp.pseudo_header_order.is_empty(), "fingerprint='{}'", fp.fingerprint);
    assert!(!fp.fingerprint.ends_with('|'), "fingerprint='{}'", fp.fingerprint);

    use huginn_net_http::PseudoHeader;
    assert_eq!(fp.pseudo_header_order[0], PseudoHeader::Method);
}

#[test]
fn test_headers_priority_flag_truncated_payload_no_panic() {
    let settings_frame = Http2Frame::new(0x4, 0x00, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);

    let headers_frame = Http2Frame::new(0x1, 0x24, 1, vec![0x00, 0x00]); // only 2 bytes

    let Some(fp) = extract_akamai_fingerprint(&[settings_frame, headers_frame]) else {
        panic!("fingerprint must still be produced from SETTINGS alone");
    };

    assert!(fp.pseudo_header_order.is_empty(), "truncated payload → no pseudo-headers");
}

#[test]
fn test_parse_settings_empty_payload() {
    let payload = vec![];
    let settings = parse_settings_payload(&payload);
    assert!(settings.is_empty());
}

#[test]
fn test_parse_settings_incomplete_setting() {
    let payload = vec![
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // Complete setting
        0x00, 0x02, 0x00, // Incomplete setting (missing 3 bytes)
    ];

    let settings = parse_settings_payload(&payload);
    assert_eq!(settings.len(), 1);
    assert_eq!(settings[0].id, SettingId::HeaderTableSize);
}
