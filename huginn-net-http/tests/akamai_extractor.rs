use huginn_net_http::akamai_extractor::{
    parse_priority_payload, parse_settings_payload, parse_window_update_payload,
};
use huginn_net_http::{SettingId, SettingParameter};

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
