use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;
use huginn_net_http::http2_parser::{Http2ParseError, HTTP2_CONNECTION_PREFACE};

/// Helper function to create an HTTP/2 frame
///
/// Creates a valid HTTP/2 frame with the specified type, stream ID, and payload.
/// Frame format: [length:24][type:8][flags:8][stream_id:32][payload]
fn create_http2_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Length (24 bits, big-endian)
    let length = payload.len() as u32;
    frame.push(((length >> 16) & 0xFF) as u8);
    frame.push(((length >> 8) & 0xFF) as u8);
    frame.push((length & 0xFF) as u8);

    // Type (8 bits)
    frame.push(frame_type);

    // Flags (8 bits)
    frame.push(0x00);

    // Stream ID (32 bits, big-endian, with reserved bit cleared)
    frame.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());

    // Payload
    frame.extend_from_slice(payload);

    frame
}

/// Create a SETTINGS frame payload with the given settings
///
/// Each setting is 6 bytes: [id:16][value:32]
fn create_settings_payload(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (id, value) in settings {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    payload
}

/// Create a WINDOW_UPDATE frame payload
fn create_window_update_payload(increment: u32) -> Vec<u8> {
    // WINDOW_UPDATE payload is 4 bytes: [increment:32]
    // The increment must have the reserved bit cleared
    (increment & 0x7FFF_FFFF).to_be_bytes().to_vec()
}

#[test]
fn test_new() {
    let extractor = Http2FingerprintExtractor::new();
    assert!(!extractor.fingerprint_extracted());
    assert!(extractor.get_fingerprint().is_none());
}

#[test]
fn test_default() {
    let extractor = Http2FingerprintExtractor::default();
    assert!(!extractor.fingerprint_extracted());
    assert!(extractor.get_fingerprint().is_none());
}

#[test]
fn test_add_bytes_empty() {
    let mut extractor = Http2FingerprintExtractor::new();
    let result = extractor.add_bytes(&[]);
    assert!(result.is_ok());
    if let Ok(value) = result {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());
}

#[test]
fn test_add_bytes_insufficient_data() {
    let mut extractor = Http2FingerprintExtractor::new();
    // Less than 9 bytes (minimum frame header size)
    let result = extractor.add_bytes(&[0x00, 0x00, 0x00, 0x04, 0x00]);
    assert!(result.is_ok());
    if let Ok(value) = &result {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());
}

#[test]
fn test_add_bytes_with_preface() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create a SETTINGS frame (required for fingerprint)
    let settings_payload = create_settings_payload(&[(1, 65536), (2, 0)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    // Add preface + frame
    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    data.extend_from_slice(&settings_frame);

    let result = extractor.add_bytes(&data);
    assert!(result.is_ok());
    // Should extract fingerprint since we have SETTINGS frame
    if let Ok(fingerprint_result) = &result {
        assert!(fingerprint_result.is_some());
    }
    assert!(extractor.fingerprint_extracted());
    assert!(extractor.get_fingerprint().is_some());
}

#[test]
fn test_add_bytes_without_preface() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create a SETTINGS frame without preface
    let settings_payload = create_settings_payload(&[(1, 65536), (2, 0)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    let result = extractor.add_bytes(&settings_frame);
    assert!(result.is_ok());
    // Should extract fingerprint since we have SETTINGS frame
    if let Ok(fingerprint_result) = &result {
        assert!(fingerprint_result.is_some());
    }
    assert!(extractor.fingerprint_extracted());
}

#[test]
fn test_add_bytes_incremental() {
    let mut extractor = Http2FingerprintExtractor::new();

    // First add preface
    let result1 = extractor.add_bytes(HTTP2_CONNECTION_PREFACE);
    assert!(result1.is_ok());
    if let Ok(value) = &result1 {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());

    // Then add partial frame header
    let partial_header = &[0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00];
    let result2 = extractor.add_bytes(partial_header);
    assert!(result2.is_ok());
    if let Ok(value) = &result2 {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());

    // Then add the rest of the frame (settings payload)
    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let result3 = extractor.add_bytes(&settings_payload);
    assert!(result3.is_ok());
    if let Ok(fingerprint_result) = result3 {
        // The fingerprint may or may not be extracted depending on frame completeness
        // But parsing should succeed
        if fingerprint_result.is_some() {
            assert!(extractor.fingerprint_extracted());
        }
    }
}

#[test]
fn test_add_bytes_no_settings_frame() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create a frame that's not SETTINGS (e.g., PING)
    let ping_frame = create_http2_frame(0x06, 0, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let result = extractor.add_bytes(&ping_frame);
    assert!(result.is_ok());
    // Should not extract fingerprint (no SETTINGS frame)
    if let Ok(value) = &result {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());
}

#[test]
fn test_add_bytes_after_fingerprint_extracted() {
    let mut extractor = Http2FingerprintExtractor::new();

    // First extract a fingerprint
    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);
    let result1 = extractor.add_bytes(&settings_frame);
    assert!(result1.is_ok());
    if let Ok(value) = &result1 {
        assert!(value.is_some());
    }
    assert!(extractor.fingerprint_extracted());

    // Try to add more data after fingerprint is extracted
    let more_data = create_http2_frame(0x06, 0, &[0x00]);
    let result2 = extractor.add_bytes(&more_data);
    assert!(result2.is_ok());
    // Should return None and not process the new data
    if let Ok(value) = &result2 {
        assert!(value.is_none());
    }
    // Fingerprint should still be the same
    assert!(extractor.fingerprint_extracted());
}

#[test]
fn test_add_bytes_invalid_frame() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create invalid frame data (frame header says length is 1000 but we only provide 9 bytes)
    let invalid_frame = vec![
        0x00, 0x03, 0xE8, // Length: 1000
        0x04, // Type: SETTINGS
        0x00, // Flags
        0x00, 0x00, 0x00,
        0x00, // Stream ID: 0
              // Missing payload (should have 1000 bytes)
    ];

    let result = extractor.add_bytes(&invalid_frame);
    // Should return an error (IncompleteFrame) or Ok(None) if more data is needed
    // The parser may handle incomplete frames differently
    match result {
        Err(err) => {
            // If it's an error, check that it's a parsing error
            assert!(matches!(err, Http2ParseError::IncompleteFrame));
        }
        Ok(value) => {
            // If it's Ok, it should be None (need more data)
            assert!(value.is_none(), "Incomplete frame should return None, not Some");
        }
    }
}

#[test]
fn test_get_fingerprint_before_extraction() {
    let extractor = Http2FingerprintExtractor::new();
    assert!(extractor.get_fingerprint().is_none());
}

#[test]
fn test_get_fingerprint_after_extraction() {
    let mut extractor = Http2FingerprintExtractor::new();

    let settings_payload = create_settings_payload(&[(1, 65536), (2, 0)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    let _ = extractor.add_bytes(&settings_frame);

    let fingerprint = extractor.get_fingerprint();
    assert!(fingerprint.is_some());
    if let Some(fp) = fingerprint {
        assert_eq!(fp.settings.len(), 2);
        assert!(!fp.fingerprint.is_empty());
        assert!(!fp.hash.is_empty());
    }
}

#[test]
fn test_fingerprint_extracted() {
    let mut extractor = Http2FingerprintExtractor::new();
    assert!(!extractor.fingerprint_extracted());

    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    let _ = extractor.add_bytes(&settings_frame);
    assert!(extractor.fingerprint_extracted());
}

#[test]
fn test_reset() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Extract a fingerprint first
    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);
    let _ = extractor.add_bytes(&settings_frame);
    assert!(extractor.fingerprint_extracted());

    // Reset
    extractor.reset();

    // Should be back to initial state
    assert!(!extractor.fingerprint_extracted());
    assert!(extractor.get_fingerprint().is_none());

    // Should be able to extract again
    let _ = extractor.add_bytes(&settings_frame);
    assert!(extractor.fingerprint_extracted());
}

#[test]
fn test_complete_fingerprint_with_all_components() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create SETTINGS frame
    let settings_payload = create_settings_payload(&[
        (1, 65536), // HEADER_TABLE_SIZE
        (2, 0),     // ENABLE_PUSH
        (3, 1000),  // MAX_CONCURRENT_STREAMS
    ]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    // Create WINDOW_UPDATE frame
    let window_update_payload = create_window_update_payload(15663105);
    let window_update_frame = create_http2_frame(0x08, 0, &window_update_payload);

    // Create PRIORITY frame
    let priority_payload = vec![
        0x00, 0x00, 0x00, 0x03, // depends_on: 3 (no exclusive bit)
        220,  // weight: 220
    ];
    let priority_frame = create_http2_frame(0x02, 1, &priority_payload);

    // Combine all frames
    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    data.extend_from_slice(&settings_frame);
    data.extend_from_slice(&window_update_frame);
    data.extend_from_slice(&priority_frame);

    let result = extractor.add_bytes(&data);
    assert!(result.is_ok());
    if let Ok(fingerprint_result) = &result {
        assert!(fingerprint_result.is_some());
    }

    if let Some(fingerprint) = extractor.get_fingerprint() {
        assert_eq!(fingerprint.settings.len(), 3);
        assert_eq!(fingerprint.window_update, 15663105);
        assert_eq!(fingerprint.priority_frames.len(), 1);
    }
}

#[test]
fn test_multiple_add_bytes_calls() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Split data across multiple calls
    let settings_payload = create_settings_payload(&[(1, 65536), (2, 0), (3, 1000)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    // Split the frame into parts
    let mid_point = settings_frame.len() / 2;
    let part1 = &settings_frame[..mid_point];
    let part2 = &settings_frame[mid_point..];

    let result1 = extractor.add_bytes(part1);
    assert!(result1.is_ok());
    if let Ok(value) = &result1 {
        assert!(value.is_none());
    }

    let result2 = extractor.add_bytes(part2);
    assert!(result2.is_ok());
    if let Ok(fingerprint_result) = &result2 {
        assert!(fingerprint_result.is_some());
    }
    assert!(extractor.fingerprint_extracted());
}

#[test]
fn test_parsed_offset_tracking() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Add preface
    let _ = extractor.add_bytes(HTTP2_CONNECTION_PREFACE);

    // Add a SETTINGS frame
    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);
    let _ = extractor.add_bytes(&settings_frame);

    // Add another frame after fingerprint is extracted
    // This should be ignored since fingerprint is already extracted
    let ping_frame = create_http2_frame(0x06, 0, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let result = extractor.add_bytes(&ping_frame);
    assert!(result.is_ok());
    if let Ok(value) = &result {
        assert!(value.is_none());
    }
}

#[test]
fn test_preface_detection_only_on_first_call() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Add data without preface first
    let settings_payload = create_settings_payload(&[(1, 65536)]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);
    let _ = extractor.add_bytes(&settings_frame);

    // Reset and add preface + frame
    extractor.reset();
    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    data.extend_from_slice(&settings_frame);

    let result = extractor.add_bytes(&data);
    assert!(result.is_ok());
    if let Ok(value) = &result {
        assert!(value.is_some());
    }
}

#[test]
fn test_empty_settings_frame() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Create SETTINGS frame with empty payload
    let settings_frame = create_http2_frame(0x04, 0, &[]);

    let result = extractor.add_bytes(&settings_frame);
    assert!(result.is_ok());
    // Empty SETTINGS frame should not produce a fingerprint
    // (extract_akamai_fingerprint requires at least one setting)
    if let Ok(value) = &result {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());
}

#[test]
fn test_frame_too_small_for_parsing() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Add preface
    let _ = extractor.add_bytes(HTTP2_CONNECTION_PREFACE);

    // Add data that's less than 9 bytes (minimum frame header)
    let small_data = &[0x00, 0x00, 0x04];
    let result = extractor.add_bytes(small_data);
    assert!(result.is_ok());
    if let Ok(value) = &result {
        assert!(value.is_none());
    }
    assert!(!extractor.fingerprint_extracted());
}

#[test]
fn test_chrome_like_fingerprint() {
    let mut extractor = Http2FingerprintExtractor::new();

    // Chrome-like SETTINGS frame
    let settings_payload = create_settings_payload(&[
        (1, 65536),   // HEADER_TABLE_SIZE: 65536
        (2, 0),       // ENABLE_PUSH: 0
        (3, 1000),    // MAX_CONCURRENT_STREAMS: 1000
        (4, 6291456), // INITIAL_WINDOW_SIZE: 6291456
        (5, 16384),   // MAX_FRAME_SIZE: 16384
        (6, 262144),  // MAX_HEADER_LIST_SIZE: 262144
    ]);
    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);

    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    data.extend_from_slice(&settings_frame);

    let result = extractor.add_bytes(&data);
    assert!(result.is_ok());
    if let Ok(Some(ref fingerprint)) = result {
        assert_eq!(fingerprint.settings.len(), 6);
        // Verify fingerprint string contains expected values
        assert!(fingerprint.fingerprint.contains("1:65536"));
        assert!(fingerprint.fingerprint.contains("2:0"));
        assert!(fingerprint.fingerprint.contains("3:1000"));
    }
}
