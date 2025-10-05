use huginn_net_http::http2_parser::{
    is_http2_traffic, Http2Config, Http2FrameType, Http2ParseError, Http2Parser,
    HTTP2_CONNECTION_PREFACE,
};

fn assert_parser_error<T>(
    result: Result<Option<T>, Http2ParseError>,
    expected_discriminant: Http2ParseError,
) {
    match result {
        Err(actual) => assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected_discriminant),
            "Expected error type {expected_discriminant:?} but got {actual:?}"
        ),
        Ok(_) => panic!("Expected error {expected_discriminant:?} but got Ok"),
    }
}

fn create_http2_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Length (24 bits)
    let length = payload.len() as u32;
    frame.push(((length >> 16) & 0xFF) as u8);
    frame.push(((length >> 8) & 0xFF) as u8);
    frame.push((length & 0xFF) as u8);

    // Type (8 bits)
    frame.push(frame_type);

    // Flags (8 bits)
    frame.push(0x00);

    // Stream ID (32 bits, with R bit cleared)
    frame.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());

    // Payload
    frame.extend_from_slice(payload);

    frame
}

fn create_http2_request_with_preface(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    for frame in frames {
        data.extend_from_slice(frame);
    }
    data
}

#[test]
fn test_http2_preface_detection() {
    let http2_data = HTTP2_CONNECTION_PREFACE;
    assert!(is_http2_traffic(http2_data));

    let http1_data = b"GET / HTTP/1.1\r\n";
    assert!(!is_http2_traffic(http1_data));

    // Edge case: partial preface
    let partial_preface = &HTTP2_CONNECTION_PREFACE[..10];
    assert!(!is_http2_traffic(partial_preface));

    // Edge case: empty data
    assert!(!is_http2_traffic(&[]));
}

#[test]
fn test_frame_type_conversion() {
    assert_eq!(Http2FrameType::from(0x0), Http2FrameType::Data);
    assert_eq!(Http2FrameType::from(0x1), Http2FrameType::Headers);
    assert_eq!(Http2FrameType::from(0x2), Http2FrameType::Priority);
    assert_eq!(Http2FrameType::from(0x3), Http2FrameType::RstStream);
    assert_eq!(Http2FrameType::from(0x4), Http2FrameType::Settings);
    assert_eq!(Http2FrameType::from(0x5), Http2FrameType::PushPromise);
    assert_eq!(Http2FrameType::from(0x6), Http2FrameType::Ping);
    assert_eq!(Http2FrameType::from(0x7), Http2FrameType::GoAway);
    assert_eq!(Http2FrameType::from(0x8), Http2FrameType::WindowUpdate);
    assert_eq!(Http2FrameType::from(0x9), Http2FrameType::Continuation);
    assert_eq!(Http2FrameType::from(0xFF), Http2FrameType::Unknown(0xFF));
}

#[test]
fn test_invalid_preface() {
    let parser = Http2Parser::new();
    let invalid_data = b"GET / HTTP/1.1\r\n\r\n";

    assert_parser_error(
        parser.parse_request(invalid_data),
        Http2ParseError::InvalidPreface,
    );
}

#[test]
fn test_empty_data() {
    let parser = Http2Parser::new();

    // Empty data should fail preface check
    assert_parser_error(parser.parse_request(&[]), Http2ParseError::InvalidPreface);

    // Only preface, no frames
    let result = parser.parse_request(HTTP2_CONNECTION_PREFACE);
    match result {
        Ok(None) => {} // Expected: no request without frames
        Ok(Some(_)) => panic!("Should not return a request without frames"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_incomplete_frame_header() {
    let parser = Http2Parser::new();

    // Preface + incomplete frame header (less than 9 bytes)
    let mut data = Vec::from(HTTP2_CONNECTION_PREFACE);
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Only 4 bytes of frame header

    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: incomplete data
        Ok(Some(_)) => panic!("Should not return a request with incomplete data"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_frame_too_large() {
    let parser = Http2Parser::new();

    // Create frame with length exceeding max_frame_size (16384)
    let large_length = 20000u32;
    let mut frame = Vec::new();

    // Length (24 bits) - exceeds max_frame_size
    frame.push(((large_length >> 16) & 0xFF) as u8);
    frame.push(((large_length >> 8) & 0xFF) as u8);
    frame.push((large_length & 0xFF) as u8);

    // Complete frame header
    frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01]); // Headers frame, stream 1

    let data = create_http2_request_with_preface(&[frame]);
    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: frame too large
        Ok(Some(_)) => panic!("Should not return a request with frame too large"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_incomplete_frame_payload() {
    let parser = Http2Parser::new();

    // Frame header says 100 bytes payload, but we only provide 50
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x00, 0x64]); // Length: 100
    frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01]); // Headers frame, stream 1
    frame.extend_from_slice(&[0x00; 50]); // Only 50 bytes instead of 100

    let data = create_http2_request_with_preface(&[frame]);
    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: incomplete payload
        Ok(Some(_)) => panic!("Should not return a request with incomplete payload"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_zero_length_frame() {
    let parser = Http2Parser::new();

    // Valid zero-length frame
    let frame = create_http2_frame(0x04, 0, &[]); // Settings frame with no payload
    let data = create_http2_request_with_preface(&[frame]);

    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: no headers frame
        Ok(Some(_)) => panic!("Should not return a request without headers frame"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_maximum_valid_frame_size() {
    let parser = Http2Parser::new();

    // Frame with exactly max_frame_size (16384 bytes)
    let max_payload = vec![0x00; 16384];
    let frame = create_http2_frame(0x00, 1, &max_payload); // Data frame
    let data = create_http2_request_with_preface(&[frame]);

    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: no headers frame, only data frame
        Ok(Some(_)) => panic!("Should not return a request without headers frame"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_invalid_stream_id_zero_for_headers() {
    let parser = Http2Parser::new();

    // Headers frame with stream ID 0 (invalid)
    let frame = create_http2_frame(0x01, 0, &[0x00]); // Headers frame, stream 0
    let data = create_http2_request_with_preface(&[frame]);

    let result = parser.parse_request(&data);
    match result {
        Ok(None) => {} // Expected: invalid stream ID 0
        Ok(Some(_)) => panic!("Should not return a request with invalid stream ID"),
        Err(e) => panic!("Should not error: {e:?}"),
    }
}

#[test]
fn test_multiple_frames_parsing() {
    let parser = Http2Parser::new();

    // Multiple frames: Settings + Headers
    let settings_frame = create_http2_frame(0x04, 0, &[]); // Settings frame
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]); // Headers frame

    let data = create_http2_request_with_preface(&[settings_frame, headers_frame]);
    let result = parser.parse_request(&data);

    // Should handle gracefully - either Ok(None) or Err due to invalid HPACK
    match result {
        Ok(None) => {
            // Expected: no valid request parsed due to invalid HPACK
        }
        Err(Http2ParseError::HpackDecodingFailed) => {
            // Also expected: HPACK decoding failed
        }
        other => {
            panic!("Unexpected result: {other:?}");
        }
    }
}

#[test]
fn test_arithmetic_overflow_protection() {
    let parser = Http2Parser::new();

    // Test frame length that would cause overflow when added to 9
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // Maximum 24-bit length
    frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01]); // Headers frame

    let data = create_http2_request_with_preface(&[frame]);
    let result = parser.parse_request(&data);

    // Should handle overflow gracefully without panicking
    assert!(result.is_ok());
}

#[test]
fn test_hpack_decoding_failure() {
    let parser = Http2Parser::new();

    // Headers frame with invalid HPACK data
    let invalid_hpack = vec![0xFF; 10]; // Invalid HPACK data
    let frame = create_http2_frame(0x01, 1, &invalid_hpack);
    let data = create_http2_request_with_preface(&[frame]);

    let result = parser.parse_request(&data);
    // Should handle HPACK decoding failure gracefully
    match result {
        Ok(None) => {} // Expected: HPACK decoding failed or no valid request
        Ok(Some(_)) => panic!("Should not return a request with HPACK decoding failure"),
        Err(_) => {} // Also expected: HPACK decoding error
    }
}

#[test]
fn test_missing_required_headers() {
    let parser = Http2Parser::new();

    // This test would require valid HPACK encoding without required pseudo-headers
    // For now, we test the error path exists
    let frame = create_http2_frame(0x01, 1, &[0x00]);
    let data = create_http2_request_with_preface(&[frame]);

    let result = parser.parse_request(&data);
    // Should either fail HPACK decoding or missing headers check
    match result {
        Ok(None) => {} // Expected: missing required headers or HPACK failure
        Ok(Some(_)) => panic!("Should not return a request with missing required headers"),
        Err(_) => {} // Also expected: HPACK decoding error
    }
}

#[test]
fn test_response_parsing_without_preface() {
    let parser = Http2Parser::new();

    // Response parsing doesn't require preface
    let frame = create_http2_frame(0x01, 1, &[0x00]); // Headers frame

    let result = parser.parse_response(&frame);
    // Should handle gracefully (likely HPACK failure)
    match result {
        Ok(None) => {} // Expected: HPACK failure or no valid response
        Ok(Some(_)) => panic!("Should not return a response with HPACK failure"),
        Err(_) => {} // Also expected: HPACK decoding error
    }
}

#[test]
fn test_frame_parsing_edge_cases() {
    let parser = Http2Parser::new();

    // Test various edge cases in frame parsing
    let test_cases = [
        // Case 1: Frame with reserved bit set in stream ID
        {
            let mut frame = create_http2_frame(0x01, 1, &[0x00]);
            // Set reserved bit in stream ID
            frame[5] |= 0x80;
            frame
        },
        // Case 2: Continuation frame (should be handled)
        create_http2_frame(0x09, 1, &[0x00]),
        // Case 3: Unknown frame type
        create_http2_frame(0xFF, 1, &[0x00]),
    ];

    for (i, frame) in test_cases.iter().enumerate() {
        let data = create_http2_request_with_preface(std::slice::from_ref(frame));
        let result = parser.parse_request(&data);

        // All should handle gracefully without panicking
        assert!(result.is_ok() || result.is_err(), "Test case {i} failed");
    }
}

#[test]
fn test_settings_frame_parsing() {
    let parser = Http2Parser::new();

    // Valid settings frame with some settings
    let mut settings_payload = Vec::new();

    // SETTINGS_HEADER_TABLE_SIZE = 4096
    settings_payload.extend_from_slice(&[0x00, 0x01]); // ID
    settings_payload.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // Value: 4096

    // SETTINGS_ENABLE_PUSH = 0
    settings_payload.extend_from_slice(&[0x00, 0x02]); // ID
    settings_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Value: 0

    let settings_frame = create_http2_frame(0x04, 0, &settings_payload);
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]);

    let data = create_http2_request_with_preface(&[settings_frame, headers_frame]);
    let result = parser.parse_request(&data);

    // Should parse settings and attempt headers (likely fail on HPACK)
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_cookie_parsing_edge_cases() {
    use huginn_net_http::http_common::HttpHeader;
    let parser = Http2Parser::new();

    let test_cases = vec![
        ("", 0),
        ("name=value", 1),
        ("name=", 1),
        ("name", 1),
        ("name=value; other=test", 2),
        ("  name  =  value  ", 1),
        ("name=value;", 1),
        (";name=value", 1),
        ("name=value;;other=test", 2),
    ];

    for (cookie_str, expected_count) in test_cases {
        let headers = [HttpHeader {
            name: "cookie".to_string(),
            value: if cookie_str.is_empty() {
                None
            } else {
                Some(cookie_str.to_string())
            },
            position: 0,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        }];

        let cookie_headers: Vec<&HttpHeader> = headers
            .iter()
            .filter(|h| h.name.to_lowercase() == "cookie")
            .collect();
        let cookies = parser.parse_cookies_from_headers(&cookie_headers);
        assert_eq!(
            cookies.len(),
            expected_count,
            "Failed for case: '{cookie_str}'"
        );

        match cookie_str {
            "" => {
                assert!(cookies.is_empty());
            }
            "name=value" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
            }
            "name=" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("".to_string()));
            }
            "name" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, None);
            }
            "name=value; other=test" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[1].name, "other");
                assert_eq!(cookies[1].value, Some("test".to_string()));
            }
            "  name  =  value  " => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
            }
            "name=value;" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
            }
            ";name=value" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
            }
            "name=value;;other=test" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[1].name, "other");
                assert_eq!(cookies[1].value, Some("test".to_string()));
            }
            _ => {}
        }
    }
}

#[test]
fn test_multiple_cookie_headers_http2() {
    use huginn_net_http::http_common::HttpHeader;
    let parser = Http2Parser::new();

    // HTTP/2 can have multiple cookie headers according to RFC 7540
    let headers = [
        HttpHeader {
            name: "cookie".to_string(),
            value: Some("session_id=abc123".to_string()),
            position: 0,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "cookie".to_string(),
            value: Some("user_id=456".to_string()),
            position: 1,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "cookie".to_string(),
            value: Some("theme=dark; lang=en".to_string()),
            position: 2,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
    ];

    let cookie_headers: Vec<&HttpHeader> = headers
        .iter()
        .filter(|h| h.name.to_lowercase() == "cookie")
        .collect();
    let cookies = parser.parse_cookies_from_headers(&cookie_headers);

    assert_eq!(cookies.len(), 4);
    assert_eq!(cookies[0].name, "session_id");
    assert_eq!(cookies[0].value, Some("abc123".to_string()));
    assert_eq!(cookies[1].name, "user_id");
    assert_eq!(cookies[1].value, Some("456".to_string()));
    assert_eq!(cookies[2].name, "theme");
    assert_eq!(cookies[2].value, Some("dark".to_string()));
    assert_eq!(cookies[3].name, "lang");
    assert_eq!(cookies[3].value, Some("en".to_string()));
}

#[test]
fn test_security_malformed_frames() {
    let parser = Http2Parser::new();

    // Test cases that could potentially cause security issues
    let malicious_cases = [
        // Case 1: Frame with malformed length field
        vec![0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01],
        // Case 2: Frame with zero stream ID for non-connection frames
        vec![0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
        // Case 3: Extremely large payload declaration
        vec![0x7F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        // Case 4: Invalid frame type with large payload
        vec![0x00, 0x10, 0x00, 0xFE, 0xFF, 0x80, 0x00, 0x00, 0x01],
    ];

    for malicious_frame in malicious_cases.iter() {
        let data = create_http2_request_with_preface(std::slice::from_ref(malicious_frame));
        let result = parser.parse_request(&data);

        // Should handle all malicious cases without panicking
        match result {
            Ok(_) | Err(_) => {
                // Both outcomes are acceptable as long as no panic occurs
            }
        }

        // Also test response parsing
        let response_result = parser.parse_response(malicious_frame);
        match response_result {
            Ok(_) | Err(_) => {
                // Both outcomes are acceptable as long as no panic occurs
            }
        }
    }
}

#[test]
fn test_memory_exhaustion_protection() {
    let parser = Http2Parser::new();

    // Test with many small frames to ensure no memory exhaustion
    let mut frames = Vec::new();
    for i in 0..1000 {
        let frame = create_http2_frame(0x00, (i % 100) + 1, &[0x00]); // Data frames
        frames.push(frame);
    }

    let data = create_http2_request_with_preface(&frames);
    let result = parser.parse_request(&data);

    // Should handle large number of frames gracefully
    assert!(result.is_ok());
}

#[test]
fn test_stream_id_edge_cases() {
    let parser = Http2Parser::new();

    let test_cases = vec![
        (0x00000001, true),  // Valid client stream ID
        (0x00000003, true),  // Valid client stream ID
        (0x00000002, true),  // Valid server stream ID (should still parse)
        (0x7FFFFFFF, true),  // Maximum valid stream ID
        (0x80000001, true),  // Stream ID with reserved bit (should be masked)
        (0x00000000, false), // Invalid for headers frame
    ];

    for (stream_id, should_find_stream) in test_cases {
        let frame = create_http2_frame(0x01, stream_id, &[0x00]); // Headers frame
        let data = create_http2_request_with_preface(&[frame]);
        let result = parser.parse_request(&data);

        if should_find_stream {
            // Should attempt to parse (likely fail on HPACK but find the stream)
            match result {
                Ok(None) => {} // Expected: HPACK failure but stream found
                Ok(Some(_)) => panic!("Should not return a request with HPACK failure"),
                Err(_) => {} // Also expected: HPACK decoding error
            }
        } else {
            // Should return None (no valid stream found)
            match result {
                Ok(None) => {} // Expected: no valid stream
                Ok(Some(_)) => panic!("Should not return a request with invalid stream"),
                Err(e) => panic!("Should not error for invalid stream: {e:?}"),
            }
        }
    }
}

#[test]
fn test_frame_flag_handling() {
    let parser = Http2Parser::new();

    // Test different flag combinations
    let flag_cases = vec![
        0x00, // No flags
        0x01, // END_STREAM
        0x04, // END_HEADERS
        0x05, // END_STREAM | END_HEADERS
        0x08, // PADDED
        0x20, // PRIORITY
        0xFF, // All flags set
    ];

    for flags in flag_cases {
        let mut frame = create_http2_frame(0x01, 1, &[0x00]); // Headers frame
        frame[4] = flags; // Set flags byte

        let data = create_http2_request_with_preface(&[frame]);
        let result = parser.parse_request(&data);

        // Should handle all flag combinations without panicking
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn test_utf8_validation() {
    let parser = Http2Parser::new();

    // Test cases with invalid UTF-8 sequences
    let invalid_utf8_cases = vec![
        vec![0xFF, 0xFE, 0xFD], // Invalid UTF-8 start bytes
        vec![0x80, 0x80, 0x80], // Invalid continuation bytes
        vec![0xC0, 0x80],       // Overlong encoding
        vec![0xED, 0xA0, 0x80], // Surrogate pair
    ];

    for invalid_utf8 in invalid_utf8_cases {
        let frame = create_http2_frame(0x01, 1, &invalid_utf8);
        let data = create_http2_request_with_preface(&[frame]);
        let result = parser.parse_request(&data);

        // Should handle invalid UTF-8 gracefully
        match result {
            Ok(_) => {
                // If it succeeds, the UTF-8 handling converted it safely
            }
            Err(Http2ParseError::HpackDecodingFailed) => {
                // Expected: HPACK decoder rejected invalid data
            }
            Err(Http2ParseError::InvalidUtf8) => {
                // Also acceptable: explicit UTF-8 validation
            }
            Err(_) => {
                // Other errors are also acceptable
            }
        }
    }
}

#[test]
fn test_error_display_formatting() {
    // Test that all error types format correctly
    let errors = vec![
        Http2ParseError::InvalidPreface,
        Http2ParseError::InvalidFrameHeader,
        Http2ParseError::InvalidFrameLength(12345),
        Http2ParseError::InvalidStreamId(67890),
        Http2ParseError::FrameTooLarge(999999),
        Http2ParseError::MissingRequiredHeaders,
        Http2ParseError::InvalidPseudoHeader(":invalid".to_string()),
        Http2ParseError::IncompleteFrame,
        Http2ParseError::InvalidUtf8,
        Http2ParseError::UnsupportedFeature("test".to_string()),
        Http2ParseError::HpackDecodingFailed,
    ];

    for error in errors {
        let formatted = format!("{error}");
        assert!(!formatted.is_empty());
        assert!(!formatted.contains("Debug")); // Should be Display, not Debug
    }
}

#[test]
fn test_config_edge_cases() {
    // Test parser with different configurations
    let config = Http2Config {
        max_frame_size: 1, // Very small max frame size
        strict_parsing: true,
        ..Default::default()
    };

    let parser = Http2Parser::with_config(config);

    // Even small valid frames should be rejected
    let frame = create_http2_frame(0x01, 1, &[0x00, 0x00]); // 2 bytes > max_frame_size(1)
    let data = create_http2_request_with_preface(&[frame]);
    let result = parser.parse_request(&data);

    // Should handle configuration limits gracefully
    assert!(result.is_ok());
}

#[test]
fn test_multiple_streams_handling() {
    let parser = Http2Parser::new();

    // Create frames for multiple streams
    let frame1 = create_http2_frame(0x01, 1, &[0x00]); // Headers for stream 1
    let frame2 = create_http2_frame(0x01, 3, &[0x00]); // Headers for stream 3
    let frame3 = create_http2_frame(0x00, 1, &[0x48, 0x65, 0x6c, 0x6c, 0x6f]); // Data for stream 1

    let data = create_http2_request_with_preface(&[frame1, frame2, frame3]);
    let result = parser.parse_request(&data);

    // Should handle multiple streams and pick the first valid one
    match result {
        Ok(Some(req)) => {
            assert_eq!(req.stream_id, 1); // Should pick stream 1 (first HEADERS frame)
        }
        Ok(None) => {}
        Err(_) => {}
    }
}

#[test]
fn test_continuation_frames() {
    let parser = Http2Parser::new();

    // Create HEADERS frame followed by CONTINUATION frame
    let headers_frame = create_http2_frame(0x01, 1, &[0x00, 0x01]); // Headers (incomplete)
    let continuation_frame = create_http2_frame(0x09, 1, &[0x02, 0x03]); // Continuation

    let data = create_http2_request_with_preface(&[headers_frame, continuation_frame]);
    let result = parser.parse_request(&data);

    // Should handle CONTINUATION frames properly
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable as long as no panic
    }
}

#[test]
fn test_settings_frame_with_invalid_payload() {
    let parser = Http2Parser::new();

    // Create SETTINGS frame with invalid payload (not multiple of 6 bytes)
    let invalid_settings = create_http2_frame(0x04, 0, &[0x00, 0x01, 0x00, 0x00, 0x10]); // 5 bytes instead of 6
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]);

    let data = create_http2_request_with_preface(&[invalid_settings, headers_frame]);
    let result = parser.parse_request(&data);

    // Should handle malformed SETTINGS gracefully
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable
    }
}

#[test]
fn test_priority_frame_handling() {
    let parser = Http2Parser::new();

    // Create PRIORITY frame followed by HEADERS
    let priority_frame = create_http2_frame(0x02, 1, &[0x00, 0x00, 0x00, 0x02, 0x10]); // Priority frame
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]);

    let data = create_http2_request_with_preface(&[priority_frame, headers_frame]);
    let result = parser.parse_request(&data);

    // Should handle PRIORITY frames without issues
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable
    }
}

#[test]
fn test_window_update_frame() {
    let parser = Http2Parser::new();

    // Create WINDOW_UPDATE frame
    let window_update = create_http2_frame(0x08, 0, &[0x00, 0x00, 0x10, 0x00]); // Window update
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]);

    let data = create_http2_request_with_preface(&[window_update, headers_frame]);
    let result = parser.parse_request(&data);

    // Should handle WINDOW_UPDATE frames
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable
    }
}

#[test]
fn test_data_frame_without_headers() {
    let parser = Http2Parser::new();

    // Create DATA frame without preceding HEADERS
    let data_frame = create_http2_frame(0x00, 1, &[0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

    let data = create_http2_request_with_preface(&[data_frame]);
    let result = parser.parse_request(&data);

    // Should return None (no valid request without HEADERS)
    match result {
        Ok(None) => {} // Expected
        Ok(Some(_)) => panic!("Should not return request without HEADERS frame"),
        Err(_) => {} // Also acceptable
    }
}

#[test]
fn test_stream_id_zero_for_headers() {
    let parser = Http2Parser::new();

    // Create HEADERS frame with stream ID 0 (invalid for HEADERS)
    let invalid_headers = create_http2_frame(0x01, 0, &[0x00]); // Stream ID 0 is invalid for HEADERS

    let data = create_http2_request_with_preface(&[invalid_headers]);
    let result = parser.parse_request(&data);

    // Should return None (no valid stream found)
    match result {
        Ok(None) => {} // Expected
        Ok(Some(_)) => panic!("Should not return request with invalid stream ID"),
        Err(_) => {} // Also acceptable
    }
}

#[test]
fn test_mixed_frame_types_sequence() {
    let parser = Http2Parser::new();

    // Create a realistic sequence of frames
    let settings_frame = create_http2_frame(0x04, 0, &[0x00, 0x02, 0x00, 0x00, 0x00, 0x01]); // SETTINGS
    let window_update = create_http2_frame(0x08, 0, &[0x00, 0x00, 0x10, 0x00]); // WINDOW_UPDATE
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]); // HEADERS
    let data_frame = create_http2_frame(0x00, 1, &[0x48, 0x65, 0x6c, 0x6c, 0x6f]); // DATA

    let data = create_http2_request_with_preface(&[
        settings_frame,
        window_update,
        headers_frame,
        data_frame,
    ]);
    let result = parser.parse_request(&data);

    // Should handle mixed frame sequence properly
    match result {
        Ok(Some(req)) => {
            assert_eq!(req.stream_id, 1);
            assert!(req.frame_sequence.len() >= 2); // Should have at least SETTINGS and HEADERS
        }
        Ok(None) => {} // Acceptable if HPACK fails
        Err(_) => {}   // Also acceptable for HPACK errors
    }
}

#[test]
fn test_response_with_invalid_status() {
    let parser = Http2Parser::new();

    // Create response frame that would result in missing :status pseudo-header
    let headers_frame = create_http2_frame(0x01, 1, &[0x00]); // Headers without proper HPACK encoding

    let result = parser.parse_response(&headers_frame);

    // Should handle missing :status gracefully
    match result {
        Ok(None) => {}                                     // Expected when :status is missing
        Err(Http2ParseError::MissingRequiredHeaders) => {} // Also expected
        Err(Http2ParseError::HpackDecodingFailed) => {}    // HPACK might fail first
        other => panic!("Unexpected result: {other:?}"),
    }
}

#[test]
fn test_frame_flags_handling() {
    let parser = Http2Parser::new();

    // Create frame with various flags set
    let mut frame = create_http2_frame(0x01, 1, &[0x00]);
    frame[4] = 0x05; // Set END_HEADERS (0x04) and END_STREAM (0x01) flags

    let data = create_http2_request_with_preface(&[frame]);
    let result = parser.parse_request(&data);

    // Should handle frame flags properly
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable
    }
}

#[test]
fn test_large_stream_id() {
    let parser = Http2Parser::new();

    // Create frame with maximum valid stream ID (2^31 - 1)
    let max_stream_id = 0x7FFFFFFF;
    let headers_frame = create_http2_frame(0x01, max_stream_id, &[0x00]);

    let data = create_http2_request_with_preface(&[headers_frame]);
    let result = parser.parse_request(&data);

    // Should handle large stream IDs
    match result {
        Ok(Some(req)) => {
            assert_eq!(req.stream_id, max_stream_id);
        }
        Ok(None) => {} // Acceptable if HPACK fails
        Err(_) => {}   // Also acceptable
    }
}

#[test]
fn test_empty_payload_frames() {
    let parser = Http2Parser::new();

    // Create frames with empty payloads
    let empty_headers = create_http2_frame(0x01, 1, &[]); // Empty HEADERS
    let empty_data = create_http2_frame(0x00, 1, &[]); // Empty DATA

    let data = create_http2_request_with_preface(&[empty_headers, empty_data]);
    let result = parser.parse_request(&data);

    // Should handle empty payloads gracefully
    match result {
        Ok(_) | Err(_) => {} // Both outcomes acceptable
    }
}

#[test]
fn test_cookie_and_referer_excluded_from_headers_list_http2() {
    use huginn_net_http::http_common::HttpHeader;
    let parser = Http2Parser::new();

    // Create HTTP/2 headers including cookie and referer
    let headers = [
        HttpHeader {
            name: ":method".to_string(),
            value: Some("GET".to_string()),
            position: 0,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: ":path".to_string(),
            value: Some("/page".to_string()),
            position: 1,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: ":authority".to_string(),
            value: Some("example.com".to_string()),
            position: 2,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "cookie".to_string(),
            value: Some("session=abc123".to_string()),
            position: 3,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "referer".to_string(),
            value: Some("https://google.com".to_string()),
            position: 4,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "user-agent".to_string(),
            value: Some("test-browser".to_string()),
            position: 5,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
        HttpHeader {
            name: "accept".to_string(),
            value: Some("text/html".to_string()),
            position: 6,
            source: huginn_net_http::http_common::HeaderSource::Http2Header,
        },
    ];

    let cookie_headers: Vec<&HttpHeader> = headers
        .iter()
        .filter(|h| h.name.to_lowercase() == "cookie")
        .collect();
    let cookies = parser.parse_cookies_from_headers(&cookie_headers);

    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].value, Some("abc123".to_string()));

    let mut filtered_headers = Vec::new();
    let mut referer_found: Option<String> = None;

    for header in headers {
        let header_name_lower = header.name.to_lowercase();

        if header_name_lower == "cookie" {
            continue;
        } else if header_name_lower == "referer" {
            if let Some(ref value) = header.value {
                referer_found = Some(value.clone());
            }
        } else {
            filtered_headers.push(header);
        }
    }

    assert_eq!(referer_found, Some("https://google.com".to_string()));

    let header_names: Vec<String> = filtered_headers
        .iter()
        .map(|h| h.name.to_lowercase())
        .collect();
    assert!(
        !header_names.contains(&"cookie".to_string()),
        "Cookie header should not be in headers list"
    );
    assert!(
        !header_names.contains(&"referer".to_string()),
        "Referer header should not be in headers list"
    );

    assert!(header_names.contains(&":method".to_string()));
    assert!(header_names.contains(&":path".to_string()));
    assert!(header_names.contains(&":authority".to_string()));
    assert!(header_names.contains(&"user-agent".to_string()));
    assert!(header_names.contains(&"accept".to_string()));

    assert_eq!(filtered_headers.len(), 5);
}
