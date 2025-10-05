use huginn_net_db;
use huginn_net_db::http;
use huginn_net_http::http2_parser::HTTP2_CONNECTION_PREFACE;
use huginn_net_http::http2_process::{
    convert_http2_request_to_observable, convert_http2_response_to_observable,
    extract_traffic_classification, has_complete_data, looks_like_http2_response, Http2Processor,
};
use huginn_net_http::http_common::HttpProcessor;
use huginn_net_http::{http2_parser, http_common};

#[test]
fn test_http2_request_conversion() {
    // Create a mock HTTP/2 request
    let req = http2_parser::Http2Request {
        method: "GET".to_string(),
        path: "/test".to_string(),
        authority: Some("example.com".to_string()),
        scheme: Some("https".to_string()),
        version: http::Version::V20,
        headers: vec![],
        cookies: vec![],
        referer: None,
        stream_id: 1,
        parsing_metadata: http_common::ParsingMetadata {
            header_count: 0,
            duplicate_headers: vec![],
            case_variations: std::collections::HashMap::new(),
            parsing_time_ns: 0,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: 0,
        },
        frame_sequence: vec![],
        settings: http2_parser::Http2Settings::default(),
    };

    let observable = convert_http2_request_to_observable(req);

    assert_eq!(observable.matching.version, http::Version::V20);
    assert_eq!(observable.method, Some("GET".to_string()));
    assert_eq!(observable.uri, Some("/test".to_string()));
}

#[test]
fn test_http2_response_conversion() {
    let res = http2_parser::Http2Response {
        status: 200,
        version: http::Version::V20,
        headers: vec![],
        stream_id: 1,
        parsing_metadata: http_common::ParsingMetadata {
            header_count: 0,
            duplicate_headers: vec![],
            case_variations: std::collections::HashMap::new(),
            parsing_time_ns: 0,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: 0,
        },
        frame_sequence: vec![],
        server: Some("nginx/1.20".to_string()),
        content_type: Some("text/html".to_string()),
    };

    let observable = convert_http2_response_to_observable(res);

    assert_eq!(observable.matching.version, http::Version::V20);
    assert_eq!(observable.status_code, Some(200));
    assert_eq!(observable.matching.expsw, "nginx/1.20");
}

#[test]
fn test_get_diagnostic_for_http2() {
    let diagnosis = http_common::get_diagnostic(None, None, None);
    assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
}

#[test]
fn test_get_diagnostic_with_http2_user_agent() {
    let user_agent = Some("Mozilla/5.0 HTTP/2.0".to_string());
    let os = "Linux".to_string();
    let browser = Some("Firefox".to_string());
    let ua_matcher: Option<(&String, &Option<String>)> = Some((&os, &browser));
    let label = huginn_net_db::Label {
        ty: huginn_net_db::Type::Specified,
        class: None,
        name: "Linux".to_string(),
        flavor: None,
    };
    let signature_os_matcher: Option<&huginn_net_db::Label> = Some(&label);

    let diagnosis = http_common::get_diagnostic(user_agent, ua_matcher, signature_os_matcher);
    assert_eq!(diagnosis, http::HttpDiagnosis::Generic);
}

#[test]
fn test_no_preface() {
    let data = b"GET /path HTTP/1.1\r\n";
    assert!(!has_complete_data(data));
}

#[test]
fn test_preface_only() {
    assert!(!has_complete_data(HTTP2_CONNECTION_PREFACE));
}

#[test]
fn test_incomplete_frame() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    // Add incomplete frame header (only 5 bytes instead of 9)
    data.extend_from_slice(&[0x00, 0x00, 0x04, 0x01, 0x00]);
    assert!(!has_complete_data(&data));
}

#[test]
fn test_complete_settings_frame_no_headers() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    // Add complete SETTINGS frame (type 0x4)
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, // Length: 0
        0x04, // Type: SETTINGS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0
    ]);
    assert!(!has_complete_data(&data)); // No HEADERS frame
}

#[test]
fn test_complete_headers_frame() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    // Add complete HEADERS frame (type 0x1) with stream ID 1
    data.extend_from_slice(&[
        0x00, 0x00, 0x04, // Length: 4
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload (4 bytes)
    ]);
    assert!(has_complete_data(&data));
}

#[test]
fn test_incomplete_headers_frame() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    // Add incomplete HEADERS frame (missing payload)
    data.extend_from_slice(&[
        0x00, 0x00, 0x04, // Length: 4
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, // Only 2 bytes of 4-byte payload
    ]);
    assert!(!has_complete_data(&data));
}

#[test]
fn test_headers_frame_stream_id_zero() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    // Add HEADERS frame with stream ID 0 (invalid)
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, // Length: 0
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0 (invalid)
    ]);
    assert!(!has_complete_data(&data)); // Stream ID 0 is invalid for HEADERS
}

#[test]
fn test_multiple_frames_with_headers() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();

    // Add SETTINGS frame first
    data.extend_from_slice(&[
        0x00, 0x00, 0x06, // Length: 6
        0x04, // Type: SETTINGS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        0x00, 0x02, 0x00, 0x00, 0x00, 0x01, // Setting: ENABLE_PUSH = 1
    ]);

    // Add HEADERS frame
    data.extend_from_slice(&[
        0x00, 0x00, 0x04, // Length: 4
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload (4 bytes)
    ]);

    assert!(has_complete_data(&data)); // Should find the HEADERS frame
}

#[test]
fn test_response_frame_detection() {
    // Test response without preface (just frames)
    let response_data = [
        0x00, 0x00, 0x04, // Length: 4
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload (4 bytes)
    ];

    assert!(has_complete_data(&response_data));
}

#[test]
fn test_frame_too_large() {
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();

    // Add frame with extremely large length (will cause overflow)
    data.extend_from_slice(&[
        0xFF, 0xFF, 0xFF, // Length: 16777215 (max 24-bit)
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
    ]);

    assert!(!has_complete_data(&data)); // Should reject oversized frame
}
#[test]
fn test_can_process_request_detection() {
    let processor = Http2Processor::new();

    // Valid HTTP/2 request with preface
    let mut valid_data = HTTP2_CONNECTION_PREFACE.to_vec();
    valid_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert!(processor.can_process_request(&valid_data));

    // HTTP/1.1 request
    let http1_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(!processor.can_process_request(http1_data));

    // Too short data
    let short_data = b"PRI * HTTP/2.0";
    assert!(!processor.can_process_request(short_data));

    // Invalid preface
    let invalid_preface = b"GET * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(!processor.can_process_request(invalid_preface));
}

#[test]
fn test_can_process_response_detection() {
    let processor = Http2Processor::new();

    // Valid HTTP/2 response frame
    let valid_response = [
        0x00, 0x00, 0x04, // Length: 4
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload
    ];
    assert!(processor.can_process_response(&valid_response));

    // HTTP/1.1 response
    let http1_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert!(!processor.can_process_response(http1_response));

    // Too short data
    let short_data = b"HTTP/2";
    assert!(!processor.can_process_response(short_data));

    // Invalid frame type
    let invalid_frame = [
        0x00, 0x00, 0x04, // Length: 4
        0xFF, // Type: Unknown (255)
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload
    ];
    assert!(!processor.can_process_response(&invalid_frame));
}

#[test]
fn test_looks_like_http2_response_edge_cases() {
    // Valid frame types (0-10)
    for frame_type in 0..=10 {
        let frame = [
            0x00, 0x00, 0x04,       // Length: 4
            frame_type, // Type: variable
            0x00,       // Flags: 0
            0x00, 0x00, 0x00, 0x01, // Stream ID: 1
            0x00, 0x00, 0x00, 0x00, // Payload
        ];
        assert!(
            looks_like_http2_response(&frame),
            "Frame type {frame_type} should be valid"
        );
    }

    // Invalid frame type (11+)
    let invalid_frame = [
        0x00, 0x00, 0x04, // Length: 4
        11,   // Type: Invalid
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
        0x00, 0x00, 0x00, 0x00, // Payload
    ];
    assert!(!looks_like_http2_response(&invalid_frame));

    // Frame too large (exceeds default max frame size)
    let large_frame = [
        0x00, 0x40, 0x01, // Length: 16385 (> 16384)
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
    ];
    assert!(!looks_like_http2_response(&large_frame));

    // Maximum valid frame size
    let max_frame = [
        0x00, 0x40, 0x00, // Length: 16384 (exactly max)
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
    ];
    assert!(looks_like_http2_response(&max_frame));
}

#[test]
fn test_processor_trait_methods() {
    let processor = Http2Processor::new();

    // Test trait methods
    assert_eq!(processor.supported_version(), http::Version::V20);
    assert_eq!(processor.name(), "HTTP/2");
}

#[test]
fn test_parse_http2_request_error_handling() {
    let processor = Http2Processor::new();

    // Invalid preface should return error
    let invalid_data = b"GET / HTTP/1.1\r\n\r\n";
    let result = processor.process_request(invalid_data);
    assert!(result.is_err());

    // Valid preface but no frames should return Ok(None)
    let result = processor.process_request(HTTP2_CONNECTION_PREFACE);
    match result {
        Ok(None) => {} // Expected
        Ok(Some(_)) => panic!("Should return None for preface without frames"),
        Err(e) => panic!("Should not error for valid preface: {e:?}"),
    }
}

#[test]
fn test_parse_http2_response_error_handling() {
    let processor = Http2Processor::new();

    // Empty data should return Ok(None)
    let result = processor.process_response(&[]);
    match result {
        Ok(None) => {} // Expected
        Ok(Some(_)) => panic!("Should return None for empty data"),
        Err(e) => panic!("Should not error for empty data: {e:?}"),
    }

    // Invalid frame should return error or None
    let invalid_frame = [0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let result = processor.process_response(&invalid_frame);
    // Should handle gracefully (either error or None)
    match result {
        Ok(None) => {} // Acceptable
        Err(_) => {}   // Also acceptable
        Ok(Some(_)) => panic!("Should not return valid response for invalid frame"),
    }
}

#[test]
fn test_extract_traffic_classification() {
    // Test with Some value
    assert_eq!(extract_traffic_classification(Some("test")), "test");

    // Test with None
    assert_eq!(extract_traffic_classification(None), "???");
}

#[test]
fn test_has_complete_data_edge_cases() {
    let processor = Http2Processor::new();

    // Empty data
    assert!(!processor.has_complete_data(&[]));

    // Only preface
    assert!(!processor.has_complete_data(HTTP2_CONNECTION_PREFACE));

    // Preface + incomplete frame header
    let mut data = HTTP2_CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&[0x00, 0x00, 0x04, 0x01]); // Only 4 bytes of 9-byte header
    assert!(!processor.has_complete_data(&data));

    // Response data (no preface) with valid frame
    let response_frame = [
        0x00, 0x00, 0x00, // Length: 0
        0x01, // Type: HEADERS
        0x00, // Flags: 0
        0x00, 0x00, 0x00, 0x01, // Stream ID: 1
    ];
    assert!(processor.has_complete_data(&response_frame));
}

#[test]
fn test_conversion_functions_with_complex_data() {
    // Test request conversion with all fields
    let req = http2_parser::Http2Request {
        method: "POST".to_string(),
        path: "/api/test".to_string(),
        authority: Some("api.example.com:443".to_string()),
        scheme: Some("https".to_string()),
        version: http::Version::V20,
        headers: vec![http_common::HttpHeader {
            name: "content-type".to_string(),
            value: Some("application/json".to_string()),
            position: 0,
            source: http_common::HeaderSource::Http2Header,
        }],
        cookies: vec![http_common::HttpCookie {
            name: "session".to_string(),
            value: Some("abc123".to_string()),
            position: 1,
        }],
        referer: Some("https://example.com".to_string()),
        stream_id: 3,
        parsing_metadata: http_common::ParsingMetadata {
            header_count: 1,
            duplicate_headers: vec![],
            case_variations: std::collections::HashMap::new(),
            parsing_time_ns: 12345,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: 25,
        },
        frame_sequence: vec![
            http2_parser::Http2FrameType::Settings,
            http2_parser::Http2FrameType::Headers,
            http2_parser::Http2FrameType::Data,
        ],
        settings: http2_parser::Http2Settings {
            header_table_size: Some(4096),
            enable_push: Some(false),
            max_concurrent_streams: Some(100),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(8192),
        },
    };

    let observable = convert_http2_request_to_observable(req);

    assert_eq!(observable.method, Some("POST".to_string()));
    assert_eq!(observable.uri, Some("/api/test".to_string()));
    assert_eq!(observable.matching.version, http::Version::V20);
    assert!(!observable.headers.is_empty());

    // Test response conversion with all fields
    let res = http2_parser::Http2Response {
        status: 201,
        version: http::Version::V20,
        headers: vec![
            http_common::HttpHeader {
                name: "server".to_string(),
                value: Some("nginx/1.20".to_string()),
                position: 0,
                source: http_common::HeaderSource::Http2Header,
            },
            http_common::HttpHeader {
                name: "content-type".to_string(),
                value: Some("text/html".to_string()),
                position: 1,
                source: http_common::HeaderSource::Http2Header,
            },
        ],
        stream_id: 5,
        parsing_metadata: http_common::ParsingMetadata {
            header_count: 2,
            duplicate_headers: vec![],
            case_variations: std::collections::HashMap::new(),
            parsing_time_ns: 54321,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: 30,
        },
        frame_sequence: vec![
            http2_parser::Http2FrameType::Headers,
            http2_parser::Http2FrameType::Data,
        ],
        server: Some("nginx/1.20".to_string()),
        content_type: Some("text/html".to_string()),
    };

    let observable = convert_http2_response_to_observable(res);

    assert_eq!(observable.status_code, Some(201));
    assert_eq!(observable.matching.version, http::Version::V20);
    assert!(!observable.headers.is_empty());
}
