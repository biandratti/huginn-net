use crate::error::HuginnNetError;
use crate::http::Header;
use crate::http_common::HttpProcessor;
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, http2_parser, http_common, http_languages};
use tracing::debug;

/// HTTP/2 Protocol Processor
///
/// Implements the HttpProcessor trait for HTTP/2 protocol.
/// Handles both request and response processing with proper protocol detection.
/// Contains a parser instance that is created once and reused.
pub struct Http2Processor {
    parser: http2_parser::Http2Parser<'static>,
}

impl Http2Processor {
    pub fn new() -> Self {
        Self {
            parser: http2_parser::Http2Parser::new(),
        }
    }
}

impl Default for Http2Processor {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProcessor for Http2Processor {
    fn can_process_request(&self, data: &[u8]) -> bool {
        // VERY SPECIFIC: HTTP/2 requests MUST start with exact connection preface
        if data.len() < 24 {
            // Minimum for preface
            return false;
        }

        // SPECIFIC: Must start with exact HTTP/2 connection preface
        http2_parser::is_http2_traffic(data)
    }

    fn can_process_response(&self, data: &[u8]) -> bool {
        // VERY SPECIFIC: HTTP/2 responses are frame-based, not text-based
        if data.len() < 9 {
            // Minimum frame header size
            return false;
        }

        // SPECIFIC: Must NOT look like HTTP/1.x first
        let data_str = String::from_utf8_lossy(&data[..data.len().min(20)]);
        if data_str.starts_with("HTTP/1.") {
            return false;
        }

        // SPECIFIC: Must look like valid HTTP/2 frame
        looks_like_http2_response(data)
    }

    fn has_complete_data(&self, data: &[u8]) -> bool {
        has_complete_data(data)
    }

    fn process_request(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
        parse_http2_request(data, &self.parser)
    }

    fn process_response(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
        parse_http2_response(data, &self.parser)
    }

    fn supported_version(&self) -> http::Version {
        http::Version::V20
    }

    fn name(&self) -> &'static str {
        "HTTP/2"
    }
}

fn convert_http2_request_to_observable(req: http2_parser::Http2Request) -> ObservableHttpRequest {
    // Create map once for all lookups (only headers with values)
    let mut headers_map = std::collections::HashMap::new();
    for header in &req.headers {
        if let Some(ref value) = header.value {
            headers_map.insert(header.name.to_lowercase(), value.as_str());
        }
    }

    let lang = headers_map
        .get("accept-language")
        .and_then(|accept_language| {
            http_languages::get_highest_quality_language(accept_language.to_string())
        });

    let headers_in_order = convert_http2_headers_to_http_format(&req.headers, true);
    let headers_absent = build_absent_headers_from_http2(&req.headers, true);

    let user_agent = headers_map.get("user-agent").map(|s| s.to_string());

    ObservableHttpRequest {
        matching: huginn_net_db::observable_signals::HttpRequestObservation {
            version: req.version,
            horder: headers_in_order,
            habsent: headers_absent,
            expsw: extract_traffic_classification(user_agent.as_deref()),
        },
        lang,
        user_agent,
        headers: req.headers,
        cookies: req.cookies.clone(),
        referer: req.referer.clone(),
        method: Some(req.method),
        uri: Some(req.path),
    }
}

fn convert_http2_response_to_observable(
    res: http2_parser::Http2Response,
) -> ObservableHttpResponse {
    let headers_in_order = convert_http2_headers_to_http_format(&res.headers, false);
    let headers_absent = build_absent_headers_from_http2(&res.headers, false);

    ObservableHttpResponse {
        matching: huginn_net_db::observable_signals::HttpResponseObservation {
            version: res.version,
            horder: headers_in_order,
            habsent: headers_absent,
            expsw: extract_traffic_classification(res.server.as_deref()),
        },
        headers: res.headers,
        status_code: Some(res.status),
    }
}

fn convert_http2_headers_to_http_format(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<Header> {
    let mut headers_in_order: Vec<Header> = Vec::new();
    let optional_list = if is_request {
        http::request_optional_headers()
    } else {
        http::response_optional_headers()
    };
    let skip_value_list = if is_request {
        http::request_skip_value_headers()
    } else {
        http::response_skip_value_headers()
    };

    for header in headers {
        let header_name_lower = header.name.to_lowercase();
        if optional_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name).optional());
        } else if skip_value_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name));
        } else {
            headers_in_order
                .push(http::Header::new(&header.name).with_optional_value(header.value.clone()));
        }
    }

    headers_in_order
}

fn build_absent_headers_from_http2(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<Header> {
    let mut headers_absent: Vec<Header> = Vec::new();
    let common_list: Vec<&str> = if is_request {
        http::request_common_headers()
    } else {
        http::response_common_headers()
    };
    let current_headers: Vec<String> = headers.iter().map(|h| h.name.to_lowercase()).collect();

    for header in &common_list {
        if !current_headers.contains(&header.to_lowercase()) {
            headers_absent.push(http::Header::new(header));
        }
    }
    headers_absent
}

fn parse_http2_request(
    data: &[u8],
    parser: &http2_parser::Http2Parser,
) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
    match parser.parse_request(data) {
        Ok(Some(req)) => {
            let observable = convert_http2_request_to_observable(req);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/2 request data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/2 request: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/2 request: {e}"
            )))
        }
    }
}

fn parse_http2_response(
    data: &[u8],
    parser: &http2_parser::Http2Parser,
) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
    match parser.parse_response(data) {
        Ok(Some(res)) => {
            let observable = convert_http2_response_to_observable(res);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/2 response data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/2 response: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/2 response: {e}"
            )))
        }
    }
}

fn extract_traffic_classification(value: Option<&str>) -> String {
    value.unwrap_or("???").to_string()
}

/// Check if data looks like HTTP/2 response (frames without preface)
pub fn looks_like_http2_response(data: &[u8]) -> bool {
    if data.len() < 9 {
        return false;
    }

    // HTTP/2 frame format: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream_id
    let frame_length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
    let frame_type = data[3];

    // Check if frame length is more than the default max frame size
    if frame_length > 16384 {
        return false;
    }

    // Check if frame type is valid HTTP/2 frame type
    // Common response frame types: HEADERS(1), DATA(0), SETTINGS(4), WINDOW_UPDATE(8)
    matches!(frame_type, 0..=10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use huginn_net_db;

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
}

/// Check if HTTP/2 data has complete frames for parsing
fn has_complete_data(data: &[u8]) -> bool {
    // For requests: Must have at least the connection preface
    if data.starts_with(crate::http2_parser::HTTP2_CONNECTION_PREFACE) {
        let frame_data = &data[crate::http2_parser::HTTP2_CONNECTION_PREFACE.len()..];
        return has_complete_frames(frame_data);
    }

    // For responses: No preface, check frames directly
    has_complete_frames(data)
}

/// Check if we have complete HTTP/2 frames (at least HEADERS frame)
fn has_complete_frames(data: &[u8]) -> bool {
    let mut remaining = data;

    while remaining.len() >= 9 {
        // Parse frame header (9 bytes)
        let length = u32::from_be_bytes([0, remaining[0], remaining[1], remaining[2]]);
        let frame_type_byte = remaining[3];
        let _flags = remaining[4];
        let stream_id =
            u32::from_be_bytes([remaining[5], remaining[6], remaining[7], remaining[8]])
                & 0x7FFF_FFFF;

        // Check if frame is complete
        let frame_total_size = match usize::try_from(9_u32.saturating_add(length)) {
            Ok(size) => size,
            Err(_) => return false, // Frame too large
        };

        if remaining.len() < frame_total_size {
            return false; // Incomplete frame
        }

        // Check if this is a HEADERS frame (type 0x1) with a valid stream ID
        if frame_type_byte == 0x1 && stream_id > 0 {
            // We need at least one complete HEADERS frame
            return true;
        }

        // Move to next frame
        remaining = &remaining[frame_total_size..];
    }

    false
}

#[cfg(test)]
mod frame_detection_tests {
    use super::*;
    use crate::http2_parser::HTTP2_CONNECTION_PREFACE;

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
}
