use crate::db::Label;
use crate::error::HuginnNetError;
use crate::http_common::HttpProcessor;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, http2_parser, http_common, http_languages};
use tracing::debug;

/// HTTP/2 Protocol Processor
///
/// Implements the HttpProcessor trait for HTTP/2 protocol.
/// Handles both request and response processing with proper protocol detection.
/// Contains a parser instance that is created once and reused.
///
/// # Usage
///
/// ```rust
/// use huginn_net::http2_process::Http2Processor;
/// use huginn_net::http_common::HttpProcessor;
///
/// let processor = Http2Processor::new();
/// if processor.can_process_request(data) {
///     let result = processor.process_request(data)?;
/// }
/// ```
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
    let lang = req
        .headers_map
        .get("accept-language")
        .and_then(|accept_language| {
            http_languages::get_highest_quality_language(accept_language.clone())
        });

    let headers_in_order = convert_http2_headers_to_http_format(&req.headers, true);
    let headers_absent = build_absent_headers_from_http2(&req.headers, true);

    let user_agent = req.headers_map.get("user-agent").cloned();

    ObservableHttpRequest {
        lang,
        user_agent: user_agent.clone(),
        version: req.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(user_agent),
        raw_headers: req.headers_map,
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
        version: res.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(res.server),
        raw_headers: res.headers_map,
        status_code: Some(res.status),
    }
}

fn convert_http2_headers_to_http_format(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<http::Header> {
    let mut headers_in_order: Vec<http::Header> = Vec::new();
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
        let value: Option<&str> = Some(&header.value);

        let header_name_lower = header.name.to_lowercase();

        if optional_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name).optional());
        } else if skip_value_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name));
        } else {
            headers_in_order.push(http::Header::new(&header.name).with_optional_value(value));
        }
    }

    headers_in_order
}

fn build_absent_headers_from_http2(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<http::Header> {
    let mut headers_absent: Vec<http::Header> = Vec::new();
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

fn extract_traffic_classification(value: Option<String>) -> String {
    value.unwrap_or_else(|| "???".to_string())
}

pub fn get_diagnostic(
    user_agent: Option<String>,
    ua_matcher: Option<(&String, &Option<String>)>,
    signature_os_matcher: Option<&Label>,
) -> http::HttpDiagnosis {
    match user_agent {
        None => http::HttpDiagnosis::Anonymous,
        Some(_ua) => match (ua_matcher, signature_os_matcher) {
            (Some((ua_name_db, _ua_flavor_db)), Some(signature_label_db)) => {
                if ua_name_db.eq_ignore_ascii_case(&signature_label_db.name) {
                    http::HttpDiagnosis::Generic
                } else {
                    http::HttpDiagnosis::Dishonest
                }
            }
            _ => http::HttpDiagnosis::None,
        },
    }
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
    use crate::db;

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
            headers_map: std::collections::HashMap::new(),
            cookies: vec![],
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

        assert_eq!(observable.version, http::Version::V20);
        assert_eq!(observable.method, Some("GET".to_string()));
        assert_eq!(observable.uri, Some("/test".to_string()));
    }

    #[test]
    fn test_http2_response_conversion() {
        let res = http2_parser::Http2Response {
            status: 200,
            version: http::Version::V20,
            headers: vec![],
            headers_map: std::collections::HashMap::new(),
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

        assert_eq!(observable.version, http::Version::V20);
        assert_eq!(observable.status_code, Some(200));
        assert_eq!(observable.expsw, "nginx/1.20");
    }

    #[test]
    fn test_get_diagnostic_for_http2() {
        let diagnosis = get_diagnostic(None, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
    }

    #[test]
    fn test_get_diagnostic_with_http2_user_agent() {
        let user_agent = Some("Mozilla/5.0 HTTP/2.0".to_string());
        let os = "Linux".to_string();
        let browser = Some("Firefox".to_string());
        let ua_matcher: Option<(&String, &Option<String>)> = Some((&os, &browser));
        let label = db::Label {
            ty: db::Type::Specified,
            class: None,
            name: "Linux".to_string(),
            flavor: None,
        };
        let signature_os_matcher: Option<&db::Label> = Some(&label);

        let diagnosis = get_diagnostic(user_agent, ua_matcher, signature_os_matcher);
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
}
