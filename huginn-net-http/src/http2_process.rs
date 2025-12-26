use crate::error::HuginnNetHttpError;
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
        Self { parser: http2_parser::Http2Parser::new() }
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
    ) -> Result<Option<ObservableHttpRequest>, HuginnNetHttpError> {
        parse_http2_request(data, &self.parser)
    }

    fn process_response(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpResponse>, HuginnNetHttpError> {
        parse_http2_response(data, &self.parser)
    }

    fn supported_version(&self) -> http::Version {
        http::Version::V20
    }

    fn name(&self) -> &'static str {
        "HTTP/2"
    }
}

pub fn convert_http2_request_to_observable(
    req: http2_parser::Http2Request,
) -> ObservableHttpRequest {
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

pub fn convert_http2_response_to_observable(
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

/// Parse HTTP/2 request and convert to ObservableHttpRequest
///
/// This function parses HTTP/2 request data and converts it to an ObservableHttpRequest
/// that can be used for fingerprinting and analysis.
pub fn parse_http2_request(
    data: &[u8],
    parser: &http2_parser::Http2Parser,
) -> Result<Option<ObservableHttpRequest>, HuginnNetHttpError> {
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
            Err(HuginnNetHttpError::Parse(format!("Failed to parse HTTP/2 request: {e}")))
        }
    }
}

fn parse_http2_response(
    data: &[u8],
    parser: &http2_parser::Http2Parser,
) -> Result<Option<ObservableHttpResponse>, HuginnNetHttpError> {
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
            Err(HuginnNetHttpError::Parse(format!("Failed to parse HTTP/2 response: {e}")))
        }
    }
}

pub fn extract_traffic_classification(value: Option<&str>) -> String {
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

/// Check if HTTP/2 data has complete frames for parsing
pub fn has_complete_data(data: &[u8]) -> bool {
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
