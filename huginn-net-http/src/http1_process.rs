use crate::error::HuginnNetHttpError;
use crate::http::Header;
use crate::http_common::HttpProcessor;
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, http1_parser, http2_parser, http2_process, http_common, http_languages};
use tracing::debug;

/// HTTP/1.x Protocol Processor
///
/// Implements the HttpProcessor trait for HTTP/1.0 and HTTP/1.1 protocols.
/// Handles both request and response processing with proper protocol detection.
/// Contains a parser instance that is created once and reused.
pub struct Http1Processor {
    parser: http1_parser::Http1Parser,
}

impl Http1Processor {
    pub fn new() -> Self {
        Self { parser: http1_parser::Http1Parser::new() }
    }
}

impl Default for Http1Processor {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProcessor for Http1Processor {
    fn can_process_request(&self, data: &[u8]) -> bool {
        if data.len() < 16 {
            // Minimum for "GET / HTTP/1.1\r\n"
            return false;
        }

        // VERY SPECIFIC: Must NOT be HTTP/2 first
        if http2_parser::is_http2_traffic(data) {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);
        let first_line = data_str.lines().next().unwrap_or("");

        // SPECIFIC: Must be exact HTTP/1.x request line format
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() != 3 {
            return false;
        }

        // SPECIFIC: Valid HTTP/1.x methods only
        let methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "TRACE",
            "CONNECT",
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
        ];

        // SPECIFIC: Must be exact HTTP/1.0 or HTTP/1.1
        methods.contains(&parts[0])
            && (parts[2] == "HTTP/1.0" || parts[2] == "HTTP/1.1")
            && !parts[1].is_empty() // Must have URI
    }

    fn can_process_response(&self, data: &[u8]) -> bool {
        if data.len() < 12 {
            // Minimum for "HTTP/1.1 200"
            return false;
        }

        // VERY SPECIFIC: Must NOT look like HTTP/2 frames
        if data.len() >= 9 && http2_process::looks_like_http2_response(data) {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);
        let first_line = data_str.lines().next().unwrap_or("");

        // SPECIFIC: Must be exact HTTP/1.x response line format
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return false;
        }

        // SPECIFIC: Must be exact HTTP/1.0 or HTTP/1.1 with valid status code
        (parts[0] == "HTTP/1.0" || parts[0] == "HTTP/1.1")
            && parts[1].len() == 3  // Status code must be 3 digits
            && parts[1].chars().all(|c| c.is_ascii_digit()) // Must be numeric
    }

    fn has_complete_data(&self, data: &[u8]) -> bool {
        has_complete_headers(data)
    }

    fn process_request(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpRequest>, HuginnNetHttpError> {
        parse_http1_request(data, &self.parser)
    }

    fn process_response(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpResponse>, HuginnNetHttpError> {
        parse_http1_response(data, &self.parser)
    }

    fn supported_version(&self) -> http::Version {
        http::Version::V11 // Primary version, but also supports V10
    }

    fn name(&self) -> &'static str {
        "HTTP/1.x"
    }
}

/// Check if HTTP/1.x headers are complete (lightweight verification)
pub fn has_complete_headers(data: &[u8]) -> bool {
    // Fast byte-level check for \r\n\r\n
    if data.len() < 4 {
        return false;
    }

    // Look for the header separator pattern
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r'
            && data.get(i.saturating_add(1)) == Some(&b'\n')
            && data.get(i.saturating_add(2)) == Some(&b'\r')
            && data.get(i.saturating_add(3)) == Some(&b'\n')
        {
            return true;
        }
    }
    false
}

fn convert_http1_request_to_observable(req: http1_parser::Http1Request) -> ObservableHttpRequest {
    let lang = req
        .accept_language
        .and_then(http_languages::get_highest_quality_language);

    let headers_in_order = convert_headers_to_http_format(&req.headers, true);
    let headers_absent = build_absent_headers_from_new_parser(&req.headers, true);

    ObservableHttpRequest {
        matching: huginn_net_db::observable_signals::HttpRequestObservation {
            version: req.version,
            horder: headers_in_order,
            habsent: headers_absent,
            expsw: extract_traffic_classification(req.user_agent.as_deref()),
        },
        lang,
        user_agent: req.user_agent.clone(),
        headers: req.headers,
        cookies: req.cookies.clone(),
        referer: req.referer.clone(),
        method: Some(req.method),
        uri: Some(req.uri),
    }
}

fn convert_http1_response_to_observable(
    res: http1_parser::Http1Response,
) -> ObservableHttpResponse {
    let headers_in_order = convert_headers_to_http_format(&res.headers, false);
    let headers_absent = build_absent_headers_from_new_parser(&res.headers, false);

    ObservableHttpResponse {
        matching: huginn_net_db::observable_signals::HttpResponseObservation {
            version: res.version,
            horder: headers_in_order,
            habsent: headers_absent,
            expsw: extract_traffic_classification(res.server.as_deref()),
        },
        headers: res.headers,
        status_code: Some(res.status_code),
    }
}

/// Convert HTTP headers to fingerprint format
/// Formats headers according to p0f-style fingerprinting rules.
pub fn convert_headers_to_http_format(
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
        if optional_list.contains(&header.name.as_str()) {
            headers_in_order.push(http::Header::new(&header.name).optional());
        } else if skip_value_list.contains(&header.name.as_str()) {
            headers_in_order.push(http::Header::new(&header.name));
        } else {
            headers_in_order
                .push(Header::new(&header.name).with_optional_value(header.value.clone()));
        }
    }

    headers_in_order
}

/// Build list of absent common headers for fingerprinting
/// Returns a list of common headers that are expected but not present in the request/response.
pub fn build_absent_headers_from_new_parser(
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
            headers_absent.push(Header::new(header));
        }
    }
    headers_absent
}

pub fn parse_http1_request(
    data: &[u8],
    parser: &http1_parser::Http1Parser,
) -> Result<Option<ObservableHttpRequest>, HuginnNetHttpError> {
    match parser.parse_request(data) {
        Ok(Some(req)) => {
            let observable = convert_http1_request_to_observable(req);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/1.x request data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/1.x request: {}", e);
            Err(HuginnNetHttpError::Parse(format!("Failed to parse HTTP/1.x request: {e}")))
        }
    }
}

pub fn parse_http1_response(
    data: &[u8],
    parser: &http1_parser::Http1Parser,
) -> Result<Option<ObservableHttpResponse>, HuginnNetHttpError> {
    match parser.parse_response(data) {
        Ok(Some(res)) => {
            let observable = convert_http1_response_to_observable(res);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/1.x response data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/1.x response: {}", e);
            Err(HuginnNetHttpError::Parse(format!("Failed to parse HTTP/1.x response: {e}")))
        }
    }
}

fn extract_traffic_classification(value: Option<&str>) -> String {
    value.unwrap_or("???").to_string()
}

/// Check if data looks like HTTP/1.x response
pub fn looks_like_http1_response(data: &[u8]) -> bool {
    if data.len() < 12 {
        // Minimum for "HTTP/1.1 200"
        return false;
    }

    // Must NOT look like HTTP/2 frames
    if data.len() >= 9 && http2_process::looks_like_http2_response(data) {
        return false;
    }

    let data_str = String::from_utf8_lossy(data);
    let first_line = data_str.lines().next().unwrap_or("");

    // Must be exact HTTP/1.x response line format
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }

    // Check HTTP version
    let version_str = parts[0];
    if version_str != "HTTP/1.0" && version_str != "HTTP/1.1" {
        return false;
    }

    // Check status code (must be 3 digits)
    let status_str = parts[1];
    status_str.len() == 3 && status_str.chars().all(|c| c.is_ascii_digit())
}
