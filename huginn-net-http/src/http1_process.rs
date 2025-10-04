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
        Self {
            parser: http1_parser::Http1Parser::new(),
        }
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
fn has_complete_headers(data: &[u8]) -> bool {
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

fn convert_headers_to_http_format(
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

fn build_absent_headers_from_new_parser(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<Header> {
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

fn parse_http1_request(
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
            Err(HuginnNetHttpError::Parse(format!(
                "Failed to parse HTTP/1.x request: {e}"
            )))
        }
    }
}

fn parse_http1_response(
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
            Err(HuginnNetHttpError::Parse(format!(
                "Failed to parse HTTP/1.x response: {e}"
            )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use huginn_net_db;

    #[test]
    fn test_parse_http1_request() {
        let valid_request = b"GET / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n\
        Accept-Language: en-US,en;q=0.9,es;q=0.8\r\n\
        Cache-Control: max-age=0\r\n\
        Connection: keep-alive\r\n\
        If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT\r\n\
        If-None-Match: \"3147526947\"\r\n\
        Upgrade-Insecure-Requests: 1\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
        \r\n";
        let parser = http1_parser::Http1Parser::new();
        match parse_http1_request(valid_request, &parser) {
            Ok(Some(request)) => {
                assert_eq!(request.lang, Some("English".to_string()));
                assert_eq!(request.user_agent, Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()));
                assert_eq!(request.matching.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Host"),
                    http::Header::new("Accept").with_value("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                    http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
                    http::Header::new("Cache-Control").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                    http::Header::new("If-Modified-Since").optional(),
                    Header::new("If-None-Match").optional(),
                    http::Header::new("Upgrade-Insecure-Requests").with_value("1"),
                    http::Header::new("User-Agent"),
                ];
                assert_eq!(request.matching.horder, expected_horder);

                let expected_habsent = vec![
                    http::Header::new("Accept-Encoding"),
                    http::Header::new("Accept-Charset"),
                    http::Header::new("Keep-Alive"),
                ];
                assert_eq!(request.matching.habsent, expected_habsent);

                assert_eq!(request.matching.expsw, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
            }
            Ok(None) => panic!("Incomplete HTTP request"),
            Err(e) => panic!("Failed to parse HTTP request: {e}"),
        }
    }

    #[test]
    fn test_parse_http1_response() {
        let valid_response = b"HTTP/1.1 200 OK\r\n\
        Server: Apache\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        Content-Length: 112\r\n\
        Connection: keep-alive\r\n\
        \r\n\
        <html><body><h1>It works!</h1></body></html>";

        let parser = http1_parser::Http1Parser::new();
        match parse_http1_response(valid_response, &parser) {
            Ok(Some(response)) => {
                assert_eq!(response.matching.expsw, "Apache");
                assert_eq!(response.matching.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Server"),
                    http::Header::new("Content-Type"),
                    http::Header::new("Content-Length").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                ];
                assert_eq!(response.matching.horder, expected_horder);

                let expected_absent = vec![
                    http::Header::new("Keep-Alive"),
                    http::Header::new("Accept-Ranges"),
                    http::Header::new("Date"),
                ];
                assert_eq!(response.matching.habsent, expected_absent);
            }
            Ok(None) => panic!("Incomplete HTTP response"),
            Err(e) => panic!("Failed to parse HTTP response: {e}"),
        }
    }

    #[test]
    fn test_get_diagnostic_for_empty_sw() {
        let diagnosis: http::HttpDiagnosis = http_common::get_diagnostic(None, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
    }

    #[test]
    fn test_get_diagnostic_with_existing_signature_matcher() {
        let user_agent: Option<String> = Some("Mozilla/5.0".to_string());
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
    fn test_get_diagnostic_with_dishonest_user_agent() {
        let user_agent = Some("Mozilla/5.0".to_string());
        let os = "Windows".to_string();
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
        assert_eq!(diagnosis, http::HttpDiagnosis::Dishonest);
    }

    #[test]
    fn test_get_diagnostic_without_user_agent_and_signature_matcher() {
        let user_agent = Some("Mozilla/5.0".to_string());

        let diagnosis = http_common::get_diagnostic(user_agent, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::None);
    }

    #[test]
    fn test_incomplete_headers() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n";
        assert!(!has_complete_headers(data));
    }

    #[test]
    fn test_complete_headers() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n";
        assert!(has_complete_headers(data));
    }

    #[test]
    fn test_complete_headers_with_body() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\nbody data here";
        assert!(has_complete_headers(data));
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        assert!(!has_complete_headers(data));
    }

    #[test]
    fn test_too_short_data() {
        let data = b"GET";
        assert!(!has_complete_headers(data));
    }

    #[test]
    fn test_response_headers() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: id=123\r\n\r\n";
        assert!(has_complete_headers(data));
    }
}
