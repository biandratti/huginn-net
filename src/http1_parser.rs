use crate::http;
use crate::http_common::{HeaderSource, HttpCookie, HttpHeader, ParsingMetadata};
use std::collections::HashMap;
use std::time::Instant;

pub struct Http1Config {
    pub max_headers: usize,
    pub max_request_line_length: usize,
    pub max_header_length: usize,
    pub preserve_header_order: bool,
    pub parse_cookies: bool,
    pub strict_parsing: bool,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self {
            max_headers: 100,
            max_request_line_length: 8192,
            max_header_length: 8192,
            preserve_header_order: true,
            parse_cookies: true,
            strict_parsing: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Http1Request {
    pub method: String,
    pub uri: String,
    pub version: http::Version,
    pub headers: Vec<HttpHeader>,
    pub cookies: Vec<HttpCookie>,
    pub referer: Option<String>,
    pub content_length: Option<usize>,
    pub transfer_encoding: Option<String>,
    pub connection: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub raw_request_line: String,
    pub parsing_metadata: ParsingMetadata,
}

#[derive(Debug, Clone)]
pub struct Http1Response {
    pub version: http::Version,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<HttpHeader>,
    pub content_length: Option<usize>,
    pub transfer_encoding: Option<String>,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub raw_status_line: String,
    pub parsing_metadata: ParsingMetadata,
}

#[derive(Debug, Clone)]
pub enum Http1ParseError {
    InvalidRequestLine(String),
    InvalidStatusLine(String),
    InvalidVersion(String),
    InvalidMethod(String),
    InvalidStatusCode(String),
    HeaderTooLong(usize),
    TooManyHeaders(usize),
    MalformedHeader(String),
    IncompleteData,
    InvalidUtf8,
}

impl std::fmt::Display for Http1ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequestLine(line) => write!(f, "Invalid request line: {line}"),
            Self::InvalidStatusLine(line) => write!(f, "Invalid status line: {line}"),
            Self::InvalidVersion(version) => write!(f, "Invalid HTTP version: {version}"),
            Self::InvalidMethod(method) => write!(f, "Invalid HTTP method: {method}"),
            Self::InvalidStatusCode(code) => write!(f, "Invalid status code: {code}"),
            Self::HeaderTooLong(len) => write!(f, "Header too long: {len} bytes"),
            Self::TooManyHeaders(count) => write!(f, "Too many headers: {count}"),
            Self::MalformedHeader(header) => write!(f, "Malformed header: {header}"),
            Self::IncompleteData => write!(f, "Incomplete HTTP data"),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in HTTP data"),
        }
    }
}

impl std::error::Error for Http1ParseError {}

/// HTTP/1.x Protocol Parser
///
/// Provides parsing capabilities for HTTP/1.0 and HTTP/1.1 requests and responses according to RFC 7230.
/// Supports header parsing, cookie extraction, and various configuration options for security and performance.
///
/// # Thread Safety
///
/// **This parser is thread-safe.** Unlike the HTTP/2 parser, this parser does not maintain internal state
/// and can be safely shared between threads or used concurrently.
pub struct Http1Parser {
    config: Http1Config,
}

impl Http1Parser {
    pub fn new() -> Self {
        Self {
            config: Http1Config::default(),
        }
    }
    pub fn parse_request(&self, data: &[u8]) -> Result<Option<Http1Request>, Http1ParseError> {
        let start_time = Instant::now();

        let data_str = std::str::from_utf8(data).map_err(|_| Http1ParseError::InvalidUtf8)?;

        if !data_str.contains("\r\n\r\n") && !data_str.contains("\n\n") {
            return Ok(None);
        }
        let lines: Vec<&str> = if data_str.contains("\r\n") {
            data_str.split("\r\n").collect()
        } else {
            data_str.split('\n').collect()
        };

        if lines.is_empty() {
            return Err(Http1ParseError::IncompleteData);
        }

        let (method, uri, version) = self.parse_request_line(lines[0])?;

        let header_end = lines
            .iter()
            .position(|line| line.is_empty())
            .unwrap_or(lines.len());

        let header_lines = &lines[1..header_end];
        let (all_headers, parsing_metadata) = self.parse_headers(header_lines)?;

        let mut headers = Vec::new();
        let mut headers_map = HashMap::new();
        let mut cookie_header_value: Option<String> = None;
        let mut referer: Option<String> = None;

        for header in all_headers {
            let header_name_lower = header.name.to_lowercase();

            if header_name_lower == "cookie" {
                if let Some(ref value) = header.value {
                    cookie_header_value = Some(value.clone());
                }
            } else if header_name_lower == "referer" {
                if let Some(ref value) = header.value {
                    referer = Some(value.clone());
                }
            } else {
                if let Some(ref value) = header.value {
                    headers_map
                        .entry(header_name_lower)
                        .or_insert(value.clone());
                }
                headers.push(header);
            }
        }

        let cookies = if self.config.parse_cookies {
            if let Some(cookie_header) = cookie_header_value {
                self.parse_cookies(&cookie_header)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let content_length = headers_map
            .get("content-length")
            .and_then(|v| v.parse().ok());

        let parsing_time = start_time.elapsed().as_nanos() as u64;

        let mut final_metadata = parsing_metadata;
        final_metadata.parsing_time_ns = parsing_time;
        final_metadata.request_line_length = lines[0].len();

        Ok(Some(Http1Request {
            method,
            uri,
            version,
            headers,
            cookies,
            referer,
            content_length,
            transfer_encoding: headers_map.get("transfer-encoding").cloned(),
            connection: headers_map.get("connection").cloned(),
            host: headers_map.get("host").cloned(),
            user_agent: headers_map.get("user-agent").cloned(),
            accept_language: headers_map.get("accept-language").cloned(),
            raw_request_line: lines[0].to_string(),
            parsing_metadata: final_metadata,
        }))
    }

    pub fn parse_response(&self, data: &[u8]) -> Result<Option<Http1Response>, Http1ParseError> {
        let start_time = Instant::now();

        let data_str = std::str::from_utf8(data).map_err(|_| Http1ParseError::InvalidUtf8)?;

        if !data_str.contains("\r\n\r\n") && !data_str.contains("\n\n") {
            return Ok(None);
        }
        let lines: Vec<&str> = if data_str.contains("\r\n") {
            data_str.split("\r\n").collect()
        } else {
            data_str.split('\n').collect()
        };

        if lines.is_empty() {
            return Err(Http1ParseError::IncompleteData);
        }

        let (version, status_code, reason_phrase) = self.parse_status_line(lines[0])?;

        let header_end = lines
            .iter()
            .position(|line| line.is_empty())
            .unwrap_or(lines.len());

        let header_lines = &lines[1..header_end];
        let (headers, parsing_metadata) = self.parse_headers(header_lines)?;

        let mut headers_map = HashMap::new();
        for header in &headers {
            if let Some(ref value) = header.value {
                headers_map
                    .entry(header.name.to_lowercase())
                    .or_insert(value.clone());
            }
        }

        let content_length = headers_map
            .get("content-length")
            .and_then(|v| v.parse().ok());

        let parsing_time = start_time.elapsed().as_nanos() as u64;

        let mut final_metadata = parsing_metadata;
        final_metadata.parsing_time_ns = parsing_time;

        Ok(Some(Http1Response {
            version,
            status_code,
            reason_phrase,
            headers,
            content_length,
            transfer_encoding: headers_map.get("transfer-encoding").cloned(),
            server: headers_map.get("server").cloned(),
            content_type: headers_map.get("content-type").cloned(),
            raw_status_line: lines[0].to_string(),
            parsing_metadata: final_metadata,
        }))
    }

    fn parse_request_line(
        &self,
        line: &str,
    ) -> Result<(String, String, http::Version), Http1ParseError> {
        if line.len() > self.config.max_request_line_length {
            return Err(Http1ParseError::InvalidRequestLine(format!(
                "Request line too long: {} bytes",
                line.len()
            )));
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(Http1ParseError::InvalidRequestLine(line.to_string()));
        }

        let method = parts[0].to_string();
        let uri = parts[1].to_string();
        let version = http::Version::parse(parts[2])
            .ok_or_else(|| Http1ParseError::InvalidVersion(parts[2].to_string()))?;

        // HTTP/1.x parser should only accept HTTP/1.0 and HTTP/1.1
        if !matches!(version, http::Version::V10 | http::Version::V11) {
            return Err(Http1ParseError::InvalidVersion(parts[2].to_string()));
        }

        if !self.is_valid_method(&method) {
            return Err(Http1ParseError::InvalidMethod(method));
        }

        Ok((method, uri, version))
    }

    fn parse_status_line(
        &self,
        line: &str,
    ) -> Result<(http::Version, u16, String), Http1ParseError> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(Http1ParseError::InvalidStatusLine(line.to_string()));
        }

        let version = http::Version::parse(parts[0])
            .ok_or_else(|| Http1ParseError::InvalidVersion(parts[0].to_string()))?;

        // HTTP/1.x parser should only accept HTTP/1.0 and HTTP/1.1
        if !matches!(version, http::Version::V10 | http::Version::V11) {
            return Err(Http1ParseError::InvalidVersion(parts[0].to_string()));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| Http1ParseError::InvalidStatusCode(parts[1].to_string()))?;
        let reason_phrase = parts.get(2).unwrap_or(&"").to_string();

        Ok((version, status_code, reason_phrase))
    }

    fn parse_headers(
        &self,
        lines: &[&str],
    ) -> Result<(Vec<HttpHeader>, ParsingMetadata), Http1ParseError> {
        if lines.len() > self.config.max_headers {
            return Err(Http1ParseError::TooManyHeaders(lines.len()));
        }

        let mut headers = Vec::new();
        let mut duplicate_headers = Vec::new();
        let mut case_variations: HashMap<String, Vec<String>> = HashMap::new();
        let mut has_malformed = false;
        let mut total_length: usize = 0;

        for (position, line) in lines.iter().enumerate() {
            if line.is_empty() {
                break;
            }

            total_length = total_length.saturating_add(line.len());

            if line.len() > self.config.max_header_length {
                return Err(Http1ParseError::HeaderTooLong(line.len()));
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line
                    .get(colon_pos.saturating_add(1)..)
                    .map(|v| v.trim().to_string());

                if name.is_empty() {
                    has_malformed = true;
                    if self.config.strict_parsing {
                        return Err(Http1ParseError::MalformedHeader(line.to_string()));
                    }
                    continue;
                }

                let name_lower = name.to_lowercase();
                case_variations
                    .entry(name_lower.clone())
                    .or_default()
                    .push(name.clone());
                if headers
                    .iter()
                    .any(|h: &HttpHeader| h.name.to_lowercase() == name_lower)
                {
                    duplicate_headers.push(name_lower.clone());
                }

                headers.push(HttpHeader {
                    name,
                    value,
                    position,
                    source: HeaderSource::Http1Line,
                });
            } else {
                has_malformed = true;
                if self.config.strict_parsing {
                    return Err(Http1ParseError::MalformedHeader(line.to_string()));
                }
            }
        }

        let metadata = ParsingMetadata {
            header_count: headers.len(),
            duplicate_headers,
            case_variations,
            parsing_time_ns: 0,
            has_malformed_headers: has_malformed,
            request_line_length: 0,
            total_headers_length: total_length,
        };

        Ok((headers, metadata))
    }

    /// HTTP/1.x cookie parsing - single cookie header with '; ' separation according to RFC 6265
    pub fn parse_cookies(&self, cookie_header: &str) -> Vec<HttpCookie> {
        let mut cookies = Vec::new();
        let mut position = 0;

        for cookie_str in cookie_header.split(';') {
            let cookie_str = cookie_str.trim();
            if cookie_str.is_empty() {
                continue;
            }

            if let Some(eq_pos) = cookie_str.find('=') {
                let name = cookie_str[..eq_pos].trim().to_string();
                let value = Some(
                    cookie_str
                        .get(eq_pos.saturating_add(1)..)
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                );
                cookies.push(HttpCookie {
                    name,
                    value,
                    position,
                });
            } else {
                cookies.push(HttpCookie {
                    name: cookie_str.to_string(),
                    value: None,
                    position,
                });
            }
            position = position.saturating_add(1);
        }

        cookies
    }

    fn is_valid_method(&self, method: &str) -> bool {
        matches!(
            method,
            "GET"
                | "POST"
                | "PUT"
                | "DELETE"
                | "HEAD"
                | "OPTIONS"
                | "PATCH"
                | "TRACE"
                | "CONNECT"
                | "PROPFIND"
                | "PROPPATCH"
                | "MKCOL"
                | "COPY"
                | "MOVE"
                | "LOCK"
                | "UNLOCK"
                | "MKCALENDAR"
                | "REPORT"
        )
    }
}

impl Default for Http1Parser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unwrap_parser_result<T>(result: Result<Option<T>, Http1ParseError>) -> T {
        match result {
            Ok(Some(value)) => value,
            Ok(None) => {
                panic!("Parser returned None when Some was expected")
            }
            Err(e) => {
                panic!("Parser failed with error: {e}")
            }
        }
    }

    fn assert_parser_none<T>(result: Result<Option<T>, Http1ParseError>) {
        match result {
            Ok(None) => {}
            Ok(Some(_)) => panic!("Expected None but got Some"),
            Err(e) => panic!("Expected None but got error: {e}"),
        }
    }

    #[test]
    fn test_parse_simple_request() {
        let parser = Http1Parser::new();
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

        let request = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/path");
        assert_eq!(request.version, http::Version::V11);
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.host, Some("example.com".to_string()));
        assert_eq!(request.user_agent, Some("test".to_string()));
    }

    #[test]
    fn test_parse_request_with_cookies() {
        let parser = Http1Parser::new();
        let data =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: name1=value1; name2=value2\r\n\r\n";

        let request = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(request.cookies.len(), 2);
        assert_eq!(request.cookies[0].name, "name1");
        assert_eq!(request.cookies[0].value, Some("value1".to_string()));
        assert_eq!(request.cookies[1].name, "name2");
        assert_eq!(request.cookies[1].value, Some("value2".to_string()));
    }

    #[test]
    fn test_parse_request_with_referer() {
        let parser = Http1Parser::new();
        let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nReferer: https://google.com/search\r\nUser-Agent: test-browser\r\n\r\n";

        let request = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/page");
        assert_eq!(request.host, Some("example.com".to_string()));
        assert_eq!(
            request.referer,
            Some("https://google.com/search".to_string())
        );
        assert_eq!(request.user_agent, Some("test-browser".to_string()));
    }

    #[test]
    fn test_parse_request_without_referer() {
        let parser = Http1Parser::new();
        let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-browser\r\n\r\n";

        let request = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/page");
        assert_eq!(request.host, Some("example.com".to_string()));
        assert_eq!(request.referer, None);
        assert_eq!(request.user_agent, Some("test-browser".to_string()));
    }

    #[test]
    fn test_cookie_and_referer_excluded_from_headers_list() {
        let parser = Http1Parser::new();
        let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\nReferer: https://google.com\r\nUser-Agent: test-browser\r\nAccept: text/html\r\n\r\n";

        let request = unwrap_parser_result(parser.parse_request(data));

        assert_eq!(request.cookies.len(), 1);
        assert_eq!(request.cookies[0].name, "session");
        assert_eq!(request.cookies[0].value, Some("abc123".to_string()));
        assert_eq!(request.referer, Some("https://google.com".to_string()));

        let header_names: Vec<String> = request
            .headers
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

        assert!(header_names.contains(&"host".to_string()));
        assert!(header_names.contains(&"user-agent".to_string()));
        assert!(header_names.contains(&"accept".to_string()));

        assert_eq!(request.headers.len(), 3);
    }

    #[test]
    fn test_parse_response() {
        let parser = Http1Parser::new();
        let data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";

        let response = unwrap_parser_result(parser.parse_response(data));
        assert_eq!(response.version, http::Version::V11);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason_phrase, "OK");
        assert_eq!(response.server, Some("nginx".to_string()));
        assert_eq!(response.content_type, Some("text/html".to_string()));
    }

    #[test]
    fn test_incomplete_request() {
        let parser = Http1Parser::new();
        let data = b"GET /path HTTP/1.1\r\nHost: example.com";

        assert_parser_none(parser.parse_request(data));
    }

    #[test]
    fn test_malformed_request_line() {
        let parser = Http1Parser::new();
        let data = b"INVALID REQUEST LINE\r\n\r\n";

        let result = parser.parse_request(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_order_preservation() {
        let parser = Http1Parser::new();
        let data =
            b"GET / HTTP/1.1\r\nZ-Header: first\r\nA-Header: second\r\nM-Header: third\r\n\r\n";

        let result = unwrap_parser_result(parser.parse_request(data));

        assert_eq!(result.headers[0].name, "Z-Header");
        assert_eq!(result.headers[0].position, 0);
        assert_eq!(result.headers[1].name, "A-Header");
        assert_eq!(result.headers[1].position, 1);
        assert_eq!(result.headers[2].name, "M-Header");
        assert_eq!(result.headers[2].position, 2);
    }

    #[test]
    fn test_case_variations_detection() {
        let parser = Http1Parser::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nHOST: example2.com\r\n\r\n";

        let result = unwrap_parser_result(parser.parse_request(data));

        assert!(result.parsing_metadata.case_variations.contains_key("host"));
        assert!(result
            .parsing_metadata
            .duplicate_headers
            .contains(&"host".to_string()));
    }

    // ========== SECURITY TESTS ==========

    #[test]
    fn test_extremely_long_request_line() {
        let parser = Http1Parser::new();

        // Create request line longer than max_request_line_length (8192)
        let long_path = "a".repeat(10000);
        let request_line = format!("GET /{long_path} HTTP/1.1");
        let data = format!("{request_line}\r\nHost: example.com\r\n\r\n");

        let result = parser.parse_request(data.as_bytes());
        assert!(result.is_err());

        if let Err(Http1ParseError::InvalidRequestLine(msg)) = result {
            assert!(msg.contains("too long"));
        } else {
            panic!("Expected InvalidRequestLine error");
        }
    }

    #[test]
    fn test_extremely_long_header() {
        let parser = Http1Parser::new();

        // Create header longer than max_header_length (8192)
        let long_value = "x".repeat(10000);
        let data = format!("GET / HTTP/1.1\r\nLong-Header: {long_value}\r\n\r\n");

        let result = parser.parse_request(data.as_bytes());
        assert!(result.is_err());

        if let Err(Http1ParseError::HeaderTooLong(len)) = result {
            assert!(len > 8192);
        } else {
            panic!("Expected HeaderTooLong error");
        }
    }

    #[test]
    fn test_too_many_headers() {
        let parser = Http1Parser::new();

        // Create more than max_headers (100)
        let mut data = String::from("GET / HTTP/1.1\r\n");
        for i in 0..150 {
            data.push_str(&format!("Header-{i}: value{i}\r\n"));
        }
        data.push_str("\r\n");

        let result = parser.parse_request(data.as_bytes());
        assert!(result.is_err());

        if let Err(Http1ParseError::TooManyHeaders(count)) = result {
            assert_eq!(count, 150);
        } else {
            panic!("Expected TooManyHeaders error");
        }
    }

    #[test]
    fn test_invalid_utf8_handling() {
        let parser = Http1Parser::new();

        // Create data with invalid UTF-8 sequences
        let mut data = Vec::from("GET / HTTP/1.1\r\nHost: ");
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // Invalid UTF-8
        data.extend_from_slice(b"\r\n\r\n");

        let result = parser.parse_request(&data);
        assert!(result.is_err());

        if let Err(Http1ParseError::InvalidUtf8) = result {
            // Expected
        } else {
            panic!("Expected InvalidUtf8 error");
        }
    }

    // ========== EDGE CASES ==========

    #[test]
    fn test_empty_data() {
        let parser = Http1Parser::new();

        assert_parser_none(parser.parse_request(b""));
        assert_parser_none(parser.parse_response(b""));
    }

    #[test]
    fn test_only_request_line() {
        let parser = Http1Parser::new();

        // No headers, no empty line
        let data = b"GET / HTTP/1.1";
        assert_parser_none(parser.parse_request(data));

        // With CRLF but no empty line
        let data = b"GET / HTTP/1.1\r\n";
        assert_parser_none(parser.parse_request(data));
    }

    #[test]
    fn test_different_line_endings() {
        let parser = Http1Parser::new();

        // Test with LF only (Unix style)
        let data_lf = b"GET / HTTP/1.1\nHost: example.com\n\n";
        let result_lf = unwrap_parser_result(parser.parse_request(data_lf));
        assert_eq!(result_lf.method, "GET");

        // Test with CRLF (Windows/HTTP standard)
        let data_crlf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result_crlf = unwrap_parser_result(parser.parse_request(data_crlf));
        assert_eq!(result_crlf.method, "GET");
    }

    #[test]
    fn test_malformed_headers() {
        let parser = Http1Parser::new();

        // Header without colon (non-strict mode)
        let data = b"GET / HTTP/1.1\r\nMalformed Header Without Colon\r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert!(result.parsing_metadata.has_malformed_headers);

        // Header with empty name
        let data = b"GET / HTTP/1.1\r\n: empty-name\r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert!(result.parsing_metadata.has_malformed_headers);
    }

    #[test]
    fn test_strict_parsing_mode() {
        let config = Http1Config {
            strict_parsing: true,
            ..Default::default()
        };
        let parser = Http1Parser { config };

        // Malformed header should fail in strict mode
        let data = b"GET / HTTP/1.1\r\nMalformed Header Without Colon\r\n\r\n";
        let result = parser.parse_request(data);
        assert!(result.is_err());

        if let Err(Http1ParseError::MalformedHeader(header)) = result {
            assert_eq!(header, "Malformed Header Without Colon");
        } else {
            panic!("Expected MalformedHeader error");
        }
    }

    #[test]
    fn test_invalid_methods() {
        let parser = Http1Parser::new();

        let invalid_methods = ["INVALID", "123", "", "G E T", "get"];

        for method in invalid_methods {
            let data = format!("{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let result = parser.parse_request(data.as_bytes());
            assert!(result.is_err(), "Method '{method}' should be invalid");
        }
    }

    #[test]
    fn test_valid_extended_methods() {
        let parser = Http1Parser::new();

        let valid_methods = [
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
        ];

        for method in valid_methods {
            let data = format!("{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let result = unwrap_parser_result(parser.parse_request(data.as_bytes()));
            assert_eq!(result.method, method);
        }
    }

    #[test]
    fn test_invalid_http_versions() {
        let parser = Http1Parser::new();

        let invalid_versions = ["HTTP/2.0", "HTTP/0.9", "HTTP/1.2", "HTTP/1", "HTTP", "1.1"];

        for version in invalid_versions {
            let data = format!("GET / {version}\r\nHost: example.com\r\n\r\n");
            let result = parser.parse_request(data.as_bytes());
            assert!(result.is_err(), "Version '{version}' should be invalid");
        }
    }

    #[test]
    fn test_invalid_status_codes() {
        let parser = Http1Parser::new();

        let invalid_codes = ["abc", "999999", "", "-1", "1.5"];

        for code in invalid_codes {
            let data = format!("HTTP/1.1 {code} OK\r\nServer: test\r\n\r\n");
            let result = parser.parse_response(data.as_bytes());
            assert!(result.is_err(), "Status code '{code}' should be invalid");
        }
    }

    #[test]
    fn test_edge_case_status_lines() {
        let parser = Http1Parser::new();

        // Status line without reason phrase
        let data = b"HTTP/1.1 404\r\nServer: test\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_response(data));
        assert_eq!(result.status_code, 404);
        assert_eq!(result.reason_phrase, "");

        // Status line with spaces in reason phrase
        let data = b"HTTP/1.1 404 Not Found Here\r\nServer: test\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_response(data));
        assert_eq!(result.status_code, 404);
        assert_eq!(result.reason_phrase, "Not Found Here");
    }

    #[test]
    fn test_cookie_parsing_edge_cases() {
        let parser = Http1Parser::new();

        let cookie_test_cases = vec![
            ("", 0),                               // Empty cookie header
            ("name=value", 1),                     // Simple cookie
            ("name=", 1),                          // Empty value
            ("name", 1),                           // No value
            ("name=value; other=test", 2),         // Multiple cookies
            ("  name  =  value  ; other=test", 2), // Whitespace handling
            ("name=value;", 1),                    // Trailing semicolon
            (";name=value", 1),                    // Leading semicolon
            ("name=value;;other=test", 2),         // Double semicolon
            ("name=value; ; other=test", 2),       // Empty cookie between
        ];

        for (cookie_str, expected_count) in cookie_test_cases {
            let data =
                format!("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: {cookie_str}\r\n\r\n");
            let result = unwrap_parser_result(parser.parse_request(data.as_bytes()));
            assert_eq!(
                result.cookies.len(),
                expected_count,
                "Failed for cookie: '{cookie_str}'"
            );
        }
    }

    #[test]
    fn test_parse_cookies_direct() {
        let parser = Http1Parser::new();

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
            let cookies = parser.parse_cookies(cookie_str);
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
                    assert_eq!(cookies[0].position, 0);
                }
                "name=" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("".to_string()));
                    assert_eq!(cookies[0].position, 0);
                }
                "name" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, None);
                    assert_eq!(cookies[0].position, 0);
                }
                "name=value; other=test" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("value".to_string()));
                    assert_eq!(cookies[0].position, 0);
                    assert_eq!(cookies[1].name, "other");
                    assert_eq!(cookies[1].value, Some("test".to_string()));
                    assert_eq!(cookies[1].position, 1);
                }
                "  name  =  value  " => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("value".to_string()));
                    assert_eq!(cookies[0].position, 0);
                }
                "name=value;" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("value".to_string()));
                    assert_eq!(cookies[0].position, 0);
                }
                ";name=value" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("value".to_string()));
                    assert_eq!(cookies[0].position, 0);
                }
                "name=value;;other=test" => {
                    assert_eq!(cookies[0].name, "name");
                    assert_eq!(cookies[0].value, Some("value".to_string()));
                    assert_eq!(cookies[0].position, 0);
                    assert_eq!(cookies[1].name, "other");
                    assert_eq!(cookies[1].value, Some("test".to_string()));
                    assert_eq!(cookies[1].position, 1);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_parse_cookies_rfc6265_compliance() {
        let parser = Http1Parser::new();

        // RFC 6265 examples - HTTP/1.x single cookie header format
        let rfc_cases = vec![
            (
                "session_id=abc123; user_id=456; theme=dark; lang=en",
                vec![
                    ("session_id", Some("abc123")),
                    ("user_id", Some("456")),
                    ("theme", Some("dark")),
                    ("lang", Some("en")),
                ],
            ),
            (
                "token=xyz; secure; httponly",
                vec![("token", Some("xyz")), ("secure", None), ("httponly", None)],
            ),
        ];

        for (cookie_str, expected_cookies) in rfc_cases {
            let cookies = parser.parse_cookies(cookie_str);
            assert_eq!(
                cookies.len(),
                expected_cookies.len(),
                "Failed for RFC case: '{cookie_str}'"
            );

            for (i, (expected_name, expected_value)) in expected_cookies.iter().enumerate() {
                assert_eq!(cookies[i].name, *expected_name);
                assert_eq!(cookies[i].value, expected_value.map(|v| v.to_string()));
                assert_eq!(cookies[i].position, i);
            }
        }
    }

    #[test]
    fn test_header_value_edge_cases() {
        let parser = Http1Parser::new();

        // Header with no value
        let data = b"GET / HTTP/1.1\r\nEmpty-Header:\r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        let empty_header = result.headers.iter().find(|h| h.name == "Empty-Header");
        assert!(empty_header.is_some(), "Empty-Header should be present");
        assert_eq!(
            empty_header.as_ref().and_then(|h| h.value.as_deref()),
            Some("")
        );

        // Header with only spaces as value
        let data = b"GET / HTTP/1.1\r\nSpaces-Header:   \r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        let spaces_header = result.headers.iter().find(|h| h.name == "Spaces-Header");
        assert!(spaces_header.is_some(), "Spaces-Header should be present");
        assert_eq!(
            spaces_header.as_ref().and_then(|h| h.value.as_deref()),
            Some("")
        );

        // Header with leading/trailing spaces
        let data =
            b"GET / HTTP/1.1\r\nTrim-Header:  value with spaces  \r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        let trim_header = result.headers.iter().find(|h| h.name == "Trim-Header");
        assert!(trim_header.is_some(), "Trim-Header should be present");
        assert_eq!(
            trim_header.as_ref().and_then(|h| h.value.as_deref()),
            Some("value with spaces")
        );
    }

    #[test]
    fn test_request_line_edge_cases() {
        let parser = Http1Parser::new();

        // Too few parts
        let data = b"GET HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parser.parse_request(data);
        assert!(result.is_err());

        // Too many parts (extra spaces)
        let data = b"GET / HTTP/1.1 extra\r\nHost: example.com\r\n\r\n";
        let result = parser.parse_request(data);
        assert!(result.is_err());

        // Empty method
        let data = b" / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parser.parse_request(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_content_length_parsing() {
        let parser = Http1Parser::new();

        // Valid content length
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(result.content_length, Some(42));

        // Invalid content length (non-numeric)
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(result.content_length, None);

        // Multiple content length headers (should use first valid one)
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\nContent-Length: 24\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(result.content_length, Some(42));
    }

    #[test]
    fn test_can_parse_detection() {
        use crate::http_process::HttpProcessors;
        let processors = HttpProcessors::new();

        // Valid HTTP/1.x requests - should be parseable
        assert!(processors
            .parse_request(b"GET / HTTP/1.1\r\n\r\n")
            .is_some());
        assert!(processors
            .parse_request(b"POST /api HTTP/1.0\r\n\r\n")
            .is_some());
        assert!(processors
            .parse_request(b"PUT /data HTTP/1.1\r\n\r\n")
            .is_some());

        // Valid HTTP/1.x responses - should be parseable
        assert!(processors
            .parse_response(b"HTTP/1.1 200 OK\r\n\r\n")
            .is_some());
        assert!(processors
            .parse_response(b"HTTP/1.0 404 Not Found\r\n\r\n")
            .is_some());

        // Invalid data - should not be parseable
        assert!(processors.parse_request(b"").is_none());
        assert!(processors.parse_request(b"short").is_none());
        assert!(processors.parse_request(b"INVALID DATA HERE").is_none());
        assert!(processors.parse_request(b"PRI * HTTP/2.0\r\n").is_none()); // HTTP/2 preface
    }

    #[test]
    fn test_error_display_formatting() {
        // Test that all error types format correctly
        let errors = vec![
            Http1ParseError::InvalidRequestLine("test".to_string()),
            Http1ParseError::InvalidStatusLine("test".to_string()),
            Http1ParseError::InvalidVersion("test".to_string()),
            Http1ParseError::InvalidMethod("test".to_string()),
            Http1ParseError::InvalidStatusCode("test".to_string()),
            Http1ParseError::HeaderTooLong(12345),
            Http1ParseError::TooManyHeaders(999),
            Http1ParseError::MalformedHeader("test".to_string()),
            Http1ParseError::IncompleteData,
            Http1ParseError::InvalidUtf8,
        ];

        for error in errors {
            let formatted = format!("{error}");
            assert!(!formatted.is_empty());
            assert!(!formatted.contains("Debug")); // Should be Display, not Debug
        }
    }

    #[test]
    fn test_config_limits() {
        // Test with very restrictive config
        let config = Http1Config {
            max_headers: 2,
            max_request_line_length: 50,
            max_header_length: 30,
            preserve_header_order: true,
            parse_cookies: false,
            strict_parsing: true,
        };
        let parser = Http1Parser { config };

        // Should work within limits
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = unwrap_parser_result(parser.parse_request(data));
        assert_eq!(result.method, "GET");
        assert!(result.cookies.is_empty()); // Cookie parsing disabled

        // Should fail when exceeding header count limit
        let data =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";
        let result = parser.parse_request(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_performance_metadata() {
        let parser = Http1Parser::new();
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

        let result = unwrap_parser_result(parser.parse_request(data));

        // Verify metadata is populated
        assert!(result.parsing_metadata.parsing_time_ns > 0);
        assert_eq!(result.parsing_metadata.header_count, 2);
        assert_eq!(
            result.parsing_metadata.request_line_length,
            "GET /path HTTP/1.1".len()
        );
        assert!(result.parsing_metadata.total_headers_length > 0);
        assert!(!result.parsing_metadata.has_malformed_headers);
    }
}
