use crate::http;
use crate::http_common::{HttpParser, HttpRequestLike, HttpResponseLike, HttpHeader, HttpCookie, ParsingMetadata, HeaderSource};
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
    pub headers_map: HashMap<String, String>,
    pub cookies: Vec<HttpCookie>,
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
    pub headers_map: HashMap<String, String>,
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
        let (headers, parsing_metadata) = self.parse_headers(header_lines)?;
        let mut headers_map = HashMap::new();
        for header in &headers {
            headers_map.insert(header.name.to_lowercase(), header.value.clone());
        }

        let cookies = if self.config.parse_cookies {
            if let Some(cookie_header) = headers_map.get("cookie") {
                self.parse_cookies(cookie_header)
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
            content_length,
            transfer_encoding: headers_map.get("transfer-encoding").cloned(),
            connection: headers_map.get("connection").cloned(),
            host: headers_map.get("host").cloned(),
            user_agent: headers_map.get("user-agent").cloned(),
            accept_language: headers_map.get("accept-language").cloned(),
            raw_request_line: lines[0].to_string(),
            parsing_metadata: final_metadata,
            headers_map,
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
            headers_map.insert(header.name.to_lowercase(), header.value.clone());
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
            headers_map,
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
        let mut total_length = 0;

        for (position, line) in lines.iter().enumerate() {
            if line.is_empty() {
                break;
            }

            total_length += line.len();

            if line.len() > self.config.max_header_length {
                return Err(Http1ParseError::HeaderTooLong(line.len()));
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();

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

    fn parse_cookies(&self, cookie_header: &str) -> Vec<HttpCookie> {
        let mut cookies = Vec::new();

        for (position, cookie_str) in cookie_header.split(';').enumerate() {
            let cookie_str = cookie_str.trim();
            if cookie_str.is_empty() {
                continue;
            }

            if let Some(eq_pos) = cookie_str.find('=') {
                let name = cookie_str[..eq_pos].trim().to_string();
                let value = Some(cookie_str[eq_pos + 1..].trim().to_string());
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

impl HttpParser for Http1Parser {
    type Request = Http1Request;
    type Response = Http1Response;
    type Error = Http1ParseError;

    fn parse_request(&self, data: &[u8]) -> Result<Option<Self::Request>, Self::Error> {
        self.parse_request(data)
    }

    fn parse_response(&self, data: &[u8]) -> Result<Option<Self::Response>, Self::Error> {
        self.parse_response(data)
    }

    fn supported_version(&self) -> http::Version {
        http::Version::V11
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        
        // Check for HTTP/1.x patterns
        let data_str = String::from_utf8_lossy(data);
        let first_line = data_str.lines().next().unwrap_or("");
        
        // Look for HTTP/1.x method patterns
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"];
        methods.iter().any(|&method| first_line.starts_with(method)) ||
        first_line.starts_with("HTTP/1.")
    }
}

impl HttpRequestLike for Http1Request {
    fn method(&self) -> &str {
        &self.method
    }

    fn uri(&self) -> &str {
        &self.uri
    }

    fn version(&self) -> http::Version {
        self.version
    }

    fn headers(&self) -> &[HttpHeader] {
        &self.headers
    }

    fn cookies(&self) -> &[HttpCookie] {
        &self.cookies
    }

    fn metadata(&self) -> &ParsingMetadata {
        &self.parsing_metadata
    }
}

impl HttpResponseLike for Http1Response {
    fn status_code(&self) -> u16 {
        self.status_code
    }

    fn version(&self) -> http::Version {
        self.version
    }

    fn headers(&self) -> &[HttpHeader] {
        &self.headers
    }

    fn metadata(&self) -> &ParsingMetadata {
        &self.parsing_metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_request() {
        let parser = Http1Parser::new();
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

        let result = parser.parse_request(data).unwrap();
        assert!(result.is_some());

        let request = result.unwrap();
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

        let result = parser.parse_request(data).unwrap();
        assert!(result.is_some());

        let request = result.unwrap();
        assert_eq!(request.cookies.len(), 2);
        assert_eq!(request.cookies[0].name, "name1");
        assert_eq!(request.cookies[0].value, Some("value1".to_string()));
        assert_eq!(request.cookies[1].name, "name2");
        assert_eq!(request.cookies[1].value, Some("value2".to_string()));
    }

    #[test]
    fn test_parse_response() {
        let parser = Http1Parser::new();
        let data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";

        let result = parser.parse_response(data).unwrap();
        assert!(result.is_some());

        let response = result.unwrap();
        assert_eq!(response.version, http::Version::V11);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason_phrase, "OK");
        assert_eq!(response.server, Some("nginx".to_string()));
        assert_eq!(response.content_type, Some("text/html".to_string()));
    }

    #[test]
    fn test_incomplete_request() {
        let parser = Http1Parser::new();
        let data = b"GET /path HTTP/1.1\r\nHost: example.com"; // Sin \r\n\r\n

        let result = parser.parse_request(data).unwrap();
        assert!(result.is_none()); // Datos incompletos
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

        let result = parser.parse_request(data).unwrap().unwrap();

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

        let result = parser.parse_request(data).unwrap().unwrap();

        assert!(result.parsing_metadata.case_variations.contains_key("host"));
        assert!(result
            .parsing_metadata
            .duplicate_headers
            .contains(&"host".to_string()));
    }
}
