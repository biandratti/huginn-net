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

    pub fn with_config(config: Http1Config) -> Self {
        Self { config }
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
