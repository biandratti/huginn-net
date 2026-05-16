use super::{HttpDiagnosis, Version};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderSource {
    Http1Line,
    Http2PseudoHeader,
    Http2Header,
    Http3Header,
}

/// Represents an HTTP header with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct HttpHeader {
    pub name: String,
    pub value: Option<String>,
    /// Position in the original header sequence (0-based)
    pub position: usize,
    /// Source protocol/type of this header
    pub source: HeaderSource,
}

impl HttpHeader {
    pub fn new(name: &str, value: Option<&str>, position: usize, source: HeaderSource) -> Self {
        Self { name: name.to_string(), value: value.map(String::from), position, source }
    }
}

/// Represents an HTTP cookie
#[derive(Debug, Clone, PartialEq)]
pub struct HttpCookie {
    pub name: String,
    pub value: Option<String>,
    /// Position in the cookie header (0-based)
    pub position: usize,
}

/// Advanced parsing metadata for fingerprinting
#[derive(Debug, Clone)]
pub struct ParsingMetadata {
    pub header_count: usize,
    pub duplicate_headers: Vec<String>,
    pub case_variations: HashMap<String, Vec<String>>,
    pub parsing_time_ns: u64,
    pub has_malformed_headers: bool,
    pub request_line_length: usize,
    pub total_headers_length: usize,
}

impl ParsingMetadata {
    pub fn new() -> Self {
        Self {
            header_count: 0,
            duplicate_headers: Vec::new(),
            case_variations: HashMap::new(),
            parsing_time_ns: 0,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: 0,
        }
    }

    pub fn with_timing<F, R>(mut self, f: F) -> (R, Self)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        self.parsing_time_ns = start.elapsed().as_nanos() as u64;
        (result, self)
    }
}

impl Default for ParsingMetadata {
    fn default() -> Self {
        Self::new()
    }
}

use super::observable::{ObservableHttpRequest, ObservableHttpResponse};

/// Common trait for all HTTP parsers across different versions
pub trait HttpParser {
    /// Get the HTTP version this parser supports
    fn supported_version(&self) -> Version;

    /// Check if this parser can handle the given data
    fn can_parse(&self, data: &[u8]) -> bool;

    /// Get a human-readable name for this parser
    fn name(&self) -> &'static str;

    /// Parse HTTP request data into observable signals
    /// Returns None if data cannot be parsed by this parser
    fn parse_request(&self, data: &[u8]) -> Option<ObservableHttpRequest>;

    /// Parse HTTP response data into observable signals  
    /// Returns None if data cannot be parsed by this parser
    fn parse_response(&self, data: &[u8]) -> Option<ObservableHttpResponse>;
}

/// Common trait for HTTP protocol processors
pub trait HttpProcessor {
    /// Check if this processor can handle the given request data
    fn can_process_request(&self, data: &[u8]) -> bool;

    /// Check if this processor can handle the given response data
    fn can_process_response(&self, data: &[u8]) -> bool;

    /// Check if the data appears to be complete for this protocol
    fn has_complete_data(&self, data: &[u8]) -> bool;

    /// Process HTTP request data and return observable request
    fn process_request(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpRequest>, crate::error::HuginnNetHttpError>;

    /// Process HTTP response data and return observable response  
    fn process_response(
        &self,
        data: &[u8],
    ) -> Result<Option<ObservableHttpResponse>, crate::error::HuginnNetHttpError>;

    /// Get the HTTP version this processor handles
    fn supported_version(&self) -> Version;

    /// Get a human-readable name for this processor
    fn name(&self) -> &'static str;
}

/// HTTP diagnostic function - determines the relationship between User-Agent and an
/// externally-observed OS signal.
///
/// This function compares the OS family reported by the User-Agent string against an
/// OS name observed from the network (typically obtained from TCP fingerprinting by the
/// caller, but this crate is intentionally agnostic about the source). A mismatch
/// between the two is a hint of potential spoofing.
///
/// # Arguments
/// * `user_agent` - Optional User-Agent string from HTTP headers
/// * `ua_os_family` - OS family resolved from the User-Agent (UA→OS mapping in the database)
/// * `network_os_name` - OS name observed from another source (e.g. TCP fingerprinting).
///   `huginn-net-http` does not know how this was produced; it just compares strings.
///
/// # Returns
/// * `HttpDiagnosis::Anonymous` - No User-Agent provided
/// * `HttpDiagnosis::Generic` - User-Agent OS matches the externally observed OS
/// * `HttpDiagnosis::Dishonest` - User-Agent OS differs from the externally observed OS (potential spoofing)
/// * `HttpDiagnosis::None` - Insufficient data for comparison
pub fn get_diagnostic(
    user_agent: Option<String>,
    ua_os_family: Option<&str>,
    network_os_name: Option<&str>,
) -> HttpDiagnosis {
    match user_agent {
        None => HttpDiagnosis::Anonymous,
        Some(_ua) => match (ua_os_family, network_os_name) {
            (Some(ua_name), Some(net_name)) => {
                if ua_name.eq_ignore_ascii_case(net_name) {
                    HttpDiagnosis::Generic
                } else {
                    HttpDiagnosis::Dishonest
                }
            }
            _ => HttpDiagnosis::None,
        },
    }
}
