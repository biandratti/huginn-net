use std::collections::HashMap;
use std::time::Instant;
use crate::http;

/// Source of an HTTP header, useful for fingerprinting
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderSource {
    /// Standard HTTP/1.x header line
    Http1Line,
    /// HTTP/2 pseudo-header (e.g., :method, :path, :authority, :scheme)
    Http2PseudoHeader,
    /// HTTP/2 regular header
    Http2Header,
    /// HTTP/3 header (for future use)
    Http3Header,
}

/// Represents an HTTP header with metadata
#[derive(Debug, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
    /// Position in the original header sequence (0-based)
    pub position: usize,
    /// Source protocol/type of this header
    pub source: HeaderSource,
}

/// Represents an HTTP cookie
#[derive(Debug, Clone)]
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

/// Common trait for all HTTP parsers across different versions
pub trait HttpParser {
    type Request;
    type Response;
    type Error: std::error::Error;

    /// Parse an HTTP request
    fn parse_request(&self, data: &[u8]) -> Result<Option<Self::Request>, Self::Error>;
    
    /// Parse an HTTP response
    fn parse_response(&self, data: &[u8]) -> Result<Option<Self::Response>, Self::Error>;
    
    /// Get the HTTP version this parser handles
    fn supported_version(&self) -> http::Version;
    
    /// Check if the parser can handle the given data
    fn can_parse(&self, data: &[u8]) -> bool;
}

/// Common HTTP request interface
pub trait HttpRequestLike {
    fn method(&self) -> &str;
    fn uri(&self) -> &str;
    fn version(&self) -> http::Version;
    fn headers(&self) -> &[HttpHeader];
    fn cookies(&self) -> &[HttpCookie];
    fn metadata(&self) -> &ParsingMetadata;
}

/// Common HTTP response interface
pub trait HttpResponseLike {
    fn status_code(&self) -> u16;
    fn version(&self) -> http::Version;
    fn headers(&self) -> &[HttpHeader];
    fn metadata(&self) -> &ParsingMetadata;
}
