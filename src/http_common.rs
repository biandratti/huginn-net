use crate::http;
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

    fn parse_request(&self, data: &[u8]) -> Result<Option<Self::Request>, Self::Error>;

    fn parse_response(&self, data: &[u8]) -> Result<Option<Self::Response>, Self::Error>;

    fn supported_version(&self) -> http::Version;

    fn can_parse(&self, data: &[u8]) -> bool;
}

/// Common trait for HTTP protocol processors
///
/// This trait abstracts the processing logic for different HTTP versions,
///
/// # Design Philosophy
///
/// - **Protocol Detection**: Each processor can detect if it can handle the data
/// - **Unified Interface**: Same interface for all HTTP versions
/// - **Extensibility**: Easy to add new protocols without changing core logic
/// - **Error Handling**: Consistent error handling across protocols
/// ```
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
    ) -> Result<
        Option<crate::observable_signals::ObservableHttpRequest>,
        crate::error::HuginnNetError,
    >;

    /// Process HTTP response data and return observable response  
    fn process_response(
        &self,
        data: &[u8],
    ) -> Result<
        Option<crate::observable_signals::ObservableHttpResponse>,
        crate::error::HuginnNetError,
    >;

    /// Get the HTTP version this processor handles
    fn supported_version(&self) -> http::Version;

    /// Get a human-readable name for this processor
    fn name(&self) -> &'static str;
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

/// HTTP diagnostic function - determines the relationship between User-Agent and OS signature
///
/// This function analyzes the consistency between the reported User-Agent string and
/// the detected OS signature from TCP fingerprinting to identify potential spoofing.
///
/// # Arguments
/// * `user_agent` - Optional User-Agent string from HTTP headers
/// * `ua_matcher` - Optional tuple of (OS name, browser flavor) extracted from User-Agent
/// * `signature_os_matcher` - Optional OS label from TCP signature matching
///
/// # Returns
/// * `HttpDiagnosis::Anonymous` - No User-Agent provided
/// * `HttpDiagnosis::Generic` - User-Agent OS matches TCP signature OS
/// * `HttpDiagnosis::Dishonest` - User-Agent OS differs from TCP signature OS (potential spoofing)
/// * `HttpDiagnosis::None` - Insufficient data for comparison
pub fn get_diagnostic(
    user_agent: Option<String>,
    ua_matcher: Option<(&String, &Option<String>)>,
    signature_os_matcher: Option<&crate::db::Label>,
) -> crate::http::HttpDiagnosis {
    match user_agent {
        None => crate::http::HttpDiagnosis::Anonymous,
        Some(_ua) => match (ua_matcher, signature_os_matcher) {
            (Some((ua_name_db, _ua_flavor_db)), Some(signature_label_db)) => {
                if ua_name_db.eq_ignore_ascii_case(&signature_label_db.name) {
                    crate::http::HttpDiagnosis::Generic
                } else {
                    crate::http::HttpDiagnosis::Dishonest
                }
            }
            _ => crate::http::HttpDiagnosis::None,
        },
    }
}
