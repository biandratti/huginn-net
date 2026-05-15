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

use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};

/// Common trait for all HTTP parsers across different versions
pub trait HttpParser {
    /// Get the HTTP version this parser supports
    fn supported_version(&self) -> http::Version;

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
    fn supported_version(&self) -> http::Version;

    /// Get a human-readable name for this processor
    fn name(&self) -> &'static str;
}

/// p0f-style HTTP diagnostic.
///
/// Faithful port of the four flags p0f's `dump_flags` emits for an HTTP
/// observation (`fp_http.c::dump_flags`, around lines 644-648 of the
/// reference C source under `data/p0f/`):
///
/// ```text
///   if (hsig->dishonest) RETF(" dishonest");
///   if (!hsig->sw)       RETF(" anonymous");
///   if (m && m->generic) RETF(" generic");
/// ```
///
/// p0f emits all that apply (concatenated). [`http::HttpDiagnosis`] is an
/// exclusive enum, so we apply the same precedence the strings would take
/// when rendered:
///
/// 1. [`http::HttpDiagnosis::Anonymous`] — no `User-Agent` (or `Server`)
///    header was observed (`hsig->sw` was empty).
/// 2. [`http::HttpDiagnosis::Dishonest`] — there is a match whose
///    `expsw` is non-empty *and* the observed UA does not contain it
///    (p0f's `!strstr(ts->sw, rs->sw)`). This is the strongest signal of
///    a forged User-Agent and outranks `generic`.
/// 3. [`http::HttpDiagnosis::Generic`] — the matched `p0f.fp` record is a
///    catch-all entry (`label = g:…`).
/// 4. [`http::HttpDiagnosis::None`] — specific match with a coherent UA,
///    or no match at all.
///
/// **HTTP-only.** This function deliberately ignores TCP fingerprinting.
/// p0f's cross-protocol UA-vs-TCP-OS check (`bad_sw` / `NAT_APP_UA` in
/// `fp_http.c::score_nat`) is a separate signal that lives on `host_data`,
/// not on the HTTP signature; it is not exposed by this crate yet.
///
/// # Arguments
/// * `user_agent` — observed `User-Agent` (request) or `Server` (response)
///   header value, or `None` if absent.
/// * `matched` — `(is_generic, expsw)` for the matched `p0f.fp` entry, or
///   `None` if no signature passed the matcher's quality threshold.
///   - `is_generic`: whether the matched label is a `g:` (catch-all)
///     entry, equivalent to `m->generic` in p0f.
///   - `expsw`: the substring expected to appear inside `user_agent`, the
///     fourth field of the `sig =` line in `p0f.fp`. An empty `expsw`
///     (or the literal `"???"` placeholder p0f uses for "unknown") is
///     treated as "no expectation" and never triggers `Dishonest`.
pub fn get_diagnostic(
    user_agent: Option<&str>,
    matched: Option<(bool, &str)>,
) -> http::HttpDiagnosis {
    match (user_agent, matched) {
        (None, _) => http::HttpDiagnosis::Anonymous,
        (Some(ua), Some((_is_generic, expsw)))
            if !expsw.is_empty() && expsw != "???" && !ua.contains(expsw) =>
        {
            http::HttpDiagnosis::Dishonest
        }
        (Some(_), Some((true, _))) => http::HttpDiagnosis::Generic,
        (Some(_), _) => http::HttpDiagnosis::None,
    }
}
