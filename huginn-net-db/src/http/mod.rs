//! HTTP signature and field-comparison helpers for the p0f database.

pub use huginn_net_http::http::{
    Header, HttpParams, UNKNOWN_SOFTWARE, Version, request_common_headers,
    request_optional_headers, request_skip_value_headers, response_common_headers,
    response_optional_headers, response_skip_value_headers,
};

mod distances;
mod matching;
mod signature;

pub use distances::{absent_headers_match, expsw_matches, headers_match, http_version_matches};
pub use signature::Signature;
