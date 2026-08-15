//! HTTP signature and field-comparison helpers for the p0f database.

pub use huginn_net_http::http::{
    request_common_headers, request_optional_headers, request_skip_value_headers,
    response_common_headers, response_optional_headers, response_skip_value_headers, Header,
    HttpParams, Version, UNKNOWN_SOFTWARE,
};

mod distances;
mod signature;

pub use distances::{absent_headers_match, expsw_matches, headers_match, http_version_matches};
pub use signature::Signature;
