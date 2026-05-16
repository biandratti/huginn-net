//! HTTP signature and scoring for the p0f database.

pub use huginn_net_http::http::{
    request_common_headers, request_optional_headers, request_skip_value_headers,
    response_common_headers, response_optional_headers, response_skip_value_headers, Header,
    HttpDiagnosis, Version,
};

mod distances;
mod signature;

pub use distances::{distance_expsw, distance_header, distance_http_version};
pub use signature::{HttpMatchQuality, Signature};
