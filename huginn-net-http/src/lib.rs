#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Standalone HTTP fingerprinting (p0f-style) analyzer.
//!
//! `huginn-net-http` is intentionally independent of any signature database:
//! you can use it to extract observable HTTP signals from raw traffic without
//! pulling in `huginn-net-db`. To enable matching against the bundled
//! signatures, plug a [`HttpMatcher`] implementation
//! (`huginn-net-db` provides `SharedHttpSignatureMatcher`) via
//! [`HuginnNetHttp::with_matcher`].

// ---------------------------------------------------------------------------
// Domain modules (canonical locations)
// ---------------------------------------------------------------------------
pub mod akamai;
pub mod analyzer;
pub mod error;
pub mod filter;
pub mod http;
pub mod http1;
pub mod http2;
pub mod matcher_api;
pub mod output;
pub mod parser;
pub mod process;

// ---------------------------------------------------------------------------
// Top-level re-exports
// ---------------------------------------------------------------------------
pub use akamai::extractor::{
    calculate_frames_bytes_consumed, extract_akamai_fingerprint,
    extract_akamai_fingerprint_from_bytes,
};
pub use akamai::{AkamaiFingerprint, Http2Priority, PseudoHeader, SettingId, SettingParameter};
pub use analyzer::HuginnNetHttp;
pub use error::*;
pub use filter::*;
pub use http::common::HttpProcessor;
pub use http::observable::*;
pub use http1::process::{
    build_absent_headers_from_new_parser, convert_headers_to_http_format, parse_http1_request,
    Http1Processor,
};
pub use http2::process::{parse_http2_request, Http2Processor};
pub use http2::Http2FingerprintExtractor;
pub use http2::{Http2Frame, Http2FrameType, Http2Parser, HTTP2_CONNECTION_PREFACE};
pub use matcher_api::{HttpMatcher, HttpRequestMatch, HttpResponseMatch, UaOsMatch};
pub use output::*;
pub use process::{process_ipv4_packet, process_ipv6_packet};
pub use process::{DispatchResult, PoolStats, SharedHttpMatcher, WorkerPool, WorkerStats};
pub use process::{FlowKey, HttpProcessors, TcpFlow};

// ---------------------------------------------------------------------------
// Public module aliases
// Convenience paths that expose domain sub-modules at well-known names.
// ---------------------------------------------------------------------------

pub mod akamai_extractor {
    pub use crate::akamai::extractor::*;
}

pub mod display {
    pub use crate::http::observable::*;
}

pub mod http_common {
    pub use crate::http::common::*;
}

pub mod http_languages {
    pub use crate::http::languages::*;
}

pub mod observable {
    pub use crate::http::observable::*;
}

pub mod http_process {
    pub use crate::process::flow::*;
}

pub mod http1_parser {
    pub use crate::http1::parser::*;
}

pub mod http1_process {
    pub use crate::http1::process::*;
}

pub mod http2_parser {
    pub use crate::http2::frames::*;
    pub use crate::http2::parser::*;
}

pub mod http2_process {
    pub use crate::http2::process::*;
}

pub mod http2_fingerprint_extractor {
    pub use crate::http2::fingerprint::*;
}

pub mod packet_hash {
    pub use crate::parser::hash::*;
}

pub mod packet_parser {
    pub use crate::parser::packet::*;
}

pub mod parallel {
    pub use crate::process::parallel::*;
}

pub mod raw_filter {
    pub use crate::filter::raw::*;
}
