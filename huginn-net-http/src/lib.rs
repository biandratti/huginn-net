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
//!
//! ## Cargo Features
//!
//! All three HTTP analysis axes are enabled by default. Disable any of them
//! to strip the matching code paths and the corresponding fields on
//! [`HttpAnalysisResult`].
//!
//! | Feature        | Default | Description                                                                                                                                                  |
//! |----------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
//! | `p0f-request`  | Yes     | p0f-style fingerprinting of HTTP request side (client → server): header order, `Accept-Language`, User-Agent, browser matching. Gates [`HttpRequestOutput`]. |
//! | `p0f-response` | Yes     | p0f-style fingerprinting of HTTP response side (server → client): header order, web-server matching. Gates [`HttpResponseOutput`].                           |
//! | `akamai`       | Yes     | Akamai HTTP/2 client fingerprinting from SETTINGS/WINDOW_UPDATE/PRIORITY frames. Standalone API surface ([`Http2FingerprintExtractor`], [`AkamaiFingerprint`], `extract_akamai_fingerprint*`); not invoked by the p0f path. |
//!
//! When a build disables every feature that would consume a packet's side
//! (request or response), `process_tcp_packet` short-circuits at the top —
//! no flow-cache lookup, no SYN insertion, no payload reassembly. A pure
//! `akamai`-only build therefore pays zero per-packet cost for the p0f
//! pipeline.
//!
//! The always-on raw parsers (`parse_http1_request`, `parse_http2_request`,
//! `Http1Processor`, `Http2Processor`, the `HttpParser`/`HttpProcessor`
//! traits) and the `HttpMatcher` trait surface stay compiled regardless of
//! the feature set so external consumers can keep using them.
//!
//! Example — observation-only client side, no database, no `akamai`:
//!
//! ```toml
//! huginn-net-http = { version = "2.0", default-features = false, features = ["p0f-request"] }
//! ```

// ---------------------------------------------------------------------------
// Domain modules (canonical locations)
// ---------------------------------------------------------------------------
#[cfg(feature = "akamai")]
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
#[cfg(feature = "akamai")]
pub use akamai::extractor::{
    calculate_frames_bytes_consumed, extract_akamai_fingerprint,
    extract_akamai_fingerprint_from_bytes,
};
#[cfg(feature = "akamai")]
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
#[cfg(feature = "akamai")]
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

#[cfg(feature = "akamai")]
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

#[cfg(feature = "akamai")]
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
