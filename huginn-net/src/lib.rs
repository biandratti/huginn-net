//! Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `db` | Yes | Pulls in [`huginn_net_db`] and enables p0f signature matching for TCP and HTTP. Disable for an observation-only build (e.g. JA4-only or downstream consumers that bring their own matcher implementation). |
//! | `tls-stable-v1` | No | Adds `JA4_s1` / `JA4_rs1` fingerprints via [`huginn_net_tls`], ephemeral extensions excluded for stable fingerprints |

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// ---------------------------------------------------------------------------
// Domain modules (canonical locations)
// ---------------------------------------------------------------------------
pub mod analyzer;
pub mod error;
pub mod matcher;
pub mod output;
pub mod parser;
pub mod process;

// ---------------------------------------------------------------------------
// Top-level re-exports
// ---------------------------------------------------------------------------
pub use analyzer::{AnalysisConfig, HuginnNet};
pub use error::HuginnNetError;
pub use output::FingerprintResult;

#[cfg(feature = "db")]
pub use huginn_net_db::{db_matching_trait, Database, Label};

pub use huginn_net_tcp::output::{
    MTUOutput, MTUQualityMatched, MatchQuality as TcpMatchQuality, OSQualityMatched,
    OperativeSystem, OsKind as TcpOsKind, SynAckTCPOutput, SynTCPOutput, UptimeOutput, UptimeRole,
};
pub use huginn_net_tcp::tcp;
pub use huginn_net_tcp::tcp::Ttl;

pub use huginn_net_http::http;
pub use huginn_net_http::observable::{ObservableHttpRequest, ObservableHttpResponse};
pub use huginn_net_http::output::{
    Browser, BrowserQualityMatched, HttpRequestOutput, HttpResponseOutput,
    MatchQuality as HttpMatchQuality, OsKind as HttpOsKind, WebServer, WebServerQualityMatched,
};

pub use huginn_net_tls::output::TlsClientOutput;
pub use huginn_net_tls::ObservableTlsClient;

pub use huginn_net_tcp::observable::ObservableTcp;

pub use huginn_net_tcp;
pub use huginn_net_tcp::{FilterConfig, IpFilter, PortFilter};

pub use huginn_net_http;
pub use huginn_net_http::{
    FilterConfig as HttpFilterConfig, IpFilter as HttpIpFilter, PortFilter as HttpPortFilter,
};

pub use huginn_net_tls;
pub use huginn_net_tls::{
    FilterConfig as TlsFilterConfig, IpFilter as TlsIpFilter, PortFilter as TlsPortFilter,
};

// ---------------------------------------------------------------------------
// Public module alias
// ---------------------------------------------------------------------------
pub mod packet_parser {
    pub use crate::parser::packet::*;
}
