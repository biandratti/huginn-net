#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.
//!
//! ## Cargo Features
//!
//! **All features are opt-in**: the default build is an empty shell. Pick the
//! analyses you actually consume, or use the convenience
//! [`full`](#cargo-features) alias to opt into everything this version
//! offers (including future axes added in later releases).
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `full` | No | Convenience alias for "everything this version offers" (currently `db` + every `tcp-*` + every `http-*` + `tls-stable-v1`). Stable across version upgrades — additions land here automatically. |
//! | `db` | No | Pulls in [`huginn_net_db`] and enables p0f signature matching for TCP and HTTP. Combine with any `tcp-*` / `http-*` for label-producing builds; omit for an observation-only build (e.g. JA4-only or downstream consumers that bring their own matcher implementation). |
//! | `tcp-syn` | No | Pass-through for `huginn-net-tcp/syn`: TCP SYN fingerprinting (`FingerprintResult::tcp_syn`). |
//! | `tcp-syn-ack` | No | Pass-through for `huginn-net-tcp/syn-ack`: TCP SYN+ACK fingerprinting (`FingerprintResult::tcp_syn_ack`). |
//! | `tcp-mtu` | No | Pass-through for `huginn-net-tcp/mtu`: MTU detection (`FingerprintResult::tcp_mtu`). |
//! | `tcp-uptime` | No | Pass-through for `huginn-net-tcp/uptime`: uptime estimation for both client and server (`FingerprintResult::tcp_client_uptime` / `tcp_server_uptime`). |
//! | `http-p0f-request` | No | Pass-through for `huginn-net-http/p0f-request`: HTTP request fingerprinting (`FingerprintResult::http_request`, [`HttpRequestOutput`], [`Browser`], [`BrowserQualityMatched`]). |
//! | `http-p0f-response` | No | Pass-through for `huginn-net-http/p0f-response`: HTTP response fingerprinting (`FingerprintResult::http_response`, [`HttpResponseOutput`], [`WebServer`], [`WebServerQualityMatched`]). |
//! | `tls-stable-v1` | No | Adds `JA4_s1` / `JA4_rs1` fingerprints via [`huginn_net_tls`], ephemeral extensions excluded for stable fingerprints. |
//!
//! Each `tcp-*` / `http-*` feature gates the corresponding field on
//! [`FingerprintResult`] and the matching re-exports. Disabling a feature
//! removes its field at compile time and shrinks the result struct. The
//! underlying parser also early-exits when none of the consumers for a
//! packet's side are enabled, so disabling features is a zero-cost
//! optimization, not just a build configuration.
//!
//! Common opt-in examples:
//!
//! ```toml
//! # Everything this version offers (forward-compatible).
//! huginn-net = { version = "2.0.0", features = ["full"] }
//!
//! # p0f-style TCP+HTTP fingerprinting with database matching.
//! huginn-net = { version = "2.0.0", features = ["db", "tcp-syn", "tcp-syn-ack", "http-p0f-request", "http-p0f-response"] }
//!
//! # Observation-only TCP SYN (no database, no matching).
//! huginn-net = { version = "2.0.0", features = ["tcp-syn"] }
//! ```

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

#[cfg(any(feature = "tcp-syn", feature = "tcp-syn-ack"))]
pub use huginn_net_tcp::output::OSQualityMatched;
#[cfg(feature = "tcp-syn-ack")]
pub use huginn_net_tcp::output::SynAckTCPOutput;
#[cfg(feature = "tcp-syn")]
pub use huginn_net_tcp::output::SynTCPOutput;
#[cfg(feature = "tcp-mtu")]
pub use huginn_net_tcp::output::{MTUOutput, MTUQualityMatched};
pub use huginn_net_tcp::output::{
    MatchQuality as TcpMatchQuality, OperativeSystem, OsKind as TcpOsKind,
};
#[cfg(feature = "tcp-uptime")]
pub use huginn_net_tcp::output::{UptimeOutput, UptimeRole};
pub use huginn_net_tcp::tcp;
pub use huginn_net_tcp::tcp::Ttl;

pub use huginn_net_http::http;
#[cfg(feature = "http-p0f-request")]
pub use huginn_net_http::observable::ObservableHttpRequest;
#[cfg(feature = "http-p0f-response")]
pub use huginn_net_http::observable::ObservableHttpResponse;
pub use huginn_net_http::output::{
    Browser, MatchQuality as HttpMatchQuality, OsKind as HttpOsKind, WebServer,
};
#[cfg(feature = "http-p0f-request")]
pub use huginn_net_http::output::{BrowserQualityMatched, HttpRequestOutput};
#[cfg(feature = "http-p0f-response")]
pub use huginn_net_http::output::{HttpResponseOutput, WebServerQualityMatched};

pub use huginn_net_tls::output::TlsClientOutput;
pub use huginn_net_tls::ObservableTlsClient;

#[cfg(any(feature = "tcp-syn", feature = "tcp-syn-ack"))]
pub use huginn_net_tcp::observable::ObservableTcp;

pub use huginn_net_tcp;
pub use huginn_net_tcp::{FilterConfig, IpFilter, PortFilter, SubnetFilter};

pub use huginn_net_http;
pub use huginn_net_http::{
    FilterConfig as HttpFilterConfig, IpFilter as HttpIpFilter, PortFilter as HttpPortFilter,
    SubnetFilter as HttpSubnetFilter,
};

pub use huginn_net_tls;
pub use huginn_net_tls::{
    FilterConfig as TlsFilterConfig, IpFilter as TlsIpFilter, PortFilter as TlsPortFilter,
    SubnetFilter as TlsSubnetFilter,
};

// ---------------------------------------------------------------------------
// Public module alias
// ---------------------------------------------------------------------------
pub mod packet_parser {
    pub use crate::parser::packet::*;
}
