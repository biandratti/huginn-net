#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `db` | Yes | Pulls in [`huginn_net_db`] and enables p0f signature matching for TCP and HTTP. Disable for an observation-only build (e.g. JA4-only or downstream consumers that bring their own matcher implementation). |
//! | `tcp-syn` | Yes | Pass-through for `huginn-net-tcp/syn`: TCP SYN fingerprinting (`FingerprintResult::tcp_syn`). |
//! | `tcp-syn-ack` | Yes | Pass-through for `huginn-net-tcp/syn-ack`: TCP SYN+ACK fingerprinting (`FingerprintResult::tcp_syn_ack`). |
//! | `tcp-mtu` | Yes | Pass-through for `huginn-net-tcp/mtu`: MTU detection (`FingerprintResult::tcp_mtu`). |
//! | `tcp-uptime` | Yes | Pass-through for `huginn-net-tcp/uptime`: uptime estimation for both client and server (`FingerprintResult::tcp_client_uptime` / `tcp_server_uptime`). |
//! | `tls-stable-v1` | No | Adds `JA4_s1` / `JA4_rs1` fingerprints via [`huginn_net_tls`], ephemeral extensions excluded for stable fingerprints. |
//!
//! Each `tcp-*` feature gates the corresponding field on [`FingerprintResult`]
//! and the matching re-exports. Disabling a feature removes its field at
//! compile time and shrinks the result struct. The underlying parser also
//! early-exits when none of the consumers for a packet's side are enabled,
//! so disabling features is a zero-cost optimization, not just a build
//! configuration.

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
pub use huginn_net_http::observable::{ObservableHttpRequest, ObservableHttpResponse};
pub use huginn_net_http::output::{
    Browser, BrowserQualityMatched, HttpRequestOutput, HttpResponseOutput,
    MatchQuality as HttpMatchQuality, OsKind as HttpOsKind, WebServer, WebServerQualityMatched,
};

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
