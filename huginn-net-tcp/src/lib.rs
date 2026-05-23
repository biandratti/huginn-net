#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! TCP fingerprinting primitives.
//!
//! This crate is intentionally **independent of any signature database**.
//! It exposes:
//! - [`tcp`] pure data types describing a TCP fingerprint.
//! - [`TcpObservation`] what was observed on the wire.
//! - [`matcher_api::TcpMatcher`] the trait any database/matcher implements
//!   to provide OS/MTU matches.
//! - [`HuginnNetTcp`] the high-level capture/processing entry point that
//!   plugs an arbitrary matcher in.
//!
//! In the default workspace setup, `huginn-net-db` provides
//! `TcpSignatureMatcher`, which loads p0f-style signatures and implements
//! [`matcher_api::TcpMatcher`].
//!
//! ## Cargo Features
//!
//! **All features are opt-in**: the default build is an empty shell that
//! exposes only the traits and entry points. Pick the analyses you actually
//! consume, or use the convenience [`full`](#cargo-features) alias to opt
//! into everything this version offers (including future axes added in
//! later releases).
//!
//! | Feature   | Default | Description                                                                                                            |
//! |-----------|---------|------------------------------------------------------------------------------------------------------------------------|
//! | `full`    | No      | Convenience alias for "everything this version offers" (currently `syn` + `syn-ack` + `mtu` + `uptime`). Stable across version upgrades — additions land here automatically. |
//! | `syn`     | No      | TCP SYN OS fingerprinting (client → server, request side). Gates [`SynTCPOutput`].                                     |
//! | `syn-ack` | No      | TCP SYN+ACK OS fingerprinting (server → client, response side). Gates [`SynAckTCPOutput`].                             |
//! | `mtu`     | No      | MTU extraction from the TCP MSS option. Gates [`mtu`] and [`MTUOutput`].                                               |
//! | `uptime`  | No      | Uptime estimation from TCP timestamps for **both client and server** sides. Gates [`uptime`] and pulls in `ttl_cache`. |
//!
//! When a build disables every feature that would consume a packet's side
//! (request or response), `visit_tcp` short-circuits before parsing TCP
//! options. SYN-only builds therefore pay zero per-packet cost for SYN+ACK
//! traffic, and SYN+ACK-only builds skip the request-side work entirely.
//!
//! Common opt-in examples:
//!
//! ```toml
//! # Everything this version offers (forward-compatible).
//! huginn-net-tcp = { version = "2.0.0", features = ["full"] }
//!
//! # Cherry-pick only what you need (smallest possible build).
//! huginn-net-tcp = { version = "2.0.0", features = ["syn"] }
//! ```

pub mod analyzer;
pub mod error;
pub mod filter;
pub mod matcher_api;
#[cfg(feature = "mtu")]
pub mod mtu;
pub mod output;
pub mod parser;
pub mod process;
pub mod tcp;
#[cfg(feature = "uptime")]
pub mod uptime;

// Re-exports from new canonical locations
pub use analyzer::{HuginnNetTcp, SharedTcpMatcher};
pub use error::*;
pub use filter::*;
#[cfg(feature = "mtu")]
pub use mtu::ObservableMtu;
pub use output::*;
pub use process::{process_ipv4_packet, process_ipv6_packet, ConnectionTracker};
pub use process::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use tcp::observable::{ObservableTcp, TcpObservation};
#[cfg(feature = "uptime")]
pub use uptime::{
    calculate_uptime_improved, Connection, ConnectionKey, FrequencyState, TcpTimestamp,
    UptimeTracker,
};

// ---------------------------------------------------------------------------
// Public module aliases
// Convenience paths that expose domain sub-modules at well-known names.
// ---------------------------------------------------------------------------

pub mod display {
    pub use crate::tcp::observable::*;
}

pub mod ip_options {
    pub use crate::tcp::ip_options::*;
}

pub mod observable {
    #[cfg(feature = "mtu")]
    pub use crate::mtu::ObservableMtu;
    pub use crate::tcp::observable::{ObservableTcp, TcpObservation};
    #[cfg(feature = "uptime")]
    pub use crate::uptime::ObservableUptime;
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

pub mod syn_options {
    pub use crate::tcp::syn_options::*;
}

pub mod tcp_process {
    pub use crate::process::flow::*;
}

pub mod ttl {
    pub use crate::tcp::ttl::*;
}

pub mod window_size {
    pub use crate::tcp::window_size::*;
}
