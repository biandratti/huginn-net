#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # huginn-net-db
//!
//! P0f database parser and matching traits for network fingerprinting.
//!
//! This crate provides:
//! - Parsing of p0f database format
//! - Database structures for TCP and HTTP signatures
//! - Traits for fingerprint matching
//! - Observable signal types
//!
//! ## Cargo Features
//!
//! **All features are opt-in**: the default build leaves only [`Label`],
//! [`Type`], the parser shell, and the database-matching traits. Pick the
//! protocols you actually consume, or use the convenience
//! [`full`](#cargo-features) alias to opt into everything this version
//! offers (including future protocols added in later releases).
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `full`  | No      | Convenience alias for "everything this version offers" (currently `tcp` + `http`). Stable across version upgrades. |
//! | `tcp`   | No      | Pulls in [`huginn_net_tcp`] and exposes [`TcpDatabase`], [`TcpSignatureMatcher`], the `[tcp:*]` p0f parser branch, and TCP signal matching impls. |
//! | `http`  | No      | Pulls in [`huginn_net_http`] and exposes [`HttpDatabase`], [`HttpSignatureMatcher`], the `[http:*]` p0f parser branch, and HTTP signal matching impls. |
//!
//! Common opt-in examples:
//!
//! ```toml
//! # Everything this version offers (forward-compatible).
//! huginn-net-db = { version = "2.0.0", features = ["full"] }
//!
//! # TCP signatures only.
//! huginn-net-db = { version = "2.0.0", features = ["tcp"] }
//! ```

#[path = "matcher/traits.rs"]
pub mod db_matching_trait;

pub mod database;
pub mod error;

pub mod parse;

pub mod db_parse {
    #[allow(unused_imports)] // re-export is a no-op when both protocol features are off
    pub use super::parse::*;
}

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "http")]
#[path = "http/matching.rs"]
pub mod observable_http_signals_matching;
#[cfg(feature = "tcp")]
#[path = "tcp/matching.rs"]
pub mod observable_tcp_signals_matching;

#[cfg(feature = "http")]
#[path = "matcher/http_signature_matcher.rs"]
pub mod http_signature_matcher;
#[cfg(feature = "tcp")]
#[path = "matcher/tcp_signature_matcher.rs"]
pub mod tcp_signature_matcher;

// Re-export main types for convenience
#[cfg(all(feature = "tcp", feature = "http"))]
pub use database::Database;
#[cfg(feature = "http")]
pub use database::HttpDatabase;
#[cfg(feature = "tcp")]
pub use database::TcpDatabase;
pub use database::{Label, Type};
pub use error::DatabaseError;
#[cfg(feature = "http")]
pub use http_signature_matcher::{HttpSignatureMatcher, SharedHttpSignatureMatcher};
#[cfg(feature = "tcp")]
pub use tcp_signature_matcher::{SharedTcpSignatureMatcher, TcpSignatureMatcher};

/// Historical module path (`huginn_net_db::db::…`); re-exports [`database`].
pub mod db {
    pub use super::database::*;
}
