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
//! - `tcp` (default) - pulls in `huginn-net-tcp` and exposes [`TcpDatabase`],
//!   [`TcpSignatureMatcher`], the `[tcp:*]` parser branch, and TCP signal
//!   matching impls.
//! - `http` (default) - pulls in `huginn-net-http` and exposes [`HttpDatabase`],
//!   [`HttpSignatureMatcher`], the `[http:*]` parser branch, and HTTP signal
//!   matching impls.
//!
//! Disabling either feature keeps the crate compiling against only the other
//! protocol; disabling both leaves only [`Label`], [`Type`], the parser
//! shell, and the database-matching traits.

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
