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

// Core database functionality
pub mod db;
pub mod db_matching_trait;
pub mod db_parse;
pub mod error;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "tcp")]
pub mod tcp;

// Observable signals and matching impls
#[cfg(feature = "http")]
pub mod observable_http_signals_matching;
pub mod observable_signals;
#[cfg(feature = "tcp")]
pub mod observable_tcp_signals_matching;

// Matcher implementations
#[cfg(feature = "http")]
pub mod http_signature_matcher;
#[cfg(feature = "tcp")]
pub mod tcp_signature_matcher;

// Display implementations for database types
pub mod display;
pub mod utils;

// Re-export main types for convenience
#[cfg(all(feature = "tcp", feature = "http"))]
pub use db::Database;
#[cfg(feature = "http")]
pub use db::HttpDatabase;
#[cfg(feature = "tcp")]
pub use db::TcpDatabase;
pub use db::{Label, Type};
pub use error::DatabaseError;
#[cfg(feature = "http")]
pub use http_signature_matcher::{HttpSignatureMatcher, SharedHttpSignatureMatcher};
#[cfg(feature = "tcp")]
pub use tcp_signature_matcher::{SharedTcpSignatureMatcher, TcpSignatureMatcher};
pub use utils::MatchQualityType;
