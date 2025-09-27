#![forbid(unsafe_code)]

//! # huginn-net-db
//!
//! P0f database parser and matching traits for network fingerprinting.
//!
//! This crate provides:
//! - Parsing of p0f database format
//! - Database structures for TCP and HTTP signatures
//! - Traits for fingerprint matching
//! - Observable signal types

// Core database functionality
pub mod db;
pub mod db_matching_trait;
pub mod db_parse;
pub mod error;

// Protocol-specific types
pub mod http;
pub mod tcp;

// Observable signals and matching impls
pub mod observable_http_signals_matching;
pub mod observable_signals;
pub mod observable_tcp_signals_matching;

// Display implementations for database types
pub mod display;

// Re-export main types for convenience
pub use db::{Database, Label, Type};
pub use error::DatabaseError;
