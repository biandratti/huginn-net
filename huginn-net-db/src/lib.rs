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
pub mod tcp;
pub mod http;

// Observable signals for matching (types only)
pub mod observable_signals;

// Display implementations for database types
pub mod display;

// Re-export main types for convenience
pub use db::{Database, Label, Type};
pub use error::DatabaseError;