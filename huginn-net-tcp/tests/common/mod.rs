//! Helpers shared by the integration-test targets of this crate.
//!
//! Each target includes this file with `#[path = "../common/mod.rs"] mod common;`
//! (same pattern as `examples/support`).

/// Result type for test helpers: errors propagate with `?` and fail the test with a message.
pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;
