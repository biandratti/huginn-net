//! Helpers shared by the integration-test targets of this crate.
//!
//! Each target includes this file with `#[path = "../common/mod.rs"] mod common;`
//! (same pattern as `examples/support`).

use serde::de::DeserializeOwned;
use std::fs;

/// Result type for test helpers: errors propagate with `?` and fail the test with a message.
pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Load a golden snapshot `tests/snapshots/<name>.json` into the caller's snapshot type.
pub(crate) fn load_snapshot<T: DeserializeOwned>(
    name: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let path = format!("tests/snapshots/{name}.json");
    let content =
        fs::read_to_string(&path).map_err(|e| format!("failed to read snapshot {path}: {e}"))?;
    let snapshot = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse snapshot {path}: {e}"))?;
    Ok(snapshot)
}

/// Parse the float out of an expected `Matched(<quality>)` string.
pub(crate) fn expected_quality(
    expected: &str,
    ctx: &str,
) -> Result<f32, Box<dyn std::error::Error>> {
    expected
        .strip_prefix("Matched(")
        .and_then(|s| s.strip_suffix(")"))
        .ok_or_else(|| format!("{ctx}: unexpected quality format: {expected}"))?
        .parse::<f32>()
        .map_err(|_| format!("{ctx}: cannot parse quality float from: {expected}").into())
}
