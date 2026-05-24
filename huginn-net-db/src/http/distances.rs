//! Pure distance helpers between an observed HTTP value and a signature value.
//!
//! These functions take **raw types** (versions, header slices, expected
//! software strings), no observation structs, so they mirror the shape of
//! [`crate::tcp`]'s `distance_*` helpers and can be reused from both the
//! `DatabaseSignature` impl and the public [`HttpDistance`] trait.
//!
//! [`HttpDistance`]: crate::observable_http_signals_matching::HttpDistance

use super::signature::HttpMatchQuality;
use super::{Header, Version};

/// Distance score between an observed [`Version`] and a database [`Version`].
///
/// [`Version::Any`] in the signature matches everything; otherwise versions
/// must be equal.
pub fn distance_http_version(observed: Version, signature: Version) -> Option<u32> {
    if signature == Version::Any || observed == signature {
        Some(HttpMatchQuality::High.as_score())
    } else {
        None
    }
}

/// Distance score between two header slices using p0f's order-respecting,
/// optional-header-aware comparison.
///
/// Implements a two-pointer walk over `observed` and `signature` headers:
/// - Exact matches advance both pointers with no error.
/// - Same name, different value: error unless the signature header is
///   marked optional.
/// - Mismatched names: skip the signature side if optional, otherwise count
///   an error.
/// - Trailing observed headers count as errors; trailing signature headers
///   count as errors unless optional.
///
/// Returns `None` once 12 or more errors accumulate (unmatchable).
pub fn distance_header(observed: &[Header], signature: &[Header]) -> Option<u32> {
    let mut obs_idx = 0usize;
    let mut sig_idx = 0usize;
    let mut errors: u32 = 0;

    while obs_idx < observed.len() && sig_idx < signature.len() {
        let obs_header = &observed[obs_idx];
        let sig_header = &signature[sig_idx];

        if obs_header.name == sig_header.name && obs_header.value == sig_header.value {
            obs_idx = obs_idx.saturating_add(1);
            sig_idx = sig_idx.saturating_add(1);
        } else if obs_header.name == sig_header.name {
            if !sig_header.optional {
                errors = errors.saturating_add(1);
            }
            obs_idx = obs_idx.saturating_add(1);
            sig_idx = sig_idx.saturating_add(1);
        } else if sig_header.optional {
            sig_idx = sig_idx.saturating_add(1);
        } else {
            errors = errors.saturating_add(1);
            sig_idx = sig_idx.saturating_add(1);
        }
    }

    while obs_idx < observed.len() {
        errors = errors.saturating_add(1);
        obs_idx = obs_idx.saturating_add(1);
    }

    while sig_idx < signature.len() {
        if !signature[sig_idx].optional {
            errors = errors.saturating_add(1);
        }
        sig_idx = sig_idx.saturating_add(1);
    }

    match errors {
        0..=2 => Some(HttpMatchQuality::High.as_score()),
        3..=5 => Some(HttpMatchQuality::Medium.as_score()),
        6..=8 => Some(HttpMatchQuality::Low.as_score()),
        9..=11 => Some(HttpMatchQuality::Bad.as_score()),
        _ => None,
    }
}

/// Distance score between an observed `expsw` string and a database
/// signature's `expsw`.
///
/// The observed value is considered a match when the signature's `expsw`
/// contains it as a substring. Mismatches still produce a score
/// ([`HttpMatchQuality::Bad`]) rather than `None`, matching the original
/// behaviour expected by the database matcher.
pub fn distance_expsw(observed: &str, signature: &str) -> Option<u32> {
    if signature.contains(observed) {
        Some(HttpMatchQuality::High.as_score())
    } else {
        Some(HttpMatchQuality::Bad.as_score())
    }
}
