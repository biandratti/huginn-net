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
use huginn_net_http::http::UNKNOWN_SOFTWARE;
use tracing::debug;

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

/// Signature `horder` vs traffic headers: required names in order, extras free.
/// Signature values are substrings. `?` may be missing, not out of order.
pub fn distance_header(observed: &[Header], signature: &[Header]) -> Option<u32> {
    let mut position = 0usize;

    for expected in signature {
        let found = observed
            .get(position..)
            .and_then(|rest| rest.iter().position(|h| h.name == expected.name));

        match found {
            Some(offset) => {
                let header = observed.get(position.saturating_add(offset))?;
                if let Some(expected_value) = expected.value.as_deref() {
                    if !header
                        .value
                        .as_deref()
                        .is_some_and(|v| v.contains(expected_value))
                    {
                        debug!(
                            "header {} value mismatch: expected substring {expected_value}",
                            expected.name
                        );
                        return None;
                    }
                }
                position = position.saturating_add(offset).saturating_add(1);
            }
            None => {
                if !expected.optional {
                    debug!("required header {} missing", expected.name);
                    return None;
                }
                if observed.iter().any(|h| h.name == expected.name) {
                    debug!("optional header {} present but out of order", expected.name);
                    return None;
                }
            }
        }
    }

    Some(HttpMatchQuality::High.as_score())
}

/// Reject if any signature `habsent` name appears in the traffic headers.
pub fn distance_habsent(observed: &[Header], signature_absent: &[Header]) -> Option<u32> {
    for forbidden in signature_absent {
        if observed.iter().any(|h| h.name == forbidden.name) {
            debug!("forbidden header {} present in traffic", forbidden.name);
            return None;
        }
    }

    Some(HttpMatchQuality::High.as_score())
}

/// True if `observed` contains the signature `expsw` substring.
/// Empty on either side counts as a match.
pub fn expsw_matches(observed: &str, signature: &str) -> bool {
    if signature.is_empty() || observed.is_empty() || observed == UNKNOWN_SOFTWARE {
        return true;
    }

    observed.contains(signature)
}
