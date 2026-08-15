//! Pure gate helpers between an observed HTTP value and a signature value.
//!
//! These functions take **raw types** (versions, header slices, expected
//! software strings), no observation structs, so they mirror the shape of
//! [`crate::tcp`]'s helpers and can be reused from both the
//! `DatabaseSignature` impl and the public [`HttpDistance`] trait.
//!
//! [`HttpDistance`]: crate::observable_http_signals_matching::HttpDistance

use super::{Header, Version};
use huginn_net_http::http::UNKNOWN_SOFTWARE;
use tracing::debug;

/// Whether an observed [`Version`] satisfies a database [`Version`].
///
/// [`Version::Any`] in the signature matches everything; otherwise versions
/// must be equal.
pub fn http_version_matches(observed: Version, signature: Version) -> bool {
    signature == Version::Any || observed == signature
}

/// Signature `horder` vs traffic headers: required names in order, extras free.
/// Signature values are substrings. `?` may be missing, not out of order.
pub fn headers_match(observed: &[Header], signature: &[Header]) -> bool {
    let mut position = 0usize;

    for expected in signature {
        let found = observed
            .get(position..)
            .and_then(|rest| rest.iter().position(|h| h.name == expected.name));

        match found {
            Some(offset) => {
                let Some(header) = observed.get(position.saturating_add(offset)) else {
                    return false;
                };
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
                        return false;
                    }
                }
                position = position.saturating_add(offset).saturating_add(1);
            }
            None => {
                if !expected.optional {
                    debug!("required header {} missing", expected.name);
                    return false;
                }
                if observed.iter().any(|h| h.name == expected.name) {
                    debug!("optional header {} present but out of order", expected.name);
                    return false;
                }
            }
        }
    }

    true
}

/// Reject if any signature `habsent` name appears in the traffic headers.
pub fn absent_headers_match(observed: &[Header], signature_absent: &[Header]) -> bool {
    for forbidden in signature_absent {
        if observed.iter().any(|h| h.name == forbidden.name) {
            debug!("forbidden header {} present in traffic", forbidden.name);
            return false;
        }
    }

    true
}

/// True if `observed` contains the signature `expsw` substring.
/// Empty on either side counts as a match.
pub fn expsw_matches(observed: &str, signature: &str) -> bool {
    if signature.is_empty() || observed.is_empty() || observed == UNKNOWN_SOFTWARE {
        return true;
    }

    observed.contains(signature)
}
