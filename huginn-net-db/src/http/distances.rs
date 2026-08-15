//! HTTP field gates: version, `horder`, `habsent`, `expsw`.

use super::{Header, Version};
use huginn_net_http::http::UNKNOWN_SOFTWARE;
use tracing::debug;

/// [`Version::Any`] matches any observed version.
pub fn http_version_matches(observed: Version, signature: Version) -> bool {
    signature == Version::Any || observed == signature
}

/// Signature `horder` vs observed headers: same relative order, value is a
/// substring, extras skipped. `optional` only covers total absence.
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

/// Signature `habsent` vs observed `horder`: none of the forbidden names may appear.
pub fn absent_headers_match(observed: &[Header], signature_absent: &[Header]) -> bool {
    for forbidden in signature_absent {
        if observed.iter().any(|h| h.name == forbidden.name) {
            debug!("forbidden header {} present in traffic", forbidden.name);
            return false;
        }
    }

    true
}

/// Observed User-Agent/Server contains the signature `expsw`. Empty on either
/// side is honest. Not a gate: used after a signature has already won.
pub fn expsw_matches(observed: &str, signature: &str) -> bool {
    if signature.is_empty() || observed.is_empty() || observed == UNKNOWN_SOFTWARE {
        return true;
    }

    observed.contains(signature)
}
