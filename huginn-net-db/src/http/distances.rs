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

/// Distance score between the headers a database signature expects
/// (`horder`) and the headers seen in the traffic.
///
/// Header matching has no error budget in p0f: every header the signature
/// lists must be found in the observed list, in the same relative order, and
/// any mismatch rejects the whole signature. Concretely:
///
/// - Observed headers the signature does not mention are skipped for free,
///   however many of them appear and wherever they appear.
/// - When the signature specifies a value, the observed value must *contain*
///   it as a substring (so `Accept=[,*/*]` matches a longer real `Accept`),
///   and an observed header carrying no value never satisfies one that
///   expects a value.
/// - A required header that is not found rejects the signature.
/// - An optional header (`?` in the `.fp`) may be missing, but only if it is
///   absent from the traffic altogether: appearing in a different position
///   than the signature dictates is still a mismatch.
///
/// Only the signature's `optional` flag is consulted. Observations carry one
/// too, but it describes how p0f would *print* the header, not how to match
/// it.
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

/// Distance score for a signature's `habsent` list: the headers that must
/// *not* show up in matching traffic.
///
/// Note that `observed` is the list of headers actually seen (the
/// observation's `horder`), not the observation's own `habsent`. p0f checks
/// its forbidden headers against the traffic's real headers; an observation's
/// `habsent` is only the set of common headers it happened to be missing,
/// which exists to print a candidate signature, not to match one.
pub fn distance_habsent(observed: &[Header], signature_absent: &[Header]) -> Option<u32> {
    for forbidden in signature_absent {
        if observed.iter().any(|h| h.name == forbidden.name) {
            debug!("forbidden header {} present in traffic", forbidden.name);
            return None;
        }
    }

    Some(HttpMatchQuality::High.as_score())
}

/// Whether the software string seen in the traffic backs up the one the
/// matched signature declares (`expsw`).
///
/// This is deliberately *not* a distance. In p0f the check runs only once a
/// signature has already been chosen, and its outcome never rejects the
/// signature nor makes it rank lower: it just flags the host as dishonest,
/// because a host whose headers say Chrome while its `User-Agent` says
/// something else is still a Chrome-shaped host.
///
/// The observed `User-Agent`/`Server` value must *contain* the signature's
/// expected substring; note the database usually writes it with a leading
/// space (`" Chrom"`), which is significant and keeps the match anchored at a
/// token boundary. Either side having nothing to say means there is nothing
/// to contradict, so it counts as honest.
pub fn expsw_matches(observed: &str, signature: &str) -> bool {
    if signature.is_empty() || observed.is_empty() || observed == UNKNOWN_SOFTWARE {
        return true;
    }

    observed.contains(signature)
}
