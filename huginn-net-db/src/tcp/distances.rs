use super::signature::TcpMatchQuality;
use super::{IpVersion, PayloadSize, Ttl, WindowSize};
use tracing::debug;

/// Distance score between an observed `IpVersion` and a database `IpVersion`.
pub fn distance_ip_version(observed: &IpVersion, signature: &IpVersion) -> Option<u32> {
    if signature == &IpVersion::Any {
        Some(TcpMatchQuality::High.as_score())
    } else {
        match (observed, signature) {
            (IpVersion::V4, IpVersion::V4) | (IpVersion::V6, IpVersion::V6) => {
                Some(TcpMatchQuality::High.as_score())
            }
            _ => None,
        }
    }
}

/// Largest hop count still considered plausible between the fingerprinted
/// host and the sensor. Beyond it the observed TTL no longer supports the
/// signature's initial TTL, and the match degrades to fuzzy. Mirrors
/// `MAX_DIST` in `data/p0f/config.h`.
pub const MAX_TTL_DISTANCE: u8 = 40;

/// TTL as seen on the wire, whichever form the observation was classified
/// into by `huginn_net_tcp::tcp::calculate_ttl`.
fn observed_ttl(observed: &Ttl) -> u8 {
    match observed {
        Ttl::Value(ttl) | Ttl::Distance(ttl, _) | Ttl::Guess(ttl) | Ttl::Bad(ttl) => *ttl,
    }
}

/// Initial TTL a database signature claims for the OS. Matches p0f's
/// `.fp` parsing: `nnn+d` sums both
/// halves, while `nnn` and `nnn-` are used verbatim.
fn signature_initial_ttl(signature: &Ttl) -> u8 {
    match signature {
        Ttl::Value(ttl) | Ttl::Guess(ttl) | Ttl::Bad(ttl) => *ttl,
        Ttl::Distance(ttl, distance) => ttl.saturating_add(*distance),
    }
}

/// Hop-distance vs the signature's initial TTL, not equality.
/// Within [`MAX_TTL_DISTANCE`]: High. Outside: Low (not a reject).
/// [`Ttl::Bad`] (`nnn-`): reject if observed > initial.
pub fn distance_ttl(observed: &Ttl, signature: &Ttl) -> Option<u32> {
    let observed = observed_ttl(observed);
    let initial = signature_initial_ttl(signature);

    if matches!(signature, Ttl::Bad(_)) {
        return if observed > initial {
            None
        } else {
            Some(TcpMatchQuality::High.as_score())
        };
    }

    if observed > initial || initial.saturating_sub(observed) > MAX_TTL_DISTANCE {
        debug!("ttl out of range: observed {observed}, signature initial {initial}");
        Some(TcpMatchQuality::Low.as_score())
    } else {
        Some(TcpMatchQuality::High.as_score())
    }
}

/// Distance score between an observed `WindowSize` and a database `WindowSize`.
///
/// Takes the observed MSS as context to resolve `WindowSize::Mss(_)` patterns
/// against a raw window value. Returns `None` for incompatible pairings.
///
/// A mismatch is always a hard reject (`None`), never a soft penalty: p0f's
/// window-size check never tolerates a mismatch here, regardless of type. Only
/// `WindowSize::Any` in the signature is a true wildcard.
pub fn distance_window_size(
    observed: &WindowSize,
    signature: &WindowSize,
    mss: Option<u16>,
) -> Option<u32> {
    match (observed, signature) {
        (WindowSize::Mss(a), WindowSize::Mss(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                None
            }
        }
        (WindowSize::Mtu(a), WindowSize::Mtu(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                None
            }
        }
        (WindowSize::Value(a), WindowSize::Mss(b)) => {
            if let Some(mss_value) = mss {
                if let Some(ratio_other) = a.checked_div(mss_value) {
                    if *b as u16 == ratio_other {
                        debug!(
                            "window size difference: a {}, b {} == ratio_other {}",
                            a, b, ratio_other
                        );
                        Some(TcpMatchQuality::High.as_score())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
        (WindowSize::Mod(a), WindowSize::Mod(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                None
            }
        }
        (WindowSize::Value(a), WindowSize::Value(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                None
            }
        }
        (_, WindowSize::Any) => Some(TcpMatchQuality::High.as_score()),
        _ => None,
    }
}

/// Distance score between an observed `PayloadSize` and a database `PayloadSize`.
pub fn distance_payload_size(observed: &PayloadSize, signature: &PayloadSize) -> Option<u32> {
    if signature == &PayloadSize::Any || observed == signature {
        Some(TcpMatchQuality::High.as_score())
    } else {
        None
    }
}
