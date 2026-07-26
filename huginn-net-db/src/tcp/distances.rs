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

/// Distance score between an observed `Ttl` and a database `Ttl`.
///
/// Returns `None` when the two TTL kinds are incompatible (e.g. observed
/// `Bad` vs database `Value`).
pub fn distance_ttl(observed: &Ttl, signature: &Ttl) -> Option<u32> {
    match (observed, signature) {
        (Ttl::Value(a), Ttl::Value(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Distance(a1, a2), Ttl::Distance(b1, b2)) => {
            if a1 == b1 && a2 == b2 {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Distance(a1, a2), Ttl::Value(b1)) => {
            if a1.saturating_add(*a2) == *b1 {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Guess(a), Ttl::Guess(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Bad(a), Ttl::Bad(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Guess(a), Ttl::Value(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Value(a), Ttl::Distance(b1, b2)) => {
            if *a == b1.saturating_add(*b2) {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (Ttl::Value(a), Ttl::Guess(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        _ => None,
    }
}

/// Distance score between an observed `WindowSize` and a database `WindowSize`.
///
/// Takes the observed MSS as context to resolve `WindowSize::Mss(_)` patterns
/// against a raw window value. Returns `None` for incompatible pairings.
///
/// A mismatch is always a hard reject (`None`), never a soft penalty: p0f's
/// window-size check (`data/p0f/fp_tcp.c::tcp_find_match`, the `win_type`
/// switch) never tolerates a mismatch here, regardless of type. Only
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
