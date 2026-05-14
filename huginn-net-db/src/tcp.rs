//! TCP-side database types.
//!
//! Pure data types ([`IpVersion`], [`Ttl`], [`WindowSize`], [`TcpOption`],
//! [`Quirk`], [`PayloadSize`]) are re-exported from `huginn-net-tcp`. This
//! module owns only the **database-specific** pieces:
//! - [`Signature`] — a fingerprint as defined in p0f's `.fp` format.
//! - [`TcpMatchQuality`] — the per-component quality bucket used during scoring.
//! - distance functions — free functions that compute the distance between
//!   an observed value and a database value.

pub use huginn_net_tcp::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};

use tracing::debug;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub version: IpVersion,
    /// initial TTL used by the OS.
    pub ittl: Ttl,
    /// length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// window size.
    pub wsize: WindowSize,
    /// window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<Quirk>,
    /// payload size classification
    pub pclass: PayloadSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMatchQuality {
    High,
    Medium,
    Low,
}

impl TcpMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            TcpMatchQuality::High => 0,
            TcpMatchQuality::Medium => 1,
            TcpMatchQuality::Low => 2,
        }
    }
}

impl crate::db_matching_trait::MatchQuality for TcpMatchQuality {
    // TCP has 9 components, each can contribute max 2 points (Low)
    const MAX_DISTANCE: u32 = 18;

    fn distance_to_score(distance: u32) -> f32 {
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3..=4 => 0.80,
            5..=6 => 0.70,
            7..=9 => 0.60,
            10..=12 => 0.40,
            13..=15 => 0.20,
            d if d <= Self::MAX_DISTANCE => 0.10,
            _ => 0.05,
        }
    }
}

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
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (WindowSize::Mtu(a), WindowSize::Mtu(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
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
                        Some(TcpMatchQuality::Low.as_score())
                    }
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (WindowSize::Mod(a), WindowSize::Mod(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
            }
        }
        (WindowSize::Value(a), WindowSize::Value(b)) => {
            if a == b {
                Some(TcpMatchQuality::High.as_score())
            } else {
                Some(TcpMatchQuality::Low.as_score())
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
