use super::{IpVersion, PayloadSize, Ttl, WindowSize};
use tracing::debug;

/// Whether an observed IP version satisfies the one a signature declares.
pub fn ip_version_matches(observed: &IpVersion, signature: &IpVersion) -> bool {
    matches!(
        (observed, signature),
        (_, IpVersion::Any) | (IpVersion::V4, IpVersion::V4) | (IpVersion::V6, IpVersion::V6)
    )
}

/// Largest hop count still considered plausible. Beyond it the match is fuzzy.
/// Same as p0f `MAX_DIST`.
pub const MAX_TTL_DISTANCE: u8 = 35;

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

/// Hop-distance vs the signature's initial TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlFit {
    pub hop_distance: u32,
    /// True when hops exceed [`MAX_TTL_DISTANCE`] (fuzzy, not a reject).
    pub out_of_range: bool,
}

/// Within [`MAX_TTL_DISTANCE`]: fit. Outside: still a fit, `out_of_range`.
/// [`Ttl::Bad`] (`nnn-`): reject if observed > initial.
pub fn ttl_fit(observed: &Ttl, signature: &Ttl) -> Option<TtlFit> {
    let observed = observed_ttl(observed);
    let initial = signature_initial_ttl(signature);
    let hop_distance = u32::from(initial.saturating_sub(observed));

    if matches!(signature, Ttl::Bad(_)) {
        return (observed <= initial).then_some(TtlFit { hop_distance, out_of_range: false });
    }

    let out_of_range = observed > initial || initial.saturating_sub(observed) > MAX_TTL_DISTANCE;
    if out_of_range {
        debug!("ttl out of range: observed {observed}, signature initial {initial}");
    }

    Some(TtlFit { hop_distance, out_of_range })
}

/// Whether an observed `WindowSize` satisfies the one a signature declares.
///
/// Takes the observed MSS as context to resolve `WindowSize::Mss(_)` patterns
/// against a raw window value. A mismatch never degrades to fuzzy: p0f's
/// window-size check does not tolerate one, regardless of type. Only
/// `WindowSize::Any` in the signature is a true wildcard.
pub fn window_size_matches(
    observed: &WindowSize,
    signature: &WindowSize,
    mss: Option<u16>,
) -> bool {
    match (observed, signature) {
        (_, WindowSize::Any) => true,
        (WindowSize::Mss(a), WindowSize::Mss(b)) => a == b,
        (WindowSize::Mtu(a), WindowSize::Mtu(b)) => a == b,
        (WindowSize::Mod(a), WindowSize::Mod(b)) => a == b,
        (WindowSize::Value(a), WindowSize::Value(b)) => a == b,
        (WindowSize::Value(a), WindowSize::Mss(b)) => {
            match mss.and_then(|mss| a.checked_div(mss)) {
                Some(ratio) => {
                    debug!("window size as mss multiple: value {a}, signature {b}, ratio {ratio}");
                    u16::from(*b) == ratio
                }
                None => false,
            }
        }
        _ => false,
    }
}

/// Whether an observed `PayloadSize` satisfies the one a signature declares.
pub fn payload_size_matches(observed: &PayloadSize, signature: &PayloadSize) -> bool {
    signature == &PayloadSize::Any || observed == signature
}
