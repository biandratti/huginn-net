use super::{IpVersion, PayloadSize, Ttl, WindowSize};
use huginn_net_tcp::tcp::WindowMultiplier;
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

/// Signature window vs the raw value. `mss*n` / `mtu*n` use the derived multiplier.
pub fn window_size_matches(
    observed: u16,
    signature: &WindowSize,
    multiplier: Option<WindowMultiplier>,
) -> bool {
    match signature {
        WindowSize::Any => true,
        WindowSize::Value(value) => observed == *value,
        WindowSize::Mod(modulus) => observed.checked_rem(*modulus) == Some(0),
        WindowSize::Mss(multiple) => multiple_matches(multiplier, *multiple, false),
        WindowSize::Mtu(multiple) => multiple_matches(multiplier, *multiple, true),
    }
}

/// Whether the observed window is a multiple of the right divisor family, by the
/// factor the signature declares.
fn multiple_matches(observed: Option<WindowMultiplier>, declared: u8, of_mtu: bool) -> bool {
    let Some(observed) = observed else {
        debug!("window size is not a multiple of any mss or mtu divisor");
        return false;
    };
    observed.of_mtu == of_mtu && observed.multiple == u16::from(declared)
}

/// Whether an observed `PayloadSize` satisfies the one a signature declares.
pub fn payload_size_matches(observed: &PayloadSize, signature: &PayloadSize) -> bool {
    signature == &PayloadSize::Any || observed == signature
}
