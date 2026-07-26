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

/// Largest hop count still considered plausible between the fingerprinted
/// host and the sensor. Beyond it the observed TTL no longer supports the
/// signature's initial TTL, and the match degrades to fuzzy. Mirrors p0f's
/// `MAX_DIST`.
pub const MAX_TTL_DISTANCE: u8 = 35;

/// TTL as seen on the wire, whichever form the observation was classified
/// into by `huginn_net_tcp::tcp::calculate_ttl`.
fn observed_ttl(observed: &Ttl) -> u8 {
    match observed {
        Ttl::Value(ttl) | Ttl::Distance(ttl, _) | Ttl::Guess(ttl) | Ttl::Bad(ttl) => *ttl,
    }
}

/// Initial TTL a database signature claims for the OS. Matches p0f's `.fp`
/// parsing: `nnn+d` sums both halves, while `nnn` and `nnn-` are used
/// verbatim.
fn signature_initial_ttl(signature: &Ttl) -> u8 {
    match signature {
        Ttl::Value(ttl) | Ttl::Guess(ttl) | Ttl::Bad(ttl) => *ttl,
        Ttl::Distance(ttl, distance) => ttl.saturating_add(*distance),
    }
}

/// How an observed TTL sits against the initial TTL a signature declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlFit {
    /// Hops the packet appears to have travelled: the signature's initial TTL
    /// minus the observed one. Doubles as the tie-break between two signatures
    /// that both fit, since the closer initial TTL is the better explanation.
    pub hop_distance: u32,
    /// The hop count is not plausible ([`MAX_TTL_DISTANCE`]), so the signature
    /// only holds as a fuzzy match.
    pub out_of_range: bool,
}

/// Compares an observed `Ttl` against a database `Ttl`.
///
/// TTL is not compared for equality: routers decrement it, so the observed
/// value is expected to sit *below* the signature's initial TTL, by at most
/// [`MAX_TTL_DISTANCE`] hops. Within that window the field fits; outside it the
/// signature still fits, but only as fuzzy — p0f never rejects on TTL alone.
///
/// The one exception is a signature with a randomised TTL (`nnn-`, parsed as
/// [`Ttl::Bad`]): the value carries no hop information, so only the upper
/// bound is enforced, and exceeding it is a hard reject.
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

/// Whether the window seen on the wire satisfies the one a signature declares.
///
/// The comparison is driven by the *signature's* form, never by a form imposed
/// on the observation: a literal is equality against the raw value, `%n` is a
/// modulo on the raw value, and only `mss*n` and `mtu*n` consult the multiplier
/// [`huginn_net_tcp::tcp::detect_win_multi`] derived from the observation. That
/// is what keeps a literal signature reachable no matter what multiple the
/// window happens to be.
///
/// A mismatch never degrades to fuzzy: p0f's window check does not tolerate one,
/// whatever the form. Only `WindowSize::Any` is a true wildcard.
pub fn window_size_matches(
    observed: u16,
    signature: &WindowSize,
    multiplier: Option<WindowMultiplier>,
) -> bool {
    match signature {
        WindowSize::Any => true,
        WindowSize::Value(value) => observed == *value,
        WindowSize::Mod(modulus) => *modulus != 0 && observed % *modulus == 0,
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
