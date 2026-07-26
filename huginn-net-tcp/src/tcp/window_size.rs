use super::IpVersion;

/// An observed window expressed as a multiple of the MSS or of the MTU.
///
/// Which of the two it is decides whether `mss*n` or `mtu*n` signatures are
/// eligible: they are separate families and a multiplier only ever answers for
/// one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowMultiplier {
    /// The multiplier itself: the observed window divided by whichever divisor
    /// came out even first.
    pub multiple: u16,
    /// The divisor was an MTU rather than an MSS.
    pub of_mtu: bool,
}

/// IPv4 header plus TCP header, neither carrying options.
const MIN_TCP4: u16 = 40;
/// IPv6 header plus TCP header, neither carrying options.
const MIN_TCP6: u16 = 60;
/// Standard Ethernet MTU.
const ETH_MTU: u16 = 1500;
/// What a timestamp option costs once padded, which some stacks subtract from
/// the segment size they scale the window by.
const TS_SIZE: u16 = 12;
/// Below this an MSS is too small to read a meaningful multiplier out of.
const MIN_USEFUL_MSS: u16 = 100;

/// Expresses an observed window as a multiple of the MSS or the MTU, when it is
/// one.
///
/// Mirrors p0f's `detect_win_multi`. The observed window is *not* stored in this
/// form anywhere: a signature declaring a literal window has to stay comparable
/// against the raw value, so the multiplier is derived on demand and only the
/// `mss*n` and `mtu*n` signature forms ever consult it.
///
/// Divisors are tried in p0f's order and the first one that divides evenly wins,
/// independently of what any signature declares. A divisor of zero means "skip",
/// which is how the cases that depend on timestamps or on the IP version drop
/// out.
pub fn detect_win_multi(
    wsize: u16,
    mss: Option<u16>,
    tot_hdr: u16,
    own_timestamp_is_nonzero: bool,
    version: IpVersion,
) -> Option<WindowMultiplier> {
    if wsize == 0 {
        return None;
    }
    let mss = mss.filter(|&mss| mss >= MIN_USEFUL_MSS)?;
    let ipv6 = version == IpVersion::V6;
    let only_if = |applies: bool, divisor: u16| if applies { divisor } else { 0 };

    let divisors = [
        (mss, false),
        (only_if(own_timestamp_is_nonzero, mss.saturating_sub(TS_SIZE)), false),
        (ETH_MTU.saturating_sub(MIN_TCP4), false),
        (ETH_MTU.saturating_sub(MIN_TCP4 + TS_SIZE), false),
        (only_if(ipv6, ETH_MTU.saturating_sub(MIN_TCP6)), false),
        (only_if(ipv6, ETH_MTU.saturating_sub(MIN_TCP6 + TS_SIZE)), false),
        (mss.saturating_add(MIN_TCP4), true),
        (mss.saturating_add(tot_hdr), true),
        (only_if(ipv6, mss.saturating_add(MIN_TCP6)), true),
        (ETH_MTU, true),
    ];

    divisors.into_iter().find_map(|(divisor, of_mtu)| {
        // The checked operations double as the skip: a divisor of zero yields
        // `None` and the search moves on to the next one.
        let multiple = wsize.checked_div(divisor)?;
        let remainder = wsize.checked_rem(divisor)?;

        (remainder == 0).then_some(WindowMultiplier { multiple, of_mtu })
    })
}
