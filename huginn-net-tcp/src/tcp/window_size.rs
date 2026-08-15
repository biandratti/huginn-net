use super::IpVersion;

/// Observed window as a multiple of MSS (`of_mtu = false`) or MTU.
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
/// Padded timestamp option size, subtracted by some stacks.
const TS_SIZE: u16 = 12;
/// Below this, no meaningful window multiplier.
const MIN_USEFUL_MSS: u16 = 100;

/// First divisor that divides `wsize` evenly, in p0f's order. Zero skips.
pub fn detect_win_multi(
    wsize: u16,
    mss: Option<u16>,
    tot_hdr: u16,
    own_timestamp_is_nonzero: bool,
    version: IpVersion,
    peer_mss: Option<u16>,
) -> Option<WindowMultiplier> {
    if wsize == 0 {
        return None;
    }
    let mss = mss.filter(|&mss| mss >= MIN_USEFUL_MSS)?;
    let ipv6 = version == IpVersion::V6;
    let only_if = |applies: bool, divisor: u16| if applies { divisor } else { 0 };
    let peer = peer_mss.filter(|&mss| mss != 0);

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
        (peer.unwrap_or(0), false),
        (peer.map(|m| m.saturating_sub(TS_SIZE)).unwrap_or(0), false),
    ];

    divisors.into_iter().find_map(|(divisor, of_mtu)| {
        let multiple = wsize.checked_div(divisor)?;
        let remainder = wsize.checked_rem(divisor)?;
        (remainder == 0).then_some(WindowMultiplier { multiple, of_mtu })
    })
}
