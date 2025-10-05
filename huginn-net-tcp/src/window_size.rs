use crate::tcp::{IpVersion, WindowSize};

/// Detects window size patterns following p0f's logic
pub fn detect_win_multiplicator(
    window_size: u16,
    mss: u16,
    total_header: u16,
    has_ts: bool,
    ip_ver: &IpVersion,
) -> WindowSize {
    const MIN_TCP4: u16 = 40; // 20 IP + 20 TCP
    const MIN_TCP6: u16 = 60; // 40 IP + 20 TCP
    const ETH_MTU: u16 = 1500; // Standard Ethernet MTU
    const TS_SIZE: u16 = 12; // TCP Timestamp option size in bytes (8 bytes for timestamps + 2 for kind/length + 2 padding)
    const MAX_MULTIPLIER: u16 = 255; // Maximum value for u8 multiplier (used in Mss and Mtu variants)

    // If there's no window or MSS is too small, return direct value
    if window_size == 0 || mss < 100 {
        return WindowSize::Value(window_size);
    }

    // 1. First check MSS multiples
    macro_rules! check_mss_div {
        ($div:expr) => {
            if $div != 0 && window_size % $div == 0 {
                let multiplier = window_size / $div;
                if multiplier <= MAX_MULTIPLIER {
                    return WindowSize::Mss(multiplier as u8);
                }
            }
        };
    }

    // 1.1 Check basic MSS and timestamp-adjusted MSS
    if mss > 0 {
        check_mss_div!(mss);
        if has_ts && mss > TS_SIZE {
            check_mss_div!(mss.saturating_sub(TS_SIZE));
        }
    }

    // 2. Check common modulo patterns first
    // These are typical values used by different operating systems
    // Iterate in reverse order to find the largest modulo that divides window_size
    let modulos = [256, 512, 1024, 2048, 4096];
    for &modulo in modulos.iter().rev() {
        if window_size.checked_rem(modulo) == Some(0) {
            return WindowSize::Mod(modulo);
        }
    }

    // 3. Check MTU multiples
    macro_rules! check_mtu_div {
        ($div:expr) => {
            if $div != 0 && window_size % $div == 0 {
                let multiplier = window_size / $div;
                if multiplier <= MAX_MULTIPLIER {
                    return WindowSize::Mtu(multiplier as u8);
                }
            }
        };
    }

    // Standard Ethernet MTU
    check_mtu_div!(ETH_MTU);

    // MTU adjusted for IPv4/IPv6
    match ip_ver {
        IpVersion::V4 => {
            check_mtu_div!(ETH_MTU - MIN_TCP4);
            if has_ts {
                check_mtu_div!(ETH_MTU - MIN_TCP4 - TS_SIZE);
            }
        }
        IpVersion::V6 => {
            check_mtu_div!(ETH_MTU - MIN_TCP6);
            if has_ts {
                check_mtu_div!(ETH_MTU - MIN_TCP6 - TS_SIZE);
            }
        }
        IpVersion::Any => {}
    }

    // 4. Check special MTU cases
    if mss > 0 {
        if total_header > 0 {
            check_mtu_div!(mss.saturating_add(total_header));
        } else {
            match ip_ver {
                IpVersion::V4 => check_mtu_div!(mss.saturating_add(MIN_TCP4)),
                IpVersion::V6 => check_mtu_div!(mss.saturating_add(MIN_TCP6)),
                _ => {}
            }
        }
    }

    // If no pattern is found, return direct value
    WindowSize::Value(window_size)
}
