//! p0f's `detect_win_multi`: which divisor a window turns out to be a multiple
//! of, tried in p0f's order, and which signature family the answer belongs to.

use huginn_net_tcp::tcp::{detect_win_multi, IpVersion, WindowMultiplier};

/// Twenty bytes of IP header plus twenty of TCP, no options on either.
const NO_OPTIONS: u16 = 40;

fn multi(wsize: u16, mss: u16) -> Option<WindowMultiplier> {
    detect_win_multi(wsize, Some(mss), NO_OPTIONS, false, IpVersion::V4, None)
}

#[test]
fn a_multiple_of_the_mss_answers_for_the_mss_family() {
    assert_eq!(multi(40000, 1000), Some(WindowMultiplier { multiple: 40, of_mtu: false }));
}

#[test]
fn a_window_that_leaves_a_remainder_is_not_a_multiple_of_the_mss() {
    // 65535 is 44.88 times 1460: p0f moves on to the next divisor rather than
    // rounding down to `mss*44`.
    assert_ne!(multi(65535, 1460), Some(WindowMultiplier { multiple: 44, of_mtu: false }));
}

#[test]
fn the_timestamp_adjusted_mss_is_only_tried_when_a_timestamp_was_sent() {
    // An MSS of 1400 keeps `mss - 12` clear of the unconditional `1500 - 40 - 12`
    // divisor, which is also 1448 when the MSS is 1460.
    let window = (1400 - 12) * 30;

    assert_eq!(
        detect_win_multi(window, Some(1400), NO_OPTIONS, true, IpVersion::V4, None),
        Some(WindowMultiplier { multiple: 30, of_mtu: false }),
        "some stacks subtract the cost of a timestamp before scaling the window"
    );
    assert_eq!(
        detect_win_multi(window, Some(1400), NO_OPTIONS, false, IpVersion::V4, None),
        None,
        "without a timestamp of its own that divisor is not p0f's to try"
    );
}

#[test]
fn a_multiple_of_the_mtu_answers_for_the_mtu_family() {
    // 4500 is 3 * 1500, and no earlier divisor divides it evenly with MSS 1460.
    assert_eq!(multi(4500, 1460), Some(WindowMultiplier { multiple: 3, of_mtu: true }));
}

#[test]
fn a_power_of_two_window_is_not_a_multiple_of_anything() {
    // p0f never reads a modulo out of an observation: `%n` exists only as a
    // signature form. A window of 8192 stays raw so that a signature declaring
    // the literal 8192 can still match it.
    assert_eq!(multi(8192, 1460), None);
}

#[test]
fn a_window_of_zero_has_no_multiplier() {
    assert_eq!(multi(0, 1460), None);
}

#[test]
fn an_mss_too_small_to_read_carries_no_multiplier() {
    // Below 100 p0f turns the whole detection off, so 396 is not reported as
    // four times an MSS of 99.
    assert_eq!(multi(396, 99), None);
}

#[test]
fn an_absent_mss_carries_no_multiplier() {
    assert_eq!(detect_win_multi(4500, None, NO_OPTIONS, false, IpVersion::V4, None), None);
}

#[test]
fn the_mss_divisor_wins_over_the_mtu_one() {
    // 5840 is both 4 * 1460 (MSS) and, were the order reversed, a candidate for
    // later divisors. p0f tries MSS first.
    assert_eq!(multi(5840, 1460), Some(WindowMultiplier { multiple: 4, of_mtu: false }));
}

#[test]
fn the_actual_header_size_is_one_of_the_mtu_divisors() {
    // MSS 1460 plus 60 bytes of headers is 1520; twice that is 3040, and no
    // earlier divisor divides it evenly.
    assert_eq!(
        detect_win_multi(3040, Some(1460), 60, false, IpVersion::V4, None),
        Some(WindowMultiplier { multiple: 2, of_mtu: true })
    );
}

#[test]
fn the_peer_mss_is_tried_after_the_own_divisors() {
    // Own MSS 1460 does not divide 28000; peer MSS 1400 does (20×). No earlier
    // unconditional divisor divides it either, so p0f answers with the peer.
    assert_eq!(
        detect_win_multi(28000, Some(1460), NO_OPTIONS, false, IpVersion::V4, Some(1400)),
        Some(WindowMultiplier { multiple: 20, of_mtu: false })
    );
}

#[test]
fn the_peer_mss_does_not_rescue_a_useless_own_mss() {
    // p0f returns before trying the peer when the own MSS is below 100.
    assert_eq!(
        detect_win_multi(28000, Some(99), NO_OPTIONS, false, IpVersion::V4, Some(1400)),
        None
    );
}

#[test]
fn a_zero_peer_mss_is_ignored() {
    assert_eq!(
        detect_win_multi(28000, Some(1460), NO_OPTIONS, false, IpVersion::V4, Some(0)),
        None
    );
}
