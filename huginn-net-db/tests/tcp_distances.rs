#![cfg(feature = "tcp")]
use huginn_net_db::tcp::{ttl_fit, window_size_matches, Ttl, TtlFit, WindowSize, MAX_TTL_DISTANCE};
use huginn_net_tcp::tcp::WindowMultiplier;

/// The observation supports the signature's initial TTL, `hops` routers away.
fn exact(hops: u32) -> Option<TtlFit> {
    Some(TtlFit { hop_distance: hops, out_of_range: false })
}

/// The observed TTL no longer supports the signature's initial TTL: still a
/// match, but only a fuzzy one.
fn fuzzy(hops: u32) -> Option<TtlFit> {
    Some(TtlFit { hop_distance: hops, out_of_range: true })
}

#[test]
fn test_ttl_fit_matches_when_observed_equals_initial() {
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Value(64)), exact(0));
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Guess(64)), exact(0));
    // `nnn+d` in the database means "initial TTL is nnn + d".
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Distance(57, 7)), exact(0));
}

#[test]
fn test_ttl_fit_matches_within_hop_distance() {
    // Observed TTL below the signature's initial TTL is the normal case: the
    // difference is the hop count, and any plausible count matches exactly.
    assert_eq!(ttl_fit(&Ttl::Distance(57, 7), &Ttl::Value(64)), exact(7));
    assert_eq!(ttl_fit(&Ttl::Value(50), &Ttl::Value(64)), exact(14));
    assert_eq!(ttl_fit(&Ttl::Guess(100), &Ttl::Value(128)), exact(28));
    // The old implementation compared the enum contents, so a signature
    // written as `60+7` (initial TTL 67) failed against an observed 64.
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Distance(60, 7)), exact(3));
}

#[test]
fn test_ttl_fit_hop_distance_boundary() {
    let initial = 64;
    let at_limit = initial - MAX_TTL_DISTANCE;
    assert_eq!(
        ttl_fit(&Ttl::Value(at_limit), &Ttl::Value(initial)),
        exact(u32::from(MAX_TTL_DISTANCE))
    );
    assert_eq!(
        ttl_fit(&Ttl::Value(at_limit - 1), &Ttl::Value(initial)),
        fuzzy(u32::from(MAX_TTL_DISTANCE) + 1)
    );
}

#[test]
fn test_ttl_fit_is_fuzzy_beyond_hop_distance() {
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Value(128)), fuzzy(64));
    assert_eq!(ttl_fit(&Ttl::Distance(57, 7), &Ttl::Value(128)), fuzzy(71));
    // TTL 0 (parsed as `Bad` on the observed side) against a normal signature.
    assert_eq!(ttl_fit(&Ttl::Bad(0), &Ttl::Value(64)), fuzzy(64));
}

#[test]
fn test_ttl_fit_is_fuzzy_when_observed_exceeds_initial() {
    // A TTL can only decrease in transit, so this cannot be a clean match, and
    // there are no hops to report.
    assert_eq!(ttl_fit(&Ttl::Value(128), &Ttl::Value(64)), fuzzy(0));
}

#[test]
fn test_ttl_fit_randomised_signature_only_enforces_upper_bound() {
    // `nnn-` in the database: the value carries no hop information, so any
    // observation at or below it matches, and anything above is rejected.
    assert_eq!(ttl_fit(&Ttl::Value(64), &Ttl::Bad(64)), exact(0));
    assert_eq!(ttl_fit(&Ttl::Value(1), &Ttl::Bad(64)), exact(63));
    assert_eq!(ttl_fit(&Ttl::Distance(64, 7), &Ttl::Bad(0)), None);
    assert_eq!(ttl_fit(&Ttl::Value(65), &Ttl::Bad(64)), None);
}

/// The raw window is compared against whatever form the *signature* declares,
/// so a literal signature answers no matter what multiple the window happens to
/// be. p0f never tolerates a window mismatch either: every branch below rejects
/// rather than degrading into a fuzzy match.
#[test]
fn test_window_size_matching_cases() {
    let of_mss = |multiple| Some(WindowMultiplier { multiple, of_mtu: false });
    let of_mtu = |multiple| Some(WindowMultiplier { multiple, of_mtu: true });

    assert!(window_size_matches(65535, &WindowSize::Value(65535), None));
    assert!(window_size_matches(12345, &WindowSize::Any, None));
    assert!(window_size_matches(8192, &WindowSize::Mod(4096), None));
    assert!(window_size_matches(5840, &WindowSize::Mss(4), of_mss(4)));
    assert!(window_size_matches(3000, &WindowSize::Mtu(2), of_mtu(2)));

    // A window that is a multiple of something is still the literal value it is.
    assert!(window_size_matches(5840, &WindowSize::Value(5840), of_mss(4)));
}

#[test]
fn test_window_size_rejects_on_mismatch() {
    let of_mss = |multiple| Some(WindowMultiplier { multiple, of_mtu: false });
    let of_mtu = |multiple| Some(WindowMultiplier { multiple, of_mtu: true });

    assert!(!window_size_matches(65535, &WindowSize::Value(1), None));
    assert!(!window_size_matches(8192, &WindowSize::Mod(4095), None));
    // Right multiple, wrong divisor family.
    assert!(!window_size_matches(3000, &WindowSize::Mss(2), of_mtu(2)));
    assert!(!window_size_matches(5840, &WindowSize::Mtu(4), of_mss(4)));
    // Wrong multiple.
    assert!(!window_size_matches(5840, &WindowSize::Mss(3), of_mss(4)));
    // The window is not a multiple of any divisor at all.
    assert!(!window_size_matches(5840, &WindowSize::Mss(4), None));
}
