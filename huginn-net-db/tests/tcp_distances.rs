#![cfg(feature = "tcp")]
use huginn_net_db::tcp::{
    distance_ttl, distance_window_size, TcpMatchQuality, Ttl, WindowSize, MAX_TTL_DISTANCE,
};

fn exact() -> Option<u32> {
    Some(TcpMatchQuality::High.as_score())
}

/// Score of a TTL that no longer supports the signature's initial TTL: still
/// a match, but only a fuzzy one.
fn fuzzy() -> Option<u32> {
    Some(TcpMatchQuality::Low.as_score())
}

#[test]
fn test_distance_ttl_matches_when_observed_equals_initial() {
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Value(64)), exact());
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Guess(64)), exact());
    // `nnn+d` in the database means "initial TTL is nnn + d".
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Distance(57, 7)), exact());
}

#[test]
fn test_distance_ttl_matches_within_hop_distance() {
    // Observed TTL below the signature's initial TTL is the normal case: the
    // difference is the hop count, and any plausible count matches exactly.
    assert_eq!(distance_ttl(&Ttl::Distance(57, 7), &Ttl::Value(64)), exact());
    assert_eq!(distance_ttl(&Ttl::Value(50), &Ttl::Value(64)), exact());
    assert_eq!(distance_ttl(&Ttl::Guess(100), &Ttl::Value(128)), exact());
    // The old implementation compared the enum contents, so a signature
    // written as `60+7` (initial TTL 67) failed against an observed 64.
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Distance(60, 7)), exact());
}

#[test]
fn test_distance_ttl_hop_distance_boundary() {
    let initial = 64;
    let at_limit = initial - MAX_TTL_DISTANCE;
    assert_eq!(distance_ttl(&Ttl::Value(at_limit), &Ttl::Value(initial)), exact());
    assert_eq!(distance_ttl(&Ttl::Value(at_limit - 1), &Ttl::Value(initial)), fuzzy());
}

#[test]
fn test_distance_ttl_is_fuzzy_beyond_hop_distance() {
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Value(128)), fuzzy());
    assert_eq!(distance_ttl(&Ttl::Distance(57, 7), &Ttl::Value(128)), fuzzy());
    // TTL 0 (parsed as `Bad` on the observed side) against a normal signature.
    assert_eq!(distance_ttl(&Ttl::Bad(0), &Ttl::Value(64)), fuzzy());
}

#[test]
fn test_distance_ttl_is_fuzzy_when_observed_exceeds_initial() {
    // A TTL can only decrease in transit, so this cannot be a clean match.
    assert_eq!(distance_ttl(&Ttl::Value(128), &Ttl::Value(64)), fuzzy());
}

#[test]
fn test_distance_ttl_randomised_signature_only_enforces_upper_bound() {
    // `nnn-` in the database: the value carries no hop information, so any
    // observation at or below it matches, and anything above is rejected.
    assert_eq!(distance_ttl(&Ttl::Value(64), &Ttl::Bad(64)), exact());
    assert_eq!(distance_ttl(&Ttl::Value(1), &Ttl::Bad(64)), exact());
    assert_eq!(distance_ttl(&Ttl::Distance(64, 7), &Ttl::Bad(0)), None);
    assert_eq!(distance_ttl(&Ttl::Value(65), &Ttl::Bad(64)), None);
}

/// p0f never tolerates a window-size mismatch: every branch below must reject (`None`) rather than fall back to a soft `Low` penalty.
#[test]
fn test_distance_window_size_matching_cases() {
    assert_eq!(
        distance_window_size(&WindowSize::Mss(4), &WindowSize::Mss(4), None),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_window_size(&WindowSize::Mtu(2), &WindowSize::Mtu(2), None),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_window_size(&WindowSize::Mod(8192), &WindowSize::Mod(8192), None),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_window_size(&WindowSize::Value(65535), &WindowSize::Value(65535), None),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_window_size(&WindowSize::Value(5840), &WindowSize::Mss(4), Some(1460)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_window_size(&WindowSize::Value(12345), &WindowSize::Any, None),
        Some(TcpMatchQuality::High.as_score())
    );
}

#[test]
fn test_distance_window_size_rejects_on_mismatch() {
    assert_eq!(distance_window_size(&WindowSize::Mss(4), &WindowSize::Mss(5), None), None);
    assert_eq!(distance_window_size(&WindowSize::Mtu(2), &WindowSize::Mtu(3), None), None);
    assert_eq!(distance_window_size(&WindowSize::Mod(8192), &WindowSize::Mod(4096), None), None);
    assert_eq!(
        distance_window_size(&WindowSize::Value(65535), &WindowSize::Value(1), None),
        None
    );
    // Wrong ratio for the observed MSS.
    assert_eq!(
        distance_window_size(&WindowSize::Value(5840), &WindowSize::Mss(3), Some(1460)),
        None
    );
    // No observed MSS available to resolve the ratio against.
    assert_eq!(distance_window_size(&WindowSize::Value(5840), &WindowSize::Mss(4), None), None);
}
