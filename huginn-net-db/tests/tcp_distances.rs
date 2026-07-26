#![cfg(feature = "tcp")]
use huginn_net_db::tcp::{distance_ttl, distance_window_size, TcpMatchQuality, Ttl, WindowSize};

#[test]
fn test_distance_ttl_matching_cases() {
    assert_eq!(
        distance_ttl(&Ttl::Value(64), &Ttl::Value(64)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Distance(57, 7), &Ttl::Distance(57, 7)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Distance(57, 7), &Ttl::Value(64)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Guess(64), &Ttl::Value(64)),
        Some(TcpMatchQuality::High.as_score())
    );
}

#[test]
fn test_distance_ttl_non_matching_cases() {
    assert_eq!(
        distance_ttl(&Ttl::Value(64), &Ttl::Value(128)),
        Some(TcpMatchQuality::Low.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Distance(57, 7), &Ttl::Value(128)),
        Some(TcpMatchQuality::Low.as_score())
    );
    assert_eq!(distance_ttl(&Ttl::Bad(0), &Ttl::Bad(1)), Some(TcpMatchQuality::Low.as_score()));
}

#[test]
fn test_distance_ttl_additional_cases() {
    assert_eq!(
        distance_ttl(&Ttl::Value(64), &Ttl::Distance(57, 7)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Value(64), &Ttl::Guess(64)),
        Some(TcpMatchQuality::High.as_score())
    );
    assert_eq!(
        distance_ttl(&Ttl::Value(64), &Ttl::Distance(60, 7)),
        Some(TcpMatchQuality::Low.as_score())
    );
}

#[test]
fn test_distance_ttl_incompatible_types() {
    assert_eq!(distance_ttl(&Ttl::Bad(0), &Ttl::Value(64)), None);
    assert_eq!(distance_ttl(&Ttl::Distance(64, 7), &Ttl::Bad(0)), None);
    assert_eq!(distance_ttl(&Ttl::Guess(64), &Ttl::Distance(64, 7)), None);
}

/// p0f never tolerates a window-size mismatch (`data/p0f/fp_tcp.c`, the
/// `win_type` switch in `tcp_find_match`): every branch below must reject
/// (`None`) rather than fall back to a soft `Low` penalty.
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
