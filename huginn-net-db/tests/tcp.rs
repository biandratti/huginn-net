#![cfg(feature = "tcp")]
use huginn_net_db::tcp::{distance_ttl, TcpMatchQuality, Ttl};

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
