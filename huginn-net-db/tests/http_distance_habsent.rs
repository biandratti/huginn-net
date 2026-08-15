#![cfg(feature = "http")]

use huginn_net_db::http::{distance_habsent, Header, HttpMatchQuality};

fn matches() -> Option<u32> {
    Some(HttpMatchQuality::High.as_score())
}

#[test]
fn empty_absent_list_always_matches() {
    let observed = vec![Header::new("Host"), Header::new("Accept-Charset")];

    assert_eq!(distance_habsent(&observed, &[]), matches());
}

#[test]
fn forbidden_header_absent_from_traffic_matches() {
    let observed = vec![Header::new("Host"), Header::new("User-Agent")];
    let forbidden = vec![Header::new("Accept-Charset"), Header::new("Keep-Alive")];

    assert_eq!(distance_habsent(&observed, &forbidden), matches());
}

#[test]
fn forbidden_header_present_in_traffic_rejects() {
    let observed = vec![
        Header::new("Host"),
        Header::new("Accept-Charset").with_value("utf-8"),
        Header::new("User-Agent"),
    ];
    let forbidden = vec![Header::new("Accept-Charset")];

    assert_eq!(distance_habsent(&observed, &forbidden), None);
}

#[test]
fn only_the_header_name_is_considered() {
    // The `.fp` grammar has no values in the habsent list, but a value on
    // either side must not change the outcome.
    let observed = vec![Header::new("Keep-Alive").with_value("timeout=5")];
    let forbidden = vec![Header::new("Keep-Alive").with_value("something else")];

    assert_eq!(distance_habsent(&observed, &forbidden), None);
}

#[test]
fn position_in_the_traffic_is_irrelevant() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent"),
        Header::new("Accept"),
        Header::new("Keep-Alive"),
    ];
    let forbidden = vec![Header::new("Keep-Alive")];

    assert_eq!(distance_habsent(&observed, &forbidden), None);
}
