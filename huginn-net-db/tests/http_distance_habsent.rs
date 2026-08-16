#![cfg(feature = "http")]

use huginn_net_db::http::{absent_headers_match, Header};

#[test]
fn empty_absent_list_always_matches() {
    let observed = vec![Header::new("Host"), Header::new("Accept-Charset")];

    assert!(absent_headers_match(&observed, &[]));
}

#[test]
fn forbidden_header_absent_from_traffic_matches() {
    let observed = vec![Header::new("Host"), Header::new("User-Agent")];
    let forbidden = vec![Header::new("Accept-Charset"), Header::new("Keep-Alive")];

    assert!(absent_headers_match(&observed, &forbidden));
}

#[test]
fn forbidden_header_present_in_traffic_rejects() {
    let observed = vec![
        Header::new("Host"),
        Header::new("Accept-Charset").with_value("utf-8"),
        Header::new("User-Agent"),
    ];
    let forbidden = vec![Header::new("Accept-Charset")];

    assert!(!absent_headers_match(&observed, &forbidden));
}

#[test]
fn only_the_header_name_is_considered() {
    // The `.fp` grammar has no values in the habsent list, but a value on
    // either side must not change the outcome.
    let observed = vec![Header::new("Keep-Alive").with_value("timeout=5")];
    let forbidden = vec![Header::new("Keep-Alive").with_value("something else")];

    assert!(!absent_headers_match(&observed, &forbidden));
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

    assert!(!absent_headers_match(&observed, &forbidden));
}
