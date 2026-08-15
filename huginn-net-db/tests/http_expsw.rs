#![cfg(feature = "http")]
//! `expsw` is p0f's "expected software" field: what the matched signature
//! claims the software is. It is checked *after* a signature wins, and its
//! only effect is to flag the host as dishonest, never to reject or demote
//! the signature.

use huginn_net_db::db_matching_trait::{DatabaseSignature, FingerprintDb};
use huginn_net_db::{http, HttpDatabase, SharedHttpSignatureMatcher};
use huginn_net_http::matcher_api::HttpMatcher;
use huginn_net_http::observable::HttpRequestObservation;
use std::sync::Arc;

/// A full `User-Agent` as seen on the wire.
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

/// How the database writes the claim: a short substring, kept anchored at a
/// token boundary by a leading space.
const CHROME_EXPSW: &str = " Chrom";

#[test]
fn observed_software_must_contain_the_signature_claim() {
    assert!(
        http::expsw_matches(CHROME_UA, CHROME_EXPSW),
        "the traffic's User-Agent is the haystack and the signature's claim the needle"
    );
    assert!(
        !http::expsw_matches(CHROME_EXPSW, CHROME_UA),
        "comparing the other way round can never hold for real traffic"
    );
}

#[test]
fn the_leading_space_keeps_the_claim_on_a_token_boundary() {
    assert!(!http::expsw_matches("Mozilla/5.0 UnChromed/1.0", CHROME_EXPSW));
}

#[test]
fn nothing_to_compare_counts_as_honest() {
    assert!(
        http::expsw_matches(CHROME_UA, ""),
        "a signature that claims nothing cannot be contradicted"
    );
    assert!(
        http::expsw_matches("", CHROME_EXPSW),
        "traffic that says nothing makes no claim to check"
    );
    assert!(
        http::expsw_matches(http::UNKNOWN_SOFTWARE, CHROME_EXPSW),
        "the absent-header placeholder is not a literal claim"
    );
}

#[test]
fn a_contradicting_software_string_is_dishonest() {
    assert!(!http::expsw_matches("Mozilla/5.0 Firefox/128.0", CHROME_EXPSW));
}

/// The point of keeping `expsw` out of the comparison: two observations that
/// differ *only* in their software string must be equally good matches.
#[test]
fn software_string_does_not_change_the_fit() {
    let db = HttpDatabase::load_default()
        .unwrap_or_else(|e| panic!("failed to create default database: {e}"));

    let observation = |expsw: &str| HttpRequestObservation {
        version: http::Version::V10,
        horder: vec![
            http::Header::new("Host"),
            http::Header::new("User-Agent"),
            http::Header::new("Accept").with_value(",*/*;q="),
            http::Header::new("Accept-Language").optional(),
            http::Header::new("Accept-Encoding").with_value("gzip,deflate"),
            http::Header::new("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
            http::Header::new("Keep-Alive").with_value("300"),
            http::Header::new("Connection").with_value("keep-alive"),
        ],
        habsent: vec![],
        expsw: expsw.to_string(),
    };

    let honest_match = db
        .http_request
        .find_best_match(&observation("Firefox/"))
        .unwrap_or_else(|| panic!("no match found for the Firefox 2.x signature"));

    let honest = honest_match.signature.fit(&observation("Firefox/"));
    let lying = honest_match
        .signature
        .fit(&observation("definitely-not-firefox"));
    assert_eq!(honest, lying, "expsw must not affect how well the signature fits");

    let lying_match = db
        .http_request
        .find_best_match(&observation("definitely-not-firefox"))
        .unwrap_or_else(|| panic!("a dishonest software string must not reject the signature"));
    assert_eq!(honest_match.quality, lying_match.quality);
}

/// The flag rides along with the match, because it takes the winning
/// signature to know what was claimed.
#[test]
fn the_match_reports_whether_the_host_is_dishonest() {
    let db = HttpDatabase::load_default()
        .unwrap_or_else(|e| panic!("failed to create default database: {e}"));
    let matcher = SharedHttpSignatureMatcher::new(Arc::new(db));

    let observation = |expsw: &str| HttpRequestObservation {
        version: http::Version::V10,
        horder: vec![
            http::Header::new("Host"),
            http::Header::new("User-Agent"),
            http::Header::new("Accept").with_value(",*/*;q="),
            http::Header::new("Accept-Language").optional(),
            http::Header::new("Accept-Encoding").with_value("gzip,deflate"),
            http::Header::new("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
            http::Header::new("Keep-Alive").with_value("300"),
            http::Header::new("Connection").with_value("keep-alive"),
        ],
        habsent: vec![],
        expsw: expsw.to_string(),
    };

    let honest = matcher
        .match_http_request(&observation("Mozilla/5.0 Firefox/2.0.0.1"))
        .unwrap_or_else(|| panic!("expected a match for the honest request"));
    assert!(!honest.dishonest);

    let lying = matcher
        .match_http_request(&observation("Mozilla/5.0 Chrome/137.0.0.0"))
        .unwrap_or_else(|| panic!("expected the same match for the lying request"));
    assert_eq!(lying.browser.name, honest.browser.name, "same headers, same browser");
    assert!(lying.dishonest, "headers say Firefox 2.x but the User-Agent says Chrome");
}
