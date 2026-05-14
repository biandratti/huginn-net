//! Layer 2 golden test: feed canonical HTTP request/response signatures
//! through the database matcher and check the resulting Browser/Server.
//!
//! This complements the Layer 1 test in
//! `huginn-net-http/tests/golden_tests.rs`, which only verifies that
//! `huginn-net-http` extracts the same raw fields from a PCAP. Here we
//! exercise the `huginn-net-db` HTTP matching half: given an
//! `HttpRequestObservation` / `HttpResponseObservation`, we ask
//! `HttpSignatureMatcher` to identify the browser/web server.

#![cfg(feature = "http")]
use huginn_net_db::{http, HttpDatabase, HttpSignatureMatcher, Type};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};

#[test]
fn matches_known_request_firefox() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = HttpSignatureMatcher::new(&db);

    let firefox = HttpRequestObservation {
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
        expsw: "Firefox/".to_string(),
    };

    match matcher.matching_by_http_request(&firefox) {
        Some((label, _sig, quality)) => {
            assert_eq!(label.name, "Firefox");
            assert_eq!(label.flavor.as_deref(), Some("2.x"));
            assert_eq!(label.ty, Type::Specified);
            assert!((quality - 1.0).abs() < f32::EPSILON);
        }
        None => panic!("expected a Firefox 2.x match"),
    }
}

#[test]
fn matches_known_response_apache() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = HttpSignatureMatcher::new(&db);

    let apache = HttpResponseObservation {
        version: http::Version::V11,
        horder: vec![
            http::Header::new("Date"),
            http::Header::new("Server"),
            http::Header::new("Last-Modified").optional(),
            http::Header::new("Accept-Ranges")
                .optional()
                .with_value("bytes"),
            http::Header::new("Content-Length").optional(),
            http::Header::new("Content-Range").optional(),
            http::Header::new("Keep-Alive").with_value("timeout"),
            http::Header::new("Connection").with_value("Keep-Alive"),
            http::Header::new("Transfer-Encoding")
                .optional()
                .with_value("chunked"),
            http::Header::new("Content-Type"),
        ],
        habsent: vec![],
        expsw: "Apache".to_string(),
    };

    match matcher.matching_by_http_response(&apache) {
        Some((label, _sig, quality)) => {
            assert_eq!(label.name, "Apache");
            assert_eq!(label.flavor.as_deref(), Some("2.x"));
            assert_eq!(label.ty, Type::Specified);
            assert!((quality - 1.0).abs() < f32::EPSILON);
        }
        None => panic!("expected an Apache 2.x match"),
    }
}

#[test]
fn unknown_request_signature_does_not_match() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = HttpSignatureMatcher::new(&db);

    // V30 (HTTP/3) has no entry in p0f.fp's `[http:request]` section, so
    // the version-keyed index returns no candidates and we get a clean
    // `None`.
    let unknown = HttpRequestObservation {
        version: http::Version::V30,
        horder: vec![http::Header::new("Totally-Made-Up-Header")],
        habsent: vec![],
        expsw: "DefinitelyNotARealBrowser/0.0".to_string(),
    };

    let result = matcher.matching_by_http_request(&unknown);
    assert!(
        result.is_none(),
        "expected no match for synthetic signature, got {:?}",
        result.map(|(label, _, q)| (label.name.clone(), q))
    );
}

#[test]
fn ua_lookup_returns_known_family() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = HttpSignatureMatcher::new(&db);

    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
              (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    if let Some((substr, _family)) = matcher.matching_by_user_agent(ua.to_string()) {
        assert!(ua.contains(substr), "matched substring should appear in UA");
    }
}
