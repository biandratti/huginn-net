#![cfg(feature = "http")]
use huginn_net_db::{http, HttpDatabase, HttpSignatureMatcher, Type};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};

#[test]
fn matching_firefox2_by_http_request() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to create default database: {e}"),
    };

    let firefox_signature = HttpRequestObservation {
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

    let matcher = HttpSignatureMatcher::new(&db);

    if let Some((label, _matched_db_sig, quality)) =
        matcher.matching_by_http_request(&firefox_signature)
    {
        assert_eq!(label.name, "Firefox");
        assert_eq!(label.class, None);
        assert_eq!(label.flavor, Some("2.x".to_string()));
        assert_eq!(label.ty, Type::Specified);
        assert_eq!(quality, 1.0);
    } else {
        panic!("No match found for Firefox 2.x HTTP signature");
    }
}

#[test]
fn matching_apache_by_http_response() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to create default database: {e}"),
    };

    let apache_signature = HttpResponseObservation {
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

    let matcher = HttpSignatureMatcher::new(&db);

    if let Some((label, _matched_db_sig, quality)) =
        matcher.matching_by_http_response(&apache_signature)
    {
        assert_eq!(label.name, "Apache");
        assert_eq!(label.class, None);
        assert_eq!(label.flavor, Some("2.x".to_string()));
        assert_eq!(label.ty, Type::Specified);
        assert_eq!(quality, 1.0);
    } else {
        panic!("No match found for Apache 2.x HTTP response signature");
    }
}

#[test]
fn matching_android_chrome_by_http_request() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to create default database: {e}"),
    };

    let android_chrome_signature = HttpRequestObservation {
        version: http::Version::V11,
        horder: vec![
            http::Header::new("Host"),
            http::Header::new("Connection").with_value("keep-alive"),
            http::Header::new("User-Agent"),
            http::Header::new("Accept").with_value(
                "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            ),
            http::Header::new("Referer").optional(),
            http::Header::new("Accept-Encoding").with_value("gzip, deflate"),
            http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
        ],
        habsent: vec![http::Header::new("Accept-Charset"), http::Header::new("Keep-Alive")],
        expsw: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36".to_string(),
    };

    let matcher = HttpSignatureMatcher::new(&db);

    match matcher.matching_by_http_request(&android_chrome_signature) {
        Some((label, _matched_db_sig, quality)) => {
            assert_eq!(label.name, "Chrome");
            assert_eq!(label.class, None);
            assert_eq!(label.flavor, Some("11 or newer".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 0.7);
        }
        None => panic!("No HTTP match found for Android Chrome signature"),
    }
}
