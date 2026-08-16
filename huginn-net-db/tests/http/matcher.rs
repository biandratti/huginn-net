use huginn_net_db::db_matching_trait::FingerprintDb;
use huginn_net_db::{http, HttpDatabase, Type};
use huginn_net_http::matcher_api::HttpMatcher;
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

    if let Some(found) = db.http_request.find_best_match(&firefox_signature) {
        assert_eq!(found.label.name, "Firefox");
        assert_eq!(found.label.class, None);
        assert_eq!(found.label.flavor, Some("2.x".to_string()));
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
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

    if let Some(found) = db.http_response.find_best_match(&apache_signature) {
        assert_eq!(found.label.name, "Apache");
        assert_eq!(found.label.class, None);
        assert_eq!(found.label.flavor, Some("2.x".to_string()));
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
    } else {
        panic!("No match found for Apache 2.x HTTP response signature");
    }
}

#[test]
fn matching_chrome11_by_http_request() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to create default database: {e}"),
    };

    // Layout from p0f.fp `Chrome:11 or newer` (2012): sdch + Accept-Charset.
    let chrome_signature = HttpRequestObservation {
        version: http::Version::V11,
        horder: vec![
            http::Header::new("Host"),
            http::Header::new("Connection").with_value("keep-alive"),
            http::Header::new("User-Agent"),
            http::Header::new("Accept").with_value("*/*"),
            http::Header::new("Accept-Encoding").with_value("gzip,deflate,sdch"),
            http::Header::new("Accept-Language"),
            http::Header::new("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.3"),
        ],
        habsent: vec![],
        expsw: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 \
                (KHTML, like Gecko) Chrome/16.0.912.75 Safari/535.7"
            .to_string(),
    };

    if let Some(found) = db.http_request.find_best_match(&chrome_signature) {
        assert_eq!(found.label.name, "Chrome");
        assert_eq!(found.label.class, None);
        assert_eq!(found.label.flavor, Some("11 or newer".to_string()));
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
    } else {
        panic!("No match found for Chrome 11 HTTP signature");
    }
}

#[test]
fn matching_modern_curl_by_http_request() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to create default database: {e}"),
    };

    let curl = HttpRequestObservation {
        version: http::Version::V11,
        horder: vec![
            http::Header::new("Host"),
            http::Header::new("User-Agent"),
            http::Header::new("Accept").with_value("*/*"),
        ],
        habsent: vec![],
        expsw: "curl/8.5.0".to_string(),
    };

    if let Some(found) = db.http_request.find_best_match(&curl) {
        assert_eq!(found.label.name, "curl");
        assert_eq!(found.label.class, None);
        assert_eq!(found.label.flavor, None);
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
    } else {
        panic!("No match found for modern curl HTTP signature");
    }
}

/// p0f.fp's Chrome signatures date from ~2012 and require
/// `Accept-Encoding=[gzip,deflate,sdch]` plus an `Accept-Charset`; a current
/// Chrome sends neither (`sdch` was dropped around 2016). Header matching is
/// all-or-nothing in p0f, and the `[http:request]` section has no generic
/// catch-all, so a modern Chrome request is simply not covered by the
/// bundled database.
///
/// Before header matching became faithful to p0f, an error budget let this
/// request match the old Chrome signature with 4 mismatched headers, which
/// happened to yield a plausible label ("11 or newer") from a signature the
/// traffic did not actually match.
#[test]
fn modern_chrome_request_is_not_covered_by_bundled_signatures() {
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

    assert!(
        db.http_request
            .find_best_match(&android_chrome_signature)
            .is_none(),
        "no bundled signature describes this request, so it must not be labelled"
    );
}

#[test]
fn unknown_request_signature_does_not_match() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };

    let unknown = HttpRequestObservation {
        version: http::Version::V30,
        horder: vec![http::Header::new("Totally-Made-Up-Header")],
        habsent: vec![],
        expsw: "DefinitelyNotARealBrowser/0.0".to_string(),
    };
    let result = db.http_request.find_best_match(&unknown);
    assert!(
        result.is_none(),
        "expected no match for synthetic signature, got {:?}",
        result.map(|found| (found.label.name.clone(), found.quality))
    );
}

#[test]
fn ua_lookup_returns_known_family() {
    let db = match HttpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = huginn_net_db::HttpSignatureMatcher::new(&db);

    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
              (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let found = matcher
        .match_user_agent(ua)
        .unwrap_or_else(|| panic!("Windows UA should map to an OS family"));
    assert_eq!(found.family, "Windows");
}
