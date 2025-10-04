use crate::http;
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_db::db_matching_trait::FingerprintDb;
use huginn_net_db::{Database, Label};

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_http_request(
        &self,
        signature: &ObservableHttpRequest,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database
            .http_request
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_http_response(
        &self,
        signature: &ObservableHttpResponse,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database
            .http_response
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_user_agent(
        &self,
        user_agent: String,
    ) -> Option<(&'a String, &'a Option<String>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua) {
                return Some((ua, ua_family));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Version as HttpVersion;
    use huginn_net_db::Type;
    #[test]
    fn matching_firefox2_by_http_request() {
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to create default database: {e}");
            }
        };

        let firefox_signature = ObservableHttpRequest {
            matching: huginn_net_db::observable_signals::HttpRequestObservation {
                version: HttpVersion::V10,
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
            },
            lang: None,
            user_agent: None,
            headers: vec![],
            cookies: vec![],
            referer: None,
            method: Some("GET".to_string()),
            uri: Some("/".to_string()),
        };

        let matcher = SignatureMatcher::new(&db);

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
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to create default database: {e}");
            }
        };

        let apache_signature = ObservableHttpResponse {
            matching: huginn_net_db::observable_signals::HttpResponseObservation {
                version: HttpVersion::V11,
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
            },
            headers: vec![],
            status_code: Some(200),
        };

        let matcher = SignatureMatcher::new(&db);

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
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to create default database: {e}");
            }
        };

        let android_chrome_signature = ObservableHttpRequest {
            matching: huginn_net_db::observable_signals::HttpRequestObservation {
                version: HttpVersion::V11, // HTTP/1.1
                horder: vec![
                    http::Header::new("Host"),
                    http::Header::new("Connection").with_value("keep-alive"),
                    http::Header::new("User-Agent"),
                    http::Header::new("Accept").with_value("image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"),
                    http::Header::new("Referer").optional(), // ?Referer
                    http::Header::new("Accept-Encoding").with_value("gzip, deflate"),
                    http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
                ],
                habsent: vec![
                    http::Header::new("Accept-Charset"),
                    http::Header::new("Keep-Alive"),
                ],
                expsw: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36".to_string(),
            },
            lang: Some("English".to_string()),
            user_agent: Some("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36".to_string()),
            headers: vec![],
            cookies: vec![],
            referer: None,
            method: Some("GET".to_string()),
            uri: Some("/".to_string()),
        };

        let matcher = SignatureMatcher::new(&db);

        match matcher.matching_by_http_request(&android_chrome_signature) {
            Some((label, _matched_db_sig, quality)) => {
                assert_eq!(label.name, "Chrome");
                assert_eq!(label.class, None);
                assert_eq!(label.flavor, Some("11 or newer".to_string()));
                assert_eq!(label.ty, Type::Specified);
                assert_eq!(quality, 0.7);
            }
            None => {
                panic!("No HTTP match found for Android Chrome signature");
            }
        }
    }
}
