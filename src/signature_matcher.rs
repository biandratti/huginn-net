use crate::db::{Database, Label};
use crate::db_matching_trait::FingerprintDb;
use crate::observable_signals::ObservableTcp;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, tcp};

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a tcp::Signature, f32)> {
        self.database.tcp_request.find_best_match(signature)
    }

    pub fn matching_by_tcp_response(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a tcp::Signature, f32)> {
        self.database.tcp_response.find_best_match(signature)
    }

    pub fn matching_by_mtu(&self, mtu: &u16) -> Option<(&'a String, &'a u16)> {
        for (link, db_mtus) in &self.database.mtu {
            for db_mtu in db_mtus {
                if mtu == db_mtu {
                    return Some((link, db_mtu));
                }
            }
        }
        None
    }

    pub fn matching_by_http_request(
        &self,
        signature: &ObservableHttpRequest,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database.http_request.find_best_match(signature)
    }

    pub fn matching_by_http_response(
        &self,
        signature: &ObservableHttpResponse,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database.http_response.find_best_match(signature)
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
    use crate::db::Type;
    use crate::http::Version as HttpVersion;
    use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
    use crate::Database;

    #[test]
    fn matching_linux_by_tcp_request() {
        let db = Database::load_default().expect("Failed to create default database");

        //sig: 4:58+6:0:1452:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
        let linux_signature = ObservableTcp {
            version: IpVersion::V4,
            ittl: Ttl::Distance(58, 6),
            olen: 0,
            mss: Some(1452),
            wsize: WindowSize::Mss(44),
            wscale: Some(7),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
        };

        let matcher = SignatureMatcher::new(&db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&linux_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("2.2.x-3.x".to_string()));
            assert_eq!(label.ty, Type::Generic);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }

    #[test]
    fn matching_android_by_tcp_request() {
        let db = Database::load_default().expect("Failed to create default database");

        //sig: "4:64+0:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
        let android_signature = ObservableTcp {
            version: IpVersion::V4,
            ittl: Ttl::Value(64),
            olen: 0,
            mss: Some(1460),
            wsize: WindowSize::Value(65535),
            wscale: Some(8),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
        };

        //sig: "4:57+7:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
        let android_signature_with_distance = ObservableTcp {
            version: IpVersion::V4,
            ittl: Ttl::Distance(57, 7),
            olen: 0,
            mss: Some(1460),
            wsize: WindowSize::Value(65535),
            wscale: Some(8),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
        };

        let matcher = SignatureMatcher::new(&db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&android_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("Android".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&android_signature_with_distance)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("Android".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }

    #[test]
    fn matching_firefox2_by_http_request() {
        let db = Database::load_default().expect("Failed to create default database");

        let firefox_signature = ObservableHttpRequest {
            lang: None,
            user_agent: None,
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
        let db = Database::load_default().expect("Failed to create default database");

        let apache_signature = ObservableHttpResponse {
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
        let db = Database::load_default().expect("Failed to create default database");

        let android_chrome_signature = ObservableHttpRequest {
            lang: Some("English".to_string()),
            user_agent: Some("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36".to_string()),
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
