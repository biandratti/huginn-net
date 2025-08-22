use crate::db::Label;
use crate::error::HuginnNetError;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, http1_parser, http_common, http_languages};
use tracing::debug;

fn convert_http1_request_to_observable(req: http1_parser::Http1Request) -> ObservableHttpRequest {
    let lang = req
        .accept_language
        .and_then(http_languages::get_highest_quality_language);

    let headers_in_order = convert_headers_to_http_format(&req.headers, true);
    let headers_absent = build_absent_headers_from_new_parser(&req.headers, true);

    ObservableHttpRequest {
        lang,
        user_agent: req.user_agent.clone(),
        version: req.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(req.user_agent),
        raw_headers: req.headers_map,
        method: Some(req.method),
        uri: Some(req.uri),
    }
}

fn convert_http1_response_to_observable(
    res: http1_parser::Http1Response,
) -> ObservableHttpResponse {
    let headers_in_order = convert_headers_to_http_format(&res.headers, false);
    let headers_absent = build_absent_headers_from_new_parser(&res.headers, false);

    ObservableHttpResponse {
        version: res.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(res.server),
        raw_headers: res.headers_map,
        status_code: Some(res.status_code),
    }
}

fn convert_headers_to_http_format(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<http::Header> {
    let mut headers_in_order: Vec<http::Header> = Vec::new();
    let optional_list = if is_request {
        http::request_optional_headers()
    } else {
        http::response_optional_headers()
    };
    let skip_value_list = if is_request {
        http::request_skip_value_headers()
    } else {
        http::response_skip_value_headers()
    };

    for header in headers {
        let value: Option<&str> = Some(&header.value);

        if optional_list.contains(&header.name.as_str()) {
            headers_in_order.push(http::Header::new(&header.name).optional());
        } else if skip_value_list.contains(&header.name.as_str()) {
            headers_in_order.push(http::Header::new(&header.name));
        } else {
            headers_in_order.push(http::Header::new(&header.name).with_optional_value(value));
        }
    }

    headers_in_order
}

fn build_absent_headers_from_new_parser(
    headers: &[http_common::HttpHeader],
    is_request: bool,
) -> Vec<http::Header> {
    let mut headers_absent: Vec<http::Header> = Vec::new();
    let common_list: Vec<&str> = if is_request {
        http::request_common_headers()
    } else {
        http::response_common_headers()
    };
    let current_headers: Vec<String> = headers.iter().map(|h| h.name.to_lowercase()).collect();

    for header in &common_list {
        if !current_headers.contains(&header.to_lowercase()) {
            headers_absent.push(http::Header::new(header));
        }
    }
    headers_absent
}

pub fn parse_http1_request(data: &[u8]) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
    let parser = http1_parser::Http1Parser::new();

    match parser.parse_request(data) {
        Ok(Some(req)) => {
            let observable = convert_http1_request_to_observable(req);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/1.x request data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/1.x request: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/1.x request: {e}"
            )))
        }
    }
}

pub fn parse_http1_response(data: &[u8]) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
    let parser = http1_parser::Http1Parser::new();

    match parser.parse_response(data) {
        Ok(Some(res)) => {
            let observable = convert_http1_response_to_observable(res);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/1.x response data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/1.x response: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/1.x response: {e}"
            )))
        }
    }
}

fn extract_traffic_classification(value: Option<String>) -> String {
    value.unwrap_or_else(|| "???".to_string())
}

pub fn get_diagnostic(
    user_agent: Option<String>,
    ua_matcher: Option<(&String, &Option<String>)>,
    signature_os_matcher: Option<&Label>,
) -> http::HttpDiagnosis {
    match user_agent {
        None => http::HttpDiagnosis::Anonymous,
        Some(_ua) => match (ua_matcher, signature_os_matcher) {
            (Some((ua_name_db, _ua_flavor_db)), Some(signature_label_db)) => {
                if ua_name_db.eq_ignore_ascii_case(&signature_label_db.name) {
                    http::HttpDiagnosis::Generic
                } else {
                    http::HttpDiagnosis::Dishonest
                }
            }
            _ => http::HttpDiagnosis::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn test_parse_http1_request() {
        let valid_request = b"GET / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n\
        Accept-Language: en-US,en;q=0.9,es;q=0.8\r\n\
        Cache-Control: max-age=0\r\n\
        Connection: keep-alive\r\n\
        If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT\r\n\
        If-None-Match: \"3147526947\"\r\n\
        Upgrade-Insecure-Requests: 1\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
        \r\n";
        match parse_http1_request(valid_request) {
            Ok(Some(request)) => {
                assert_eq!(request.lang, Some("English".to_string()));
                assert_eq!(request.user_agent, Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()));
                assert_eq!(request.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Host"),
                    http::Header::new("Accept").with_value("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                    http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
                    http::Header::new("Cache-Control").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                    http::Header::new("If-Modified-Since").optional(),
                    http::Header::new("If-None-Match").optional(),
                    http::Header::new("Upgrade-Insecure-Requests").with_value("1"),
                    http::Header::new("User-Agent"),
                ];
                assert_eq!(request.horder, expected_horder);

                let expected_habsent = vec![
                    http::Header::new("Accept-Encoding"),
                    http::Header::new("Accept-Charset"),
                    http::Header::new("Keep-Alive"),
                ];
                assert_eq!(request.habsent, expected_habsent);

                assert_eq!(request.expsw, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
            }
            Ok(None) => panic!("Incomplete HTTP request"),
            Err(e) => panic!("Failed to parse HTTP request: {e}"),
        }
    }

    #[test]
    fn test_parse_http1_response() {
        let valid_response = b"HTTP/1.1 200 OK\r\n\
        Server: Apache\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        Content-Length: 112\r\n\
        Connection: keep-alive\r\n\
        \r\n\
        <html><body><h1>It works!</h1></body></html>";

        match parse_http1_response(valid_response) {
            Ok(Some(response)) => {
                assert_eq!(response.expsw, "Apache");
                assert_eq!(response.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Server"),
                    http::Header::new("Content-Type"),
                    http::Header::new("Content-Length").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                ];
                assert_eq!(response.horder, expected_horder);

                let expected_absent = vec![
                    http::Header::new("Keep-Alive"),
                    http::Header::new("Accept-Ranges"),
                    http::Header::new("Date"),
                ];
                assert_eq!(response.habsent, expected_absent);
            }
            Ok(None) => panic!("Incomplete HTTP response"),
            Err(e) => panic!("Failed to parse HTTP response: {e}"),
        }
    }

    #[test]
    fn test_get_diagnostic_for_empty_sw() {
        let diagnosis: http::HttpDiagnosis = get_diagnostic(None, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
    }

    #[test]
    fn test_get_diagnostic_with_existing_signature_matcher() {
        let user_agent: Option<String> = Some("Mozilla/5.0".to_string());
        let os = "Linux".to_string();
        let browser = Some("Firefox".to_string());
        let ua_matcher: Option<(&String, &Option<String>)> = Some((&os, &browser));
        let label = db::Label {
            ty: db::Type::Specified,
            class: None,
            name: "Linux".to_string(),
            flavor: None,
        };
        let signature_os_matcher: Option<&db::Label> = Some(&label);

        let diagnosis = get_diagnostic(user_agent, ua_matcher, signature_os_matcher);
        assert_eq!(diagnosis, http::HttpDiagnosis::Generic);
    }

    #[test]
    fn test_get_diagnostic_with_dishonest_user_agent() {
        let user_agent = Some("Mozilla/5.0".to_string());
        let os = "Windows".to_string();
        let browser = Some("Firefox".to_string());
        let ua_matcher: Option<(&String, &Option<String>)> = Some((&os, &browser));
        let label = db::Label {
            ty: db::Type::Specified,
            class: None,
            name: "Linux".to_string(),
            flavor: None,
        };
        let signature_os_matcher: Option<&db::Label> = Some(&label);

        let diagnosis = get_diagnostic(user_agent, ua_matcher, signature_os_matcher);
        assert_eq!(diagnosis, http::HttpDiagnosis::Dishonest);
    }

    #[test]
    fn test_get_diagnostic_without_user_agent_and_signature_matcher() {
        let user_agent = Some("Mozilla/5.0".to_string());

        let diagnosis = get_diagnostic(user_agent, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::None);
    }
}
