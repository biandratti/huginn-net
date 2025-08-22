use crate::db::Label;
use crate::error::HuginnNetError;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http, http_common, http2_parser, http_languages};
use tracing::debug;

fn convert_http2_request_to_observable(req: http2_parser::Http2Request) -> ObservableHttpRequest {
    let lang = req
        .headers_map
        .get("accept-language")
        .and_then(|accept_language| {
            http_languages::get_highest_quality_language(accept_language.clone())
        });

    let headers_in_order = convert_http2_headers_to_http_format(&req.headers, true);
    let headers_absent = build_absent_headers_from_http2(&req.headers, true);

    let user_agent = req.headers_map.get("user-agent").cloned();

    ObservableHttpRequest {
        lang,
        user_agent: user_agent.clone(),
        version: req.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(user_agent),
        raw_headers: req.headers_map,
        method: Some(req.method),
        uri: Some(req.path),
    }
}

fn convert_http2_response_to_observable(
    res: http2_parser::Http2Response,
) -> ObservableHttpResponse {
    let headers_in_order = convert_http2_headers_to_http_format(&res.headers, false);
    let headers_absent = build_absent_headers_from_http2(&res.headers, false);

    ObservableHttpResponse {
        version: res.version,
        horder: headers_in_order,
        habsent: headers_absent,
        expsw: extract_traffic_classification(res.server),
        raw_headers: res.headers_map,
        status_code: Some(res.status),
    }
}

fn convert_http2_headers_to_http_format(
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

        let header_name_lower = header.name.to_lowercase();

        if optional_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name).optional());
        } else if skip_value_list.contains(&header_name_lower.as_str()) {
            headers_in_order.push(http::Header::new(&header.name));
        } else {
            headers_in_order.push(http::Header::new(&header.name).with_optional_value(value));
        }
    }

    headers_in_order
}

fn build_absent_headers_from_http2(
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

pub fn parse_http2_request(data: &[u8]) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
    let parser = http2_parser::Http2Parser::new();

    match parser.parse_request(data) {
        Ok(Some(req)) => {
            let observable = convert_http2_request_to_observable(req);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/2 request data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/2 request: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/2 request: {e}"
            )))
        }
    }
}

pub fn parse_http2_response(data: &[u8]) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
    let parser = http2_parser::Http2Parser::new();

    match parser.parse_response(data) {
        Ok(Some(res)) => {
            let observable = convert_http2_response_to_observable(res);
            Ok(Some(observable))
        }
        Ok(None) => {
            debug!("Incomplete HTTP/2 response data");
            Ok(None)
        }
        Err(e) => {
            debug!("Failed to parse HTTP/2 response: {}", e);
            Err(HuginnNetError::Parse(format!(
                "Failed to parse HTTP/2 response: {e}"
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
    fn test_http2_request_conversion() {
        // Create a mock HTTP/2 request
        let req = http2_parser::Http2Request {
            method: "GET".to_string(),
            path: "/test".to_string(),
            authority: Some("example.com".to_string()),
            scheme: Some("https".to_string()),
            version: http::Version::V20,
            headers: vec![],
            headers_map: std::collections::HashMap::new(),
            cookies: vec![],
            stream_id: 1,
            parsing_metadata: http_common::ParsingMetadata {
                header_count: 0,
                duplicate_headers: vec![],
                case_variations: std::collections::HashMap::new(),
                parsing_time_ns: 0,
                has_malformed_headers: false,
                request_line_length: 0,
                total_headers_length: 0,
            },
            frame_sequence: vec![],
            settings: http2_parser::Http2Settings::default(),
        };

        let observable = convert_http2_request_to_observable(req);

        assert_eq!(observable.version, http::Version::V20);
        assert_eq!(observable.method, Some("GET".to_string()));
        assert_eq!(observable.uri, Some("/test".to_string()));
    }

    #[test]
    fn test_http2_response_conversion() {
        let res = http2_parser::Http2Response {
            status: 200,
            version: http::Version::V20,
            headers: vec![],
            headers_map: std::collections::HashMap::new(),
            stream_id: 1,
            parsing_metadata: http_common::ParsingMetadata {
                header_count: 0,
                duplicate_headers: vec![],
                case_variations: std::collections::HashMap::new(),
                parsing_time_ns: 0,
                has_malformed_headers: false,
                request_line_length: 0,
                total_headers_length: 0,
            },
            frame_sequence: vec![],
            server: Some("nginx/1.20".to_string()),
            content_type: Some("text/html".to_string()),
        };

        let observable = convert_http2_response_to_observable(res);

        assert_eq!(observable.version, http::Version::V20);
        assert_eq!(observable.status_code, Some(200));
        assert_eq!(observable.expsw, "nginx/1.20");
    }

    #[test]
    fn test_get_diagnostic_for_http2() {
        let diagnosis = get_diagnostic(None, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
    }

    #[test]
    fn test_get_diagnostic_with_http2_user_agent() {
        let user_agent = Some("Mozilla/5.0 HTTP/2.0".to_string());
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
}
