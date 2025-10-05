use huginn_net_db::http;
use huginn_net_http::http1_process;
use huginn_net_http::http_common::HttpProcessor;
use huginn_net_http::http_common;

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
    match http1_process::Http1Processor::new().process_request(valid_request) {
        Ok(Some(request)) => {
            assert_eq!(request.lang, Some("English".to_string()));
            assert_eq!(request.user_agent, Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()));
            assert_eq!(request.matching.version, http::Version::V11);

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
            assert_eq!(request.matching.horder, expected_horder);

            let expected_habsent = vec![
                http::Header::new("Accept-Encoding"),
                http::Header::new("Accept-Charset"),
                http::Header::new("Keep-Alive"),
            ];
            assert_eq!(request.matching.habsent, expected_habsent);

            assert_eq!(request.matching.expsw, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
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

    match http1_process::Http1Processor::new().process_response(valid_response) {
        Ok(Some(response)) => {
            assert_eq!(response.matching.expsw, "Apache");
            assert_eq!(response.matching.version, http::Version::V11);

            let expected_horder = vec![
                http::Header::new("Server"),
                http::Header::new("Content-Type"),
                http::Header::new("Content-Length").optional(),
                http::Header::new("Connection").with_value("keep-alive"),
            ];
            assert_eq!(response.matching.horder, expected_horder);

            let expected_absent = vec![
                http::Header::new("Keep-Alive"),
                http::Header::new("Accept-Ranges"),
                http::Header::new("Date"),
            ];
            assert_eq!(response.matching.habsent, expected_absent);
        }
        Ok(None) => panic!("Incomplete HTTP response"),
        Err(e) => panic!("Failed to parse HTTP response: {e}"),
    }
}

#[test]
fn test_get_diagnostic_for_empty_sw() {
    let diagnosis: http::HttpDiagnosis = http_common::get_diagnostic(None, None, None);
    assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
}
