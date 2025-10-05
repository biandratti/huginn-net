use huginn_net_db::http;
use huginn_net_http::http1_parser::{Http1Config, Http1ParseError, Http1Parser};

fn unwrap_parser_result<T>(result: Result<Option<T>, Http1ParseError>) -> T {
    match result {
        Ok(Some(value)) => value,
        Ok(None) => {
            panic!("Parser returned None when Some was expected")
        }
        Err(e) => {
            panic!("Parser failed with error: {e}")
        }
    }
}

fn assert_parser_none<T>(result: Result<Option<T>, Http1ParseError>) {
    match result {
        Ok(None) => {}
        Ok(Some(_)) => panic!("Expected None but got Some"),
        Err(e) => panic!("Expected None but got error: {e}"),
    }
}

#[test]
fn test_parse_simple_request() {
    let parser = Http1Parser::new();
    let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

    let request = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(request.method, "GET");
    assert_eq!(request.uri, "/path");
    assert_eq!(request.version, http::Version::V11);
    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.host, Some("example.com".to_string()));
    assert_eq!(request.user_agent, Some("test".to_string()));
}

#[test]
fn test_parse_request_with_cookies() {
    let parser = Http1Parser::new();
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: name1=value1; name2=value2\r\n\r\n";

    let request = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(request.cookies.len(), 2);
    assert_eq!(request.cookies[0].name, "name1");
    assert_eq!(request.cookies[0].value, Some("value1".to_string()));
    assert_eq!(request.cookies[1].name, "name2");
    assert_eq!(request.cookies[1].value, Some("value2".to_string()));
}

#[test]
fn test_parse_request_with_referer() {
    let parser = Http1Parser::new();
    let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nReferer: https://google.com/search\r\nUser-Agent: test-browser\r\n\r\n";

    let request = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(request.method, "GET");
    assert_eq!(request.uri, "/page");
    assert_eq!(request.host, Some("example.com".to_string()));
    assert_eq!(
        request.referer,
        Some("https://google.com/search".to_string())
    );
    assert_eq!(request.user_agent, Some("test-browser".to_string()));
}

#[test]
fn test_parse_request_without_referer() {
    let parser = Http1Parser::new();
    let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-browser\r\n\r\n";

    let request = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(request.method, "GET");
    assert_eq!(request.uri, "/page");
    assert_eq!(request.host, Some("example.com".to_string()));
    assert_eq!(request.referer, None);
    assert_eq!(request.user_agent, Some("test-browser".to_string()));
}

#[test]
fn test_cookie_and_referer_excluded_from_headers_list() {
    let parser = Http1Parser::new();
    let data = b"GET /page HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\nReferer: https://google.com\r\nUser-Agent: test-browser\r\nAccept: text/html\r\n\r\n";

    let request = unwrap_parser_result(parser.parse_request(data));

    assert_eq!(request.cookies.len(), 1);
    assert_eq!(request.cookies[0].name, "session");
    assert_eq!(request.cookies[0].value, Some("abc123".to_string()));
    assert_eq!(request.referer, Some("https://google.com".to_string()));

    let header_names: Vec<String> = request
        .headers
        .iter()
        .map(|h| h.name.to_lowercase())
        .collect();
    assert!(
        !header_names.contains(&"cookie".to_string()),
        "Cookie header should not be in headers list"
    );
    assert!(
        !header_names.contains(&"referer".to_string()),
        "Referer header should not be in headers list"
    );

    assert!(header_names.contains(&"host".to_string()));
    assert!(header_names.contains(&"user-agent".to_string()));
    assert!(header_names.contains(&"accept".to_string()));

    assert_eq!(request.headers.len(), 3);
}

#[test]
fn test_parse_response() {
    let parser = Http1Parser::new();
    let data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";

    let response = unwrap_parser_result(parser.parse_response(data));
    assert_eq!(response.version, http::Version::V11);
    assert_eq!(response.status_code, 200);
    assert_eq!(response.reason_phrase, "OK");
    assert_eq!(response.server, Some("nginx".to_string()));
    assert_eq!(response.content_type, Some("text/html".to_string()));
}

#[test]
fn test_incomplete_request() {
    let parser = Http1Parser::new();
    let data = b"GET /path HTTP/1.1\r\nHost: example.com";

    assert_parser_none(parser.parse_request(data));
}

#[test]
fn test_malformed_request_line() {
    let parser = Http1Parser::new();
    let data = b"INVALID REQUEST LINE\r\n\r\n";

    let result = parser.parse_request(data);
    assert!(result.is_err());
}

#[test]
fn test_header_order_preservation() {
    let parser = Http1Parser::new();
    let data = b"GET / HTTP/1.1\r\nZ-Header: first\r\nA-Header: second\r\nM-Header: third\r\n\r\n";

    let result = unwrap_parser_result(parser.parse_request(data));

    assert_eq!(result.headers[0].name, "Z-Header");
    assert_eq!(result.headers[0].position, 0);
    assert_eq!(result.headers[1].name, "A-Header");
    assert_eq!(result.headers[1].position, 1);
    assert_eq!(result.headers[2].name, "M-Header");
    assert_eq!(result.headers[2].position, 2);
}

#[test]
fn test_case_variations_detection() {
    let parser = Http1Parser::new();
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nHOST: example2.com\r\n\r\n";

    let result = unwrap_parser_result(parser.parse_request(data));

    assert!(result.parsing_metadata.case_variations.contains_key("host"));
    assert!(result
        .parsing_metadata
        .duplicate_headers
        .contains(&"host".to_string()));
}

// ========== SECURITY TESTS ==========

#[test]
fn test_extremely_long_request_line() {
    let parser = Http1Parser::new();

    // Create request line longer than max_request_line_length (8192)
    let long_path = "a".repeat(10000);
    let request_line = format!("GET /{long_path} HTTP/1.1");
    let data = format!("{request_line}\r\nHost: example.com\r\n\r\n");

    let result = parser.parse_request(data.as_bytes());
    assert!(result.is_err());

    if let Err(Http1ParseError::InvalidRequestLine(msg)) = result {
        assert!(msg.contains("too long"));
    } else {
        panic!("Expected InvalidRequestLine error");
    }
}

#[test]
fn test_extremely_long_header() {
    let parser = Http1Parser::new();

    // Create header longer than max_header_length (8192)
    let long_value = "x".repeat(10000);
    let data = format!("GET / HTTP/1.1\r\nLong-Header: {long_value}\r\n\r\n");

    let result = parser.parse_request(data.as_bytes());
    assert!(result.is_err());

    if let Err(Http1ParseError::HeaderTooLong(len)) = result {
        assert!(len > 8192);
    } else {
        panic!("Expected HeaderTooLong error");
    }
}

#[test]
fn test_too_many_headers() {
    let parser = Http1Parser::new();

    // Create more than max_headers (100)
    let mut data = String::from("GET / HTTP/1.1\r\n");
    for i in 0..150 {
        data.push_str(&format!("Header-{i}: value{i}\r\n"));
    }
    data.push_str("\r\n");

    let result = parser.parse_request(data.as_bytes());
    assert!(result.is_err());

    if let Err(Http1ParseError::TooManyHeaders(count)) = result {
        assert_eq!(count, 150);
    } else {
        panic!("Expected TooManyHeaders error");
    }
}

#[test]
fn test_invalid_utf8_handling() {
    let parser = Http1Parser::new();

    // Create data with invalid UTF-8 sequences
    let mut data = Vec::from("GET / HTTP/1.1\r\nHost: ");
    data.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // Invalid UTF-8
    data.extend_from_slice(b"\r\n\r\n");

    let result = parser.parse_request(&data);
    assert!(result.is_err());

    if let Err(Http1ParseError::InvalidUtf8) = result {
        // Expected
    } else {
        panic!("Expected InvalidUtf8 error");
    }
}

// ========== EDGE CASES ==========

#[test]
fn test_empty_data() {
    let parser = Http1Parser::new();

    assert_parser_none(parser.parse_request(b""));
    assert_parser_none(parser.parse_response(b""));
}

#[test]
fn test_only_request_line() {
    let parser = Http1Parser::new();

    // No headers, no empty line
    let data = b"GET / HTTP/1.1";
    assert_parser_none(parser.parse_request(data));

    // With CRLF but no empty line
    let data = b"GET / HTTP/1.1\r\n";
    assert_parser_none(parser.parse_request(data));
}

#[test]
fn test_different_line_endings() {
    let parser = Http1Parser::new();

    // Test with LF only (Unix style)
    let data_lf = b"GET / HTTP/1.1\nHost: example.com\n\n";
    let result_lf = unwrap_parser_result(parser.parse_request(data_lf));
    assert_eq!(result_lf.method, "GET");

    // Test with CRLF (Windows/HTTP standard)
    let data_crlf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result_crlf = unwrap_parser_result(parser.parse_request(data_crlf));
    assert_eq!(result_crlf.method, "GET");
}

#[test]
fn test_malformed_headers() {
    let parser = Http1Parser::new();

    // Header without colon (non-strict mode)
    let data = b"GET / HTTP/1.1\r\nMalformed Header Without Colon\r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert!(result.parsing_metadata.has_malformed_headers);

    // Header with empty name
    let data = b"GET / HTTP/1.1\r\n: empty-name\r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert!(result.parsing_metadata.has_malformed_headers);
}

#[test]
fn test_strict_parsing_mode() {
    let config = Http1Config {
        strict_parsing: true,
        ..Default::default()
    };
    let parser = Http1Parser::with_config(config);

    // Malformed header should fail in strict mode
    let data = b"GET / HTTP/1.1\r\nMalformed Header Without Colon\r\n\r\n";
    let result = parser.parse_request(data);
    assert!(result.is_err());

    if let Err(Http1ParseError::MalformedHeader(header)) = result {
        assert_eq!(header, "Malformed Header Without Colon");
    } else {
        panic!("Expected MalformedHeader error");
    }
}

#[test]
fn test_invalid_methods() {
    let parser = Http1Parser::new();

    let invalid_methods = ["INVALID", "123", "", "G E T", "get"];

    for method in invalid_methods {
        let data = format!("{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let result = parser.parse_request(data.as_bytes());
        assert!(result.is_err(), "Method '{method}' should be invalid");
    }
}

#[test]
fn test_valid_extended_methods() {
    let parser = Http1Parser::new();

    let valid_methods = [
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    ];

    for method in valid_methods {
        let data = format!("{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let result = unwrap_parser_result(parser.parse_request(data.as_bytes()));
        assert_eq!(result.method, method);
    }
}

#[test]
fn test_invalid_http_versions() {
    let parser = Http1Parser::new();

    let invalid_versions = ["HTTP/2.0", "HTTP/0.9", "HTTP/1.2", "HTTP/1", "HTTP", "1.1"];

    for version in invalid_versions {
        let data = format!("GET / {version}\r\nHost: example.com\r\n\r\n");
        let result = parser.parse_request(data.as_bytes());
        assert!(result.is_err(), "Version '{version}' should be invalid");
    }
}

#[test]
fn test_invalid_status_codes() {
    let parser = Http1Parser::new();

    let invalid_codes = ["abc", "999999", "", "-1", "1.5"];

    for code in invalid_codes {
        let data = format!("HTTP/1.1 {code} OK\r\nServer: test\r\n\r\n");
        let result = parser.parse_response(data.as_bytes());
        assert!(result.is_err(), "Status code '{code}' should be invalid");
    }
}

#[test]
fn test_edge_case_status_lines() {
    let parser = Http1Parser::new();

    // Status line without reason phrase
    let data = b"HTTP/1.1 404\r\nServer: test\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_response(data));
    assert_eq!(result.status_code, 404);
    assert_eq!(result.reason_phrase, "");

    // Status line with spaces in reason phrase
    let data = b"HTTP/1.1 404 Not Found Here\r\nServer: test\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_response(data));
    assert_eq!(result.status_code, 404);
    assert_eq!(result.reason_phrase, "Not Found Here");
}

#[test]
fn test_cookie_parsing_edge_cases() {
    let parser = Http1Parser::new();

    let cookie_test_cases = vec![
        ("", 0),                               // Empty cookie header
        ("name=value", 1),                     // Simple cookie
        ("name=", 1),                          // Empty value
        ("name", 1),                           // No value
        ("name=value; other=test", 2),         // Multiple cookies
        ("  name  =  value  ; other=test", 2), // Whitespace handling
        ("name=value;", 1),                    // Trailing semicolon
        (";name=value", 1),                    // Leading semicolon
        ("name=value;;other=test", 2),         // Double semicolon
        ("name=value; ; other=test", 2),       // Empty cookie between
    ];

    for (cookie_str, expected_count) in cookie_test_cases {
        let data = format!("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: {cookie_str}\r\n\r\n");
        let result = unwrap_parser_result(parser.parse_request(data.as_bytes()));
        assert_eq!(
            result.cookies.len(),
            expected_count,
            "Failed for cookie: '{cookie_str}'"
        );
    }
}

#[test]
fn test_parse_cookies_direct() {
    let parser = Http1Parser::new();

    let test_cases = vec![
        ("", 0),
        ("name=value", 1),
        ("name=", 1),
        ("name", 1),
        ("name=value; other=test", 2),
        ("  name  =  value  ", 1),
        ("name=value;", 1),
        (";name=value", 1),
        ("name=value;;other=test", 2),
    ];

    for (cookie_str, expected_count) in test_cases {
        let cookies = parser.parse_cookies(cookie_str);
        assert_eq!(
            cookies.len(),
            expected_count,
            "Failed for case: '{cookie_str}'"
        );

        match cookie_str {
            "" => {
                assert!(cookies.is_empty());
            }
            "name=value" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
            }
            "name=" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("".to_string()));
                assert_eq!(cookies[0].position, 0);
            }
            "name" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, None);
                assert_eq!(cookies[0].position, 0);
            }
            "name=value; other=test" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
                assert_eq!(cookies[1].name, "other");
                assert_eq!(cookies[1].value, Some("test".to_string()));
                assert_eq!(cookies[1].position, 1);
            }
            "  name  =  value  " => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
            }
            "name=value;" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
            }
            ";name=value" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
            }
            "name=value;;other=test" => {
                assert_eq!(cookies[0].name, "name");
                assert_eq!(cookies[0].value, Some("value".to_string()));
                assert_eq!(cookies[0].position, 0);
                assert_eq!(cookies[1].name, "other");
                assert_eq!(cookies[1].value, Some("test".to_string()));
                assert_eq!(cookies[1].position, 1);
            }
            _ => {}
        }
    }
}

#[test]
fn test_parse_cookies_rfc6265_compliance() {
    let parser = Http1Parser::new();

    // RFC 6265 examples - HTTP/1.x single cookie header format
    let rfc_cases = vec![
        (
            "session_id=abc123; user_id=456; theme=dark; lang=en",
            vec![
                ("session_id", Some("abc123")),
                ("user_id", Some("456")),
                ("theme", Some("dark")),
                ("lang", Some("en")),
            ],
        ),
        (
            "token=xyz; secure; httponly",
            vec![("token", Some("xyz")), ("secure", None), ("httponly", None)],
        ),
    ];

    for (cookie_str, expected_cookies) in rfc_cases {
        let cookies = parser.parse_cookies(cookie_str);
        assert_eq!(
            cookies.len(),
            expected_cookies.len(),
            "Failed for RFC case: '{cookie_str}'"
        );

        for (i, (expected_name, expected_value)) in expected_cookies.iter().enumerate() {
            assert_eq!(cookies[i].name, *expected_name);
            assert_eq!(cookies[i].value, expected_value.map(|v| v.to_string()));
            assert_eq!(cookies[i].position, i);
        }
    }
}

#[test]
fn test_header_value_edge_cases() {
    let parser = Http1Parser::new();

    // Header with no value
    let data = b"GET / HTTP/1.1\r\nEmpty-Header:\r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    let empty_header = result.headers.iter().find(|h| h.name == "Empty-Header");
    assert!(empty_header.is_some(), "Empty-Header should be present");
    assert_eq!(
        empty_header.as_ref().and_then(|h| h.value.as_deref()),
        Some("")
    );

    // Header with only spaces as value
    let data = b"GET / HTTP/1.1\r\nSpaces-Header:   \r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    let spaces_header = result.headers.iter().find(|h| h.name == "Spaces-Header");
    assert!(spaces_header.is_some(), "Spaces-Header should be present");
    assert_eq!(
        spaces_header.as_ref().and_then(|h| h.value.as_deref()),
        Some("")
    );

    // Header with leading/trailing spaces
    let data = b"GET / HTTP/1.1\r\nTrim-Header:  value with spaces  \r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    let trim_header = result.headers.iter().find(|h| h.name == "Trim-Header");
    assert!(trim_header.is_some(), "Trim-Header should be present");
    assert_eq!(
        trim_header.as_ref().and_then(|h| h.value.as_deref()),
        Some("value with spaces")
    );
}

#[test]
fn test_request_line_edge_cases() {
    let parser = Http1Parser::new();

    // Too few parts
    let data = b"GET HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = parser.parse_request(data);
    assert!(result.is_err());

    // Too many parts (extra spaces)
    let data = b"GET / HTTP/1.1 extra\r\nHost: example.com\r\n\r\n";
    let result = parser.parse_request(data);
    assert!(result.is_err());

    // Empty method
    let data = b" / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = parser.parse_request(data);
    assert!(result.is_err());
}

#[test]
fn test_content_length_parsing() {
    let parser = Http1Parser::new();

    // Valid content length
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(result.content_length, Some(42));

    // Invalid content length (non-numeric)
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(result.content_length, None);

    // Multiple content length headers (should use first valid one)
    let data =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\nContent-Length: 24\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(result.content_length, Some(42));
}

#[test]
fn test_can_parse_detection() {
    use huginn_net_http::http_process::HttpProcessors;
    let processors = HttpProcessors::new();

    // Valid HTTP/1.x requests - should be parseable
    assert!(processors
        .parse_request(b"GET / HTTP/1.1\r\n\r\n")
        .is_some());
    assert!(processors
        .parse_request(b"POST /api HTTP/1.0\r\n\r\n")
        .is_some());
    assert!(processors
        .parse_request(b"PUT /data HTTP/1.1\r\n\r\n")
        .is_some());

    // Valid HTTP/1.x responses - should be parseable
    assert!(processors
        .parse_response(b"HTTP/1.1 200 OK\r\n\r\n")
        .is_some());
    assert!(processors
        .parse_response(b"HTTP/1.0 404 Not Found\r\n\r\n")
        .is_some());

    // Invalid data - should not be parseable
    assert!(processors.parse_request(b"").is_none());
    assert!(processors.parse_request(b"short").is_none());
    assert!(processors.parse_request(b"INVALID DATA HERE").is_none());
    assert!(processors.parse_request(b"PRI * HTTP/2.0\r\n").is_none()); // HTTP/2 preface
}

#[test]
fn test_error_display_formatting() {
    // Test that all error types format correctly
    let errors = vec![
        Http1ParseError::InvalidRequestLine("test".to_string()),
        Http1ParseError::InvalidStatusLine("test".to_string()),
        Http1ParseError::InvalidVersion("test".to_string()),
        Http1ParseError::InvalidMethod("test".to_string()),
        Http1ParseError::InvalidStatusCode("test".to_string()),
        Http1ParseError::HeaderTooLong(12345),
        Http1ParseError::TooManyHeaders(999),
        Http1ParseError::MalformedHeader("test".to_string()),
        Http1ParseError::IncompleteData,
        Http1ParseError::InvalidUtf8,
    ];

    for error in errors {
        let formatted = format!("{error}");
        assert!(!formatted.is_empty());
        assert!(!formatted.contains("Debug")); // Should be Display, not Debug
    }
}

#[test]
fn test_config_limits() {
    // Test with very restrictive config
    let config = Http1Config {
        max_headers: 2,
        max_request_line_length: 50,
        max_header_length: 30,
        preserve_header_order: true,
        parse_cookies: false,
        strict_parsing: true,
    };
    let parser = Http1Parser::with_config(config);

    // Should work within limits
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = unwrap_parser_result(parser.parse_request(data));
    assert_eq!(result.method, "GET");
    assert!(result.cookies.is_empty()); // Cookie parsing disabled

    // Should fail when exceeding header count limit
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";
    let result = parser.parse_request(data);
    assert!(result.is_err());
}

#[test]
fn test_performance_metadata() {
    let parser = Http1Parser::new();
    let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

    let result = unwrap_parser_result(parser.parse_request(data));

    // Verify metadata is populated
    assert!(result.parsing_metadata.parsing_time_ns > 0);
    assert_eq!(result.parsing_metadata.header_count, 2);
    assert_eq!(
        result.parsing_metadata.request_line_length,
        "GET /path HTTP/1.1".len()
    );
    assert!(result.parsing_metadata.total_headers_length > 0);
    assert!(!result.parsing_metadata.has_malformed_headers);
}
