#![cfg(feature = "http")]
use huginn_net_db::http::headers_match;
use huginn_net_db::http::Header;

#[test]
fn test_headers_with_one_optional_header_mismatch() {
    let a = vec![
        Header::new("Date"),
        Header::new("Server"),
        Header::new("Last-Modified").optional(),
        Header::new("Accept-Ranges").optional().with_value("bytes"),
        Header::new("Content-Length").optional(),
        Header::new("Content-Range").optional(),
        Header::new("Keep-Alive").optional().with_value("timeout"),
        Header::new("Connection").with_value("Keep-Alive"),
        Header::new("Transfer-Encoding")
            .optional()
            .with_value("chunked"),
        Header::new("Content-Type"),
    ];

    let b = vec![
        Header::new("Date"),
        Header::new("Server"),
        Header::new("Last-Modified").optional(),
        Header::new("Accept-Ranges").optional().with_value("bytes"),
        Header::new("Content-Length").optional(),
        Header::new("Content-Range").optional(),
        Header::new("Keep-Alive").with_value("timeout"),
        Header::new("Connection").with_value("Keep-Alive"),
        Header::new("Transfer-Encoding")
            .optional()
            .with_value("chunked"),
        Header::new("Content-Type"),
    ];

    assert!(a[6].optional);
    assert!(!b[6].optional);
    assert_ne!(a[6], b[6]);

    let result = headers_match(&a, &b);
    assert!(
        result,
        "only the signature's optional flag is consulted, so the observation's differing flag is irrelevant"
    );
}

#[test]
fn test_headers_optional_skip_in_middle() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(result, "Optional header in middle should be skipped for perfect alignment");
}

#[test]
fn test_headers_multiple_optional_skips() {
    let observed = vec![Header::new("Host"), Header::new("Connection").with_value("keep-alive")];

    let signature = vec![
        Header::new("Host"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"),
        Header::new("Accept-Encoding").optional().with_value("gzip"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(result, "Multiple optional headers should be skipped");
}

#[test]
fn test_headers_missing_required_header_in_middle_rejects() {
    let observed = vec![Header::new("Host"), Header::new("Connection").with_value("keep-alive")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"), // Required, missing
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(!result, "a required header missing rejects the signature outright");
}

#[test]
fn test_headers_realistic_browser_with_optional_skips() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept").with_value("text/html"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept").with_value("text/html"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Optional, missing
        Header::new("Accept-Encoding").optional().with_value("gzip"), // Optional, missing
        Header::new("Cookie").optional(),                             // Optional, missing
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(result, "Browser should match signature even with optional headers missing");
}

#[test]
fn test_headers_missing_optional_header() {
    let observed = vec![Header::new("Host"), Header::new("User-Agent").with_value("Mozilla/5.0")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Missing but optional
    ];

    let result = headers_match(&observed, &signature);
    assert!(result, "Missing optional headers should not cause errors");
}

#[test]
fn test_headers_missing_required_header_at_end_rejects() {
    let observed = vec![Header::new("Host")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"), // Missing and NOT optional
    ];

    let result = headers_match(&observed, &signature);
    assert!(!result, "a required header missing rejects the signature outright");
}

#[test]
fn test_headers_extra_headers_in_observed_are_free() {
    let observed = vec![
        Header::new("Host"),
        Header::new("X-Custom-Header").with_value("custom"), // Not in the signature
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("X-Another").with_value("trailing"),
    ];

    let signature = vec![Header::new("Host"), Header::new("User-Agent").with_value("Mozilla/5.0")];

    let result = headers_match(&observed, &signature);
    assert!(
        result,
        "headers the signature does not mention never penalise, wherever they appear"
    );
}

#[test]
fn test_headers_expected_value_matches_as_substring() {
    let observed = vec![
        Header::new("Host"),
        Header::new("Accept").with_value("image/avif,image/webp,image/*,*/*;q=0.8"),
    ];

    let signature = vec![Header::new("Host"), Header::new("Accept").with_value("*/*")];

    let result = headers_match(&observed, &signature);
    assert!(result, "the expected value only has to be contained in the observed one");
}

#[test]
fn test_headers_expects_value_but_observed_has_none_rejects() {
    // Observations drop the value of headers p0f prints without one, so a
    // signature demanding a value can never be satisfied by them.
    let observed = vec![Header::new("Host"), Header::new("User-Agent")];

    let signature = vec![Header::new("Host"), Header::new("User-Agent").with_value("Mozilla/5.0")];

    let result = headers_match(&observed, &signature);
    assert!(!result, "a valueless observed header cannot satisfy an expected value");
}

#[test]
fn test_headers_optional_header_out_of_order_rejects() {
    // The signature wants Referer between Host and User-Agent. It does appear
    // in the traffic, just in the wrong place: p0f treats that as a mismatch
    // rather than as a missing optional header.
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Referer").with_value("http://example.com"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("Referer").optional(),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(!result, "an optional header present out of order rejects the signature");
}

#[test]
fn test_headers_required_header_out_of_order_rejects() {
    let observed = vec![Header::new("Connection").with_value("keep-alive"), Header::new("Host")];

    let signature = vec![Header::new("Host"), Header::new("Connection").with_value("keep-alive")];

    let result = headers_match(&observed, &signature);
    assert!(!result, "header order is part of the signature");
}

#[test]
fn test_headers_optional_header_at_end() {
    let observed = vec![Header::new("Host"), Header::new("User-Agent").with_value("Mozilla/5.0")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Optional, missing
    ];

    let result = headers_match(&observed, &signature);
    assert!(result, "Missing optional headers at end should not cause errors");
}

#[test]
fn test_headers_observed_vs_signature_with_optional() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept").with_value("text/html"),
        Header::new("Accept-Language").with_value("en-US"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept").with_value("text/html"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Optional but value must match
    ];

    let result = headers_match(&observed, &signature);
    assert!(
        result,
        "Should match perfectly: all headers match including values for optional headers"
    );
}

#[test]
fn test_headers_value_mismatch_rejects() {
    let observed = vec![Header::new("Host"), Header::new("Connection").with_value("keep-alive")];

    let signature = vec![
        Header::new("Host"),
        Header::new("Connection").with_value("close"), // Different value
    ];

    let result = headers_match(&observed, &signature);
    assert!(!result, "a value that is not a substring of the observed one rejects");
}

#[test]
fn test_headers_value_mismatch_rejects_even_when_optional() {
    // `optional` only covers absence: a header that is present must still
    // match the expected value.
    let observed = vec![Header::new("Host"), Header::new("Referer").with_value("http://other")];

    let signature = vec![
        Header::new("Host"),
        Header::new("Referer")
            .optional()
            .with_value("http://example.com"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(!result, "optional headers that are present must still match their value");
}

#[test]
fn test_headers_realistic_browser_scenario() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent")
            .with_value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
        Header::new("Accept").with_value("text/html,application/xhtml+xml"),
        Header::new("Accept-Language").with_value("en-US,en;q=0.9"),
        Header::new("Accept-Encoding").with_value("gzip, deflate"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    // Database signature for Chrome
    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent")
            .with_value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
        Header::new("Accept").with_value("text/html,application/xhtml+xml"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US,en;q=0.9"), // Optional but value must match
        Header::new("Accept-Encoding").with_value("gzip, deflate"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = headers_match(&observed, &signature);
    assert!(
        result,
        "Should match perfectly for realistic Chrome signature with value matching"
    );
}
