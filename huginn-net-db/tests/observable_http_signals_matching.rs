use huginn_net_db::http::{Header, HttpMatchQuality};
use huginn_net_db::observable_http_signals_matching::HttpDistance;
use huginn_net_db::observable_signals::{HttpRequestObservation, HttpResponseObservation};

#[test]
fn test_distance_header_with_one_optional_header_mismatch() {
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

    let result = <HttpResponseObservation as HttpDistance>::distance_header(&a, &b);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Expected Medium quality for 1 error in lists of 10"
    );
}

#[test]
fn test_distance_header_optional_skip_in_middle() {
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

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Optional header in middle should be skipped for perfect alignment"
    );
}

#[test]
fn test_distance_header_multiple_optional_skips() {
    let observed = vec![
        Header::new("Host"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"),
        Header::new("Accept-Encoding").optional().with_value("gzip"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Multiple optional headers should be skipped"
    );
}

#[test]
fn test_distance_header_required_in_middle_causes_error() {
    // Required header in middle should cause error and misalignment
    let observed = vec![
        Header::new("Host"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"), // Required, missing
        Header::new("Connection").with_value("keep-alive"),
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()), // 1 error falls in High range (0-2 errors)
        "Required header missing should cause 1 error"
    );
}

#[test]
fn test_distance_header_realistic_browser_with_optional_skips() {
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

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Browser should match signature even with optional headers missing"
    );
}

#[test]
fn test_distance_header_missing_optional_header() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Missing but optional
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Missing optional headers should not cause errors"
    );
}

#[test]
fn test_distance_header_missing_required_header() {
    let observed = vec![Header::new("Host")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"), // Missing and NOT optional
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()), // 1 error out of many
        "Missing required headers should cause errors"
    );
}

#[test]
fn test_distance_header_extra_headers_in_observed() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("X-Custom-Header").with_value("custom"), // Extra header
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()), // 1 error for extra header
        "Extra headers in observed should cause errors"
    );
}

#[test]
fn test_distance_header_optional_header_at_end() {
    let observed = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"),
        Header::new("Accept-Language")
            .optional()
            .with_value("en-US"), // Optional, missing
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Missing optional headers at end should not cause errors"
    );
}

#[test]
fn test_distance_header_required_header_at_end() {
    let observed = vec![Header::new("Host")];

    let signature = vec![
        Header::new("Host"),
        Header::new("User-Agent").with_value("Mozilla/5.0"), // Required, missing
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Missing required headers should cause 1 error"
    );
}

#[test]
fn test_distance_header_observed_vs_signature_with_optional() {
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

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Should match perfectly: all headers match including values for optional headers"
    );
}

#[test]
fn test_distance_header_value_mismatch_not_optional() {
    let observed = vec![
        Header::new("Host"),
        Header::new("Connection").with_value("keep-alive"),
    ];

    let signature = vec![
        Header::new("Host"),
        Header::new("Connection").with_value("close"), // Different value, not optional
    ];

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Should have 1 error out of 2 headers"
    );
}

#[test]
fn test_distance_header_realistic_browser_scenario() {
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

    let result = <HttpRequestObservation as HttpDistance>::distance_header(&observed, &signature);
    assert_eq!(
        result,
        Some(HttpMatchQuality::High.as_score()),
        "Should match perfectly for realistic Chrome signature with value matching"
    );
}
