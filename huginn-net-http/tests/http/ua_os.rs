use huginn_net_http::http::{
    check_ua_os_agreement, NotCheckedReason, ObservedOs, ObservedOsInput, ObservedOsScope,
    UNKNOWN_SOFTWARE,
};
use huginn_net_http::matcher_api::{HttpMatcher, HttpRequestMatch, HttpResponseMatch, UaOsMatch};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};
use huginn_net_http::output::{Browser, OsKind};

struct StubMatcher {
    request: Option<HttpRequestMatch>,
    ua: Option<UaOsMatch>,
}

impl HttpMatcher for StubMatcher {
    fn match_http_request(&self, _: &HttpRequestObservation) -> Option<HttpRequestMatch> {
        self.request.clone()
    }

    fn match_http_response(&self, _: &HttpResponseObservation) -> Option<HttpResponseMatch> {
        None
    }

    fn match_user_agent(&self, _: &str) -> Option<UaOsMatch> {
        self.ua.clone()
    }
}

fn userland(dishonest: bool) -> HttpRequestMatch {
    HttpRequestMatch {
        browser: Browser {
            name: "Chrome".to_owned(),
            family: None,
            variant: None,
            kind: OsKind::Specified,
        },
        quality: 1.0,
        dishonest,
    }
}

fn os_signature() -> HttpRequestMatch {
    HttpRequestMatch {
        browser: Browser {
            name: "Linux".to_owned(),
            family: Some("unix".to_owned()),
            variant: None,
            kind: OsKind::Specified,
        },
        quality: 1.0,
        dishonest: false,
    }
}

fn windows_ua() -> UaOsMatch {
    UaOsMatch { family: "Windows".to_owned(), flavor: None }
}

fn observed(name: &str, scope: ObservedOsScope) -> ObservedOs {
    ObservedOs { name: name.to_owned(), scope }
}

fn check(
    ua: Option<&str>,
    matched: Option<&HttpRequestMatch>,
    matcher: Option<&StubMatcher>,
    observed: ObservedOsInput<'_>,
) -> huginn_net_http::UaOsAgreement {
    let matcher = matcher.map(|m| m as &dyn HttpMatcher);
    check_ua_os_agreement(ua, matched, matcher, observed)
}

#[test]
fn no_http_match_is_not_checked() {
    let out = check(Some("Mozilla/5.0 (Windows NT 10.0)"), None, None, ObservedOsInput::NoSource);
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NoMatch));
}

#[test]
fn os_class_signature_is_not_userland() {
    let matched = os_signature();
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let os = observed("Linux", ObservedOsScope::Flow);
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Present(&os),
    );
    assert_eq!(
        out,
        huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NotUserlandApp)
    );
}

#[test]
fn missing_or_placeholder_ua_is_not_checked() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    for ua in [None, Some(""), Some("   "), Some(UNKNOWN_SOFTWARE)] {
        let out = check(ua, Some(&matched), Some(&matcher), ObservedOsInput::NoSource);
        assert_eq!(
            out,
            huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NoUserAgent),
            "ua={ua:?}"
        );
    }
}

#[test]
fn dishonest_ua_is_not_checked() {
    let matched = userland(true);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let os = observed("Linux", ObservedOsScope::Flow);
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Present(&os),
    );
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::Dishonest));
}

#[test]
fn ua_not_in_table_is_not_checked() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: None };
    let os = observed("Linux", ObservedOsScope::Flow);
    let out = check(
        Some("Mozilla/5.0 (UnknownOS)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Present(&os),
    );
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::UaNotInTable));
}

#[test]
fn no_source_only_after_http_gates() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::NoSource,
    );
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NoSource));
}

#[test]
fn missing_observed_os_is_not_checked() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Missing,
    );
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NoObservedOs));
}

#[test]
fn same_names_are_consistent() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let os = observed("Windows", ObservedOsScope::Flow);
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Present(&os),
    );
    assert_eq!(
        out,
        huginn_net_http::UaOsAgreement::Consistent {
            os: "Windows".to_owned(),
            scope: ObservedOsScope::Flow,
        }
    );
}

#[test]
fn different_names_are_divergent() {
    let matched = userland(false);
    let matcher = StubMatcher { request: Some(matched.clone()), ua: Some(windows_ua()) };
    let os = observed("Linux", ObservedOsScope::Host);
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&matched),
        Some(&matcher),
        ObservedOsInput::Present(&os),
    );
    assert_eq!(
        out,
        huginn_net_http::UaOsAgreement::Divergent {
            ua_os: "Windows".to_owned(),
            network_os: "Linux".to_owned(),
            scope: ObservedOsScope::Host,
        }
    );
}

#[test]
fn earlier_gates_win_over_missing_source() {
    let out = check(Some("Mozilla/5.0 (Windows NT 10.0)"), None, None, ObservedOsInput::NoSource);
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::NoMatch));

    let dishonest = userland(true);
    let matcher = StubMatcher { request: Some(dishonest.clone()), ua: Some(windows_ua()) };
    let out = check(
        Some("Mozilla/5.0 (Windows NT 10.0)"),
        Some(&dishonest),
        Some(&matcher),
        ObservedOsInput::NoSource,
    );
    assert_eq!(out, huginn_net_http::UaOsAgreement::NotChecked(NotCheckedReason::Dishonest));
}
