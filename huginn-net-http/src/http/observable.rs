use super::common::{HttpCookie, HttpHeader};
use super::{Header, Version};
use core::fmt;
use std::fmt::Formatter;

/// Observed HTTP request characteristics extracted from network traffic.
///
/// `huginn-net-http` defines this type so the crate stays independent of any
/// signature database. `huginn-net-db` re-exports it from here for matching.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpRequestObservation {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic (p0f style).
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic (p0f style).
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

/// Observed HTTP response characteristics extracted from network traffic.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpResponseObservation {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic (p0f style).
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic (p0f style).
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

/// Public-facing HTTP request observation: includes the matching payload plus
/// raw signal fields useful to consumers (lang, UA, headers, cookies, …).
#[derive(Debug, Clone)]
pub struct ObservableHttpRequest {
    pub matching: HttpRequestObservation,
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub cookies: Vec<HttpCookie>,
    pub referer: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObservableHttpResponse {
    pub matching: HttpResponseObservation,
    pub headers: Vec<HttpHeader>,
    pub status_code: Option<u16>,
}

/// Trait used to render HTTP signatures in the canonical p0f text form
/// `version:horder:habsent:expsw`.
///
/// `huginn-net-db` implements this trait for its own `http::Signature` and
/// reuses the same shape, so observations and DB signatures print identically.
pub trait HttpDisplayFormat {
    fn get_version(&self) -> Version;
    fn get_horder(&self) -> &[Header];
    fn get_habsent(&self) -> &[Header];
    fn get_expsw(&self) -> &str;

    fn format_http_display(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.get_version())?;

        for (i, h) in self.get_horder().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{h}")?;
        }

        f.write_str(":")?;

        for (i, h) in self.get_habsent().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{h}")?;
        }

        write!(f, ":{}", self.get_expsw())
    }
}

impl HttpDisplayFormat for HttpRequestObservation {
    fn get_version(&self) -> Version {
        self.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.expsw
    }
}

impl HttpDisplayFormat for HttpResponseObservation {
    fn get_version(&self) -> Version {
        self.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.expsw
    }
}

impl fmt::Display for HttpRequestObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for HttpResponseObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl HttpDisplayFormat for ObservableHttpRequest {
    fn get_version(&self) -> Version {
        self.matching.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl HttpDisplayFormat for ObservableHttpResponse {
    fn get_version(&self) -> Version {
        self.matching.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl fmt::Display for ObservableHttpRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for ObservableHttpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for HttpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(ref value) = self.value {
            write!(f, "{}={}", self.name, value)
        } else {
            write!(f, "{}", self.name)
        }
    }
}
