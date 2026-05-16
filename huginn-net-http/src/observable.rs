use crate::http::{Header, Version};
use crate::http_common::{HttpCookie, HttpHeader};

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
