//! HTTP matcher trait owned by `huginn-net-http`.
//!
//! Mirrors `huginn_net_tcp::matcher_api::TcpMatcher`. Any consumer that wants
//! HTTP signature matching feeds an implementation of this trait into
//! [`crate::HuginnNetHttp`]. The reference implementation lives in
//! `huginn-net-db` (`HttpSignatureMatcher` and `SharedHttpSignatureMatcher`),
//! but downstream users are free to plug their own.

use crate::observable::{HttpRequestObservation, HttpResponseObservation};
use crate::output::{Browser, WebServer};

/// Result of matching an [`HttpRequestObservation`] against a database.
///
/// `expsw` is the substring expected to appear inside the observed
/// `User-Agent` for this signature (the fourth field of the `sig =` line in
/// `p0f.fp`, e.g. `"Firefox/"`). It is preserved here so the diagnostic step
/// can compare it against the observed UA and surface
/// [`crate::http::HttpDiagnosis::Dishonest`] when the two disagree, mirroring
/// p0f's `strstr(ts->sw, rs->sw)` check. Implementations that do not have
/// this information should leave it empty; the diagnostic step then falls
/// back to one of the other variants instead of `Dishonest`.
#[derive(Debug, Clone)]
pub struct HttpRequestMatch {
    pub browser: Browser,
    pub quality: f32,
    pub expsw: String,
}

/// Result of matching an [`HttpResponseObservation`] against a database.
///
/// `expsw` is the substring expected to appear inside the observed `Server`
/// header, analogous to [`HttpRequestMatch::expsw`].
#[derive(Debug, Clone)]
pub struct HttpResponseMatch {
    pub web_server: WebServer,
    pub quality: f32,
    pub expsw: String,
}

/// Result of mapping a User-Agent string against the database's UA→OS table.
///
/// `family` is the OS family (e.g. `"Windows"`, `"Linux"`); `flavor` is the
/// optional sub-variant (e.g. `"7 or 8"`).
#[derive(Debug, Clone)]
pub struct UaOsMatch {
    pub family: String,
    pub flavor: Option<String>,
}

/// Pluggable HTTP signature matcher.
///
/// Implementations must be `Send + Sync` so they can be shared across the
/// worker threads spawned by [`crate::HuginnNetHttp`].
pub trait HttpMatcher: Send + Sync {
    /// Match an HTTP request observation. Returns `None` if no candidate
    /// signature meets the configured quality threshold.
    fn match_http_request(&self, obs: &HttpRequestObservation) -> Option<HttpRequestMatch>;

    /// Match an HTTP response observation.
    fn match_http_response(&self, obs: &HttpResponseObservation) -> Option<HttpResponseMatch>;

    /// Map a User-Agent string against the database UA→OS table.
    fn match_user_agent(&self, ua: &str) -> Option<UaOsMatch>;
}
