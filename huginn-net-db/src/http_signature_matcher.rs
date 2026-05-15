use crate::db::{HttpDatabase, Label, Type};
use crate::db_matching_trait::FingerprintDb;
use crate::observable_signals::{HttpRequestObservation, HttpResponseObservation};
use huginn_net_http::matcher_api::{HttpMatcher, HttpRequestMatch, HttpResponseMatch, UaOsMatch};
use huginn_net_http::output::{Browser, OsKind, WebServer};
use std::sync::Arc;

pub struct HttpSignatureMatcher<'a> {
    database: &'a HttpDatabase,
}

impl<'a> HttpSignatureMatcher<'a> {
    pub fn new(database: &'a HttpDatabase) -> Self {
        Self { database }
    }

    /// Lower-level lookup that returns the raw label/signature/quality tuple
    /// produced by the underlying [`FingerprintDb`].
    pub fn matching_by_http_request(
        &self,
        signature: &HttpRequestObservation,
    ) -> Option<(&'a Label, &'a crate::http::Signature, f32)> {
        self.database.http_request.find_best_match(signature)
    }

    /// Lower-level lookup for HTTP responses.
    pub fn matching_by_http_response(
        &self,
        signature: &HttpResponseObservation,
    ) -> Option<(&'a Label, &'a crate::http::Signature, f32)> {
        self.database.http_response.find_best_match(signature)
    }

    /// Map a User-Agent string to its OS family using the database UA→OS
    /// table. Returns the UA substring that matched and the OS family.
    pub fn matching_by_user_agent(&self, user_agent: String) -> Option<(&'a str, Option<&'a str>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua) {
                return Some((ua.as_str(), ua_family.as_ref().map(|s| s.as_str())));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Conversion bridges
// ---------------------------------------------------------------------------

impl From<&Label> for Browser {
    fn from(label: &Label) -> Self {
        Browser {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: match label.ty {
                Type::Specified => OsKind::Specified,
                Type::Generic => OsKind::Generic,
            },
        }
    }
}

impl From<&Label> for WebServer {
    fn from(label: &Label) -> Self {
        WebServer {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: match label.ty {
                Type::Specified => OsKind::Specified,
                Type::Generic => OsKind::Generic,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// HttpMatcher implementation for the borrowed matcher.
// ---------------------------------------------------------------------------

impl<'a> HttpMatcher for HttpSignatureMatcher<'a> {
    fn match_http_request(&self, obs: &HttpRequestObservation) -> Option<HttpRequestMatch> {
        let (label, sig, quality) = self.database.http_request.find_best_match(obs)?;
        Some(HttpRequestMatch { browser: Browser::from(label), quality, expsw: sig.expsw.clone() })
    }

    fn match_http_response(&self, obs: &HttpResponseObservation) -> Option<HttpResponseMatch> {
        let (label, sig, quality) = self.database.http_response.find_best_match(obs)?;
        Some(HttpResponseMatch {
            web_server: WebServer::from(label),
            quality,
            expsw: sig.expsw.clone(),
        })
    }

    fn match_user_agent(&self, ua: &str) -> Option<UaOsMatch> {
        for (ua_substr, family) in &self.database.ua_os {
            if ua.contains(ua_substr) {
                if let Some(family) = family {
                    return Some(UaOsMatch { family: family.clone(), flavor: None });
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Shared, owned matcher (implements HttpMatcher)
// ---------------------------------------------------------------------------

/// Owned wrapper around an `Arc<HttpDatabase>` that implements [`HttpMatcher`].
///
/// This is the type you typically hand to
/// [`huginn_net_http::HuginnNetHttp::with_matcher`].
pub struct SharedHttpSignatureMatcher {
    database: Arc<HttpDatabase>,
}

impl SharedHttpSignatureMatcher {
    pub fn new(database: Arc<HttpDatabase>) -> Self {
        Self { database }
    }

    /// Convenience constructor for callers that already have an `Arc` of the
    /// composed [`crate::Database`]. Clones the inner [`HttpDatabase`] once;
    /// after that, lookups are zero-copy.
    ///
    /// Available only when both `tcp` and `http` features are enabled (the
    /// composed [`crate::Database`] requires both).
    #[cfg(all(feature = "tcp", feature = "http"))]
    pub fn from_database(database: &crate::Database) -> Self {
        Self { database: Arc::new(database.http.clone()) }
    }

    /// Borrow the underlying database, e.g. to construct a borrowed
    /// [`HttpSignatureMatcher`] for low-level access.
    pub fn database(&self) -> &HttpDatabase {
        &self.database
    }
}

impl HttpMatcher for SharedHttpSignatureMatcher {
    fn match_http_request(&self, obs: &HttpRequestObservation) -> Option<HttpRequestMatch> {
        let (label, sig, quality) = self.database.http_request.find_best_match(obs)?;
        Some(HttpRequestMatch { browser: Browser::from(label), quality, expsw: sig.expsw.clone() })
    }

    fn match_http_response(&self, obs: &HttpResponseObservation) -> Option<HttpResponseMatch> {
        let (label, sig, quality) = self.database.http_response.find_best_match(obs)?;
        Some(HttpResponseMatch {
            web_server: WebServer::from(label),
            quality,
            expsw: sig.expsw.clone(),
        })
    }

    fn match_user_agent(&self, ua: &str) -> Option<UaOsMatch> {
        for (ua_substr, family) in &self.database.ua_os {
            if ua.contains(ua_substr) {
                if let Some(family) = family {
                    return Some(UaOsMatch { family: family.clone(), flavor: None });
                }
            }
        }
        None
    }
}
