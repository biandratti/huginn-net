use crate::database::{HttpDatabase, Label, Type};
use crate::db_matching_trait::FingerprintDb;
use huginn_net_http::matcher_api::{HttpMatcher, HttpRequestMatch, HttpResponseMatch, UaOsMatch};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};
use huginn_net_http::output::{Browser, OsKind, WebServer};
use std::sync::Arc;

pub struct HttpSignatureMatcher<'a> {
    database: &'a HttpDatabase,
}

impl<'a> HttpSignatureMatcher<'a> {
    pub fn new(database: &'a HttpDatabase) -> Self {
        Self { database }
    }

    pub fn matching_by_http_request(
        &self,
        signature: &HttpRequestObservation,
    ) -> Option<(&'a Label, &'a crate::http::Signature, f32)> {
        self.database.http_request.find_best_match(signature)
    }

    pub fn matching_by_http_response(
        &self,
        signature: &HttpResponseObservation,
    ) -> Option<(&'a Label, &'a crate::http::Signature, f32)> {
        self.database.http_response.find_best_match(signature)
    }

    pub fn matching_by_user_agent(&self, user_agent: &str) -> Option<(&'a str, Option<&'a str>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua.as_str()) {
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
// Shared matching helpers
// ---------------------------------------------------------------------------

fn match_http_request_impl(
    db: &HttpDatabase,
    obs: &HttpRequestObservation,
) -> Option<HttpRequestMatch> {
    let (label, _sig, quality) = db.http_request.find_best_match(obs)?;
    Some(HttpRequestMatch { browser: Browser::from(label), quality })
}

fn match_http_response_impl(
    db: &HttpDatabase,
    obs: &HttpResponseObservation,
) -> Option<HttpResponseMatch> {
    let (label, _sig, quality) = db.http_response.find_best_match(obs)?;
    Some(HttpResponseMatch { web_server: WebServer::from(label), quality })
}

fn match_user_agent_impl(db: &HttpDatabase, ua: &str) -> Option<UaOsMatch> {
    for (ua_substr, family) in &db.ua_os {
        if ua.contains(ua_substr.as_str()) {
            if let Some(family) = family {
                return Some(UaOsMatch { family: family.clone(), flavor: None });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HttpMatcher implementation for the borrowed matcher.
// ---------------------------------------------------------------------------

impl<'a> HttpMatcher for HttpSignatureMatcher<'a> {
    fn match_http_request(&self, obs: &HttpRequestObservation) -> Option<HttpRequestMatch> {
        match_http_request_impl(self.database, obs)
    }

    fn match_http_response(&self, obs: &HttpResponseObservation) -> Option<HttpResponseMatch> {
        match_http_response_impl(self.database, obs)
    }

    fn match_user_agent(&self, ua: &str) -> Option<UaOsMatch> {
        match_user_agent_impl(self.database, ua)
    }
}

// ---------------------------------------------------------------------------
// Shared, owned matcher (implements HttpMatcher)
// ---------------------------------------------------------------------------

pub struct SharedHttpSignatureMatcher {
    database: Arc<HttpDatabase>,
}

impl SharedHttpSignatureMatcher {
    pub fn new(database: Arc<HttpDatabase>) -> Self {
        Self { database }
    }

    #[cfg(all(feature = "tcp", feature = "http"))]
    pub fn from_database(database: &crate::Database) -> Self {
        Self { database: Arc::new(database.http.clone()) }
    }

    pub fn database(&self) -> &HttpDatabase {
        &self.database
    }
}

impl HttpMatcher for SharedHttpSignatureMatcher {
    fn match_http_request(&self, obs: &HttpRequestObservation) -> Option<HttpRequestMatch> {
        match_http_request_impl(&self.database, obs)
    }

    fn match_http_response(&self, obs: &HttpResponseObservation) -> Option<HttpResponseMatch> {
        match_http_response_impl(&self.database, obs)
    }

    fn match_user_agent(&self, ua: &str) -> Option<UaOsMatch> {
        match_user_agent_impl(&self.database, ua)
    }
}
