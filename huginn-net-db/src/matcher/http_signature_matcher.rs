use crate::database::{HttpDatabase, Label, Type};
use crate::db_matching_trait::{FingerprintDb, MatchRank, NoFuzziness};
use crate::http::expsw_matches;
use huginn_net_http::matcher_api::{HttpMatcher, HttpRequestMatch, HttpResponseMatch, UaOsMatch};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};
use huginn_net_http::output::{Browser, MatchRank as HttpMatchRank, OsKind, WebServer};
use std::sync::Arc;

pub struct HttpSignatureMatcher<'a> {
    database: &'a HttpDatabase,
}

impl<'a> HttpSignatureMatcher<'a> {
    pub fn new(database: &'a HttpDatabase) -> Self {
        Self { database }
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

impl From<MatchRank<NoFuzziness>> for HttpMatchRank {
    fn from(rank: MatchRank<NoFuzziness>) -> Self {
        match rank {
            MatchRank::Specific => HttpMatchRank::Specific,
            MatchRank::Generic => HttpMatchRank::Generic,
            // `NoFuzziness` is uninhabited: HTTP signatures have no tolerances.
            MatchRank::Fuzzy(never) => match never {},
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
    let found = db.http_request.find_best_match(obs)?;
    Some(HttpRequestMatch {
        browser: Browser::from(found.label),
        rank: found.rank.into(),
        dishonest: !expsw_matches(&obs.expsw, &found.signature.expsw),
    })
}

fn match_http_response_impl(
    db: &HttpDatabase,
    obs: &HttpResponseObservation,
) -> Option<HttpResponseMatch> {
    let found = db.http_response.find_best_match(obs)?;
    Some(HttpResponseMatch {
        web_server: WebServer::from(found.label),
        rank: found.rank.into(),
        dishonest: !expsw_matches(&obs.expsw, &found.signature.expsw),
    })
}

fn match_user_agent_impl(db: &HttpDatabase, ua: &str) -> Option<UaOsMatch> {
    for (name, mapped) in &db.ua_os {
        // `ua_os = Linux,Windows,iOS=[iPad]`: a bare name is both the needle
        // and the family; `Family=[substr]` searches for `substr`.
        let (needle, family) = match mapped.as_deref() {
            Some(substr) => (substr, name.as_str()),
            None => (name.as_str(), name.as_str()),
        };
        if ua.contains(needle) {
            return Some(UaOsMatch { family: family.to_string(), flavor: None });
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

    /// Clone the HTTP sub-database out of a composed [`crate::Database`].
    /// Requires both `tcp` and `http` features.
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
