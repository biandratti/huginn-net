use crate::http;
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_db::db_matching_trait::FingerprintDb;
use huginn_net_db::{Database, Label};

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_http_request(
        &self,
        signature: &ObservableHttpRequest,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database
            .http_request
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_http_response(
        &self,
        signature: &ObservableHttpResponse,
    ) -> Option<(&'a Label, &'a http::Signature, f32)> {
        self.database
            .http_response
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_user_agent(&self, user_agent: String) -> Option<(&'a str, Option<&'a str>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua) {
                return Some((ua.as_str(), ua_family.as_ref().map(|s| s.as_str())));
            }
        }
        None
    }
}
