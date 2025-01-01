use crate::db::Label;
use crate::Database;
use crate::{http, tcp};

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &tcp::Signature,
    ) -> Option<(&'a Label, &'a tcp::Signature)> {
        for (label, db_signatures) in &self.database.tcp_request {
            for db_signature in db_signatures {
                if signature.matches(db_signature) {
                    return Some((label, db_signature));
                }
            }
        }
        None
    }

    pub fn matching_by_tcp_response(
        &self,
        signature: &tcp::Signature,
    ) -> Option<(&'a Label, &'a tcp::Signature)> {
        for (label, db_signatures) in &self.database.tcp_response {
            for db_signature in db_signatures {
                if signature.matches(db_signature) {
                    return Some((label, db_signature));
                }
            }
        }
        None
    }

    pub fn matching_by_mtu(&self, mtu: &u16) -> Option<(&'a String, &'a u16)> {
        for (link, db_mtus) in &self.database.mtu {
            for db_mtu in db_mtus {
                if mtu == db_mtu {
                    return Some((link, db_mtu));
                }
            }
        }
        None
    }

    pub fn matching_by_http_request(
        &self,
        signature: &http::Signature,
    ) -> Option<(&'a Label, &'a http::Signature)> {
        for (label, db_signatures) in &self.database.http_request {
            for db_signature in db_signatures {
                if signature.matches(db_signature) {
                    return Some((label, db_signature));
                }
            }
        }
        None
    }

    pub fn matching_by_http_response(
        &self,
        signature: &http::Signature,
    ) -> Option<(&'a Label, &'a http::Signature)> {
        for (label, db_signatures) in &self.database.http_response {
            for db_signature in db_signatures {
                if signature.matches(db_signature) {
                    return Some((label, db_signature));
                }
            }
        }
        None
    }

    pub fn matching_by_user_agent(
        &self,
        user_agent: &str,
    ) -> Option<(&'a String, &'a Option<String>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua) {
                return Some((ua, ua_family));
            }
        }
        None
    }
}
