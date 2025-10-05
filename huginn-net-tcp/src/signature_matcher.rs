use crate::db::{db_matching_trait::FingerprintDb, Database, Label};
use crate::observable::ObservableTcp;

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_request
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_tcp_response(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_response
            .find_best_match(&signature.matching)
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
}
