use crate::db::Label;
use crate::tcp::Signature;
use crate::Database;

pub struct SignatureMatcher<'a> {
    database: &'a Database, // Reference to the database
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &Signature,
    ) -> Option<(&'a Label, &'a Signature)> {
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
        signature: &Signature,
    ) -> Option<(&'a Label, &'a Signature)> {
        for (label, db_signatures) in &self.database.tcp_response {
            for db_signature in db_signatures {
                if signature.matches(db_signature) {
                    return Some((label, db_signature));
                }
            }
        }
        None
    }
}
