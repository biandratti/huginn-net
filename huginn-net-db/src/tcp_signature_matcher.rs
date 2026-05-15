use crate::db::{Label, TcpDatabase, Type};
use crate::db_matching_trait::FingerprintDb;
use crate::observable_signals::TcpObservation;
use huginn_net_tcp::matcher_api::{MtuMatch, TcpMatch, TcpMatcher};
use huginn_net_tcp::observable::ObservableTcp;
use huginn_net_tcp::output::{OperativeSystem, OsKind};
use std::sync::Arc;

pub struct TcpSignatureMatcher<'a> {
    database: &'a TcpDatabase,
}

impl<'a> TcpSignatureMatcher<'a> {
    pub fn new(database: &'a TcpDatabase) -> Self {
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

// ---------------------------------------------------------------------------
// Conversion bridges
// ---------------------------------------------------------------------------

impl From<&Label> for OperativeSystem {
    fn from(label: &Label) -> Self {
        OperativeSystem {
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

fn match_tcp_request_impl(db: &TcpDatabase, obs: &TcpObservation) -> Option<TcpMatch> {
    let (label, _sig, quality) = db.tcp_request.find_best_match(obs)?;
    Some(TcpMatch { os: OperativeSystem::from(label), quality })
}

fn match_tcp_response_impl(db: &TcpDatabase, obs: &TcpObservation) -> Option<TcpMatch> {
    let (label, _sig, quality) = db.tcp_response.find_best_match(obs)?;
    Some(TcpMatch { os: OperativeSystem::from(label), quality })
}

fn match_mtu_impl(db: &TcpDatabase, mtu: u16) -> Option<MtuMatch> {
    for (link, db_mtus) in &db.mtu {
        for db_mtu in db_mtus {
            if mtu == *db_mtu {
                return Some(MtuMatch { link: link.clone() });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TcpMatcher implementation for the borrowed matcher.
// ---------------------------------------------------------------------------

impl<'a> TcpMatcher for TcpSignatureMatcher<'a> {
    fn match_tcp_request(&self, obs: &TcpObservation) -> Option<TcpMatch> {
        match_tcp_request_impl(self.database, obs)
    }

    fn match_tcp_response(&self, obs: &TcpObservation) -> Option<TcpMatch> {
        match_tcp_response_impl(self.database, obs)
    }

    fn match_mtu(&self, mtu: u16) -> Option<MtuMatch> {
        match_mtu_impl(self.database, mtu)
    }
}

// ---------------------------------------------------------------------------
// Shared, owned matcher (implements TcpMatcher)
// ---------------------------------------------------------------------------

pub struct SharedTcpSignatureMatcher {
    database: Arc<TcpDatabase>,
}

impl SharedTcpSignatureMatcher {
    pub fn new(database: Arc<TcpDatabase>) -> Self {
        Self { database }
    }

    /// composed [`crate::Database`] requires both).
    #[cfg(all(feature = "tcp", feature = "http"))]
    pub fn from_database(database: &crate::Database) -> Self {
        Self { database: Arc::new(database.tcp.clone()) }
    }

    pub fn database(&self) -> &TcpDatabase {
        &self.database
    }
}

impl TcpMatcher for SharedTcpSignatureMatcher {
    fn match_tcp_request(&self, obs: &TcpObservation) -> Option<TcpMatch> {
        match_tcp_request_impl(&self.database, obs)
    }

    fn match_tcp_response(&self, obs: &TcpObservation) -> Option<TcpMatch> {
        match_tcp_response_impl(&self.database, obs)
    }

    fn match_mtu(&self, mtu: u16) -> Option<MtuMatch> {
        match_mtu_impl(&self.database, mtu)
    }
}
