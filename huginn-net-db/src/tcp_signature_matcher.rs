//! TCP signature matchers backed by a [`TcpDatabase`].
//!
//! Two flavours are exposed:
//! - [`TcpSignatureMatcher<'a>`] - a borrowed matcher used by the umbrella
//!   crate (and any code that already has a `&TcpDatabase` in hand). This is
//!   the lower-level, allocation-free API.
//! - [`SharedTcpSignatureMatcher`] an owned matcher (holds an
//!   `Arc<TcpDatabase>`) that implements [`TcpMatcher`]. This is the matcher
//!   you hand to [`huginn_net_tcp::HuginnNetTcp`] when you want OS/MTU
//!   matching without writing your own glue.

use crate::db::{Label, TcpDatabase, Type};
use crate::db_matching_trait::FingerprintDb;
use crate::observable_signals::TcpObservation;
use huginn_net_tcp::matcher_api::{MtuMatch, TcpMatch, TcpMatcher};
use huginn_net_tcp::observable::ObservableTcp;
use huginn_net_tcp::output::{OperativeSystem, OsKind};
use std::sync::Arc;

/// A TCP signature matcher that searches a [`TcpDatabase`] for the closest
/// match to an observed fingerprint.
pub struct TcpSignatureMatcher<'a> {
    database: &'a TcpDatabase,
}

impl<'a> TcpSignatureMatcher<'a> {
    pub fn new(database: &'a TcpDatabase) -> Self {
        Self { database }
    }

    /// Lower-level lookup that returns the raw label/signature/quality tuple
    /// produced by the underlying [`FingerprintDb`].
    ///
    /// Useful for callers that need access to the matched [`Label`] (e.g. the
    /// HTTP UA-OS heuristic). Most consumers should prefer [`TcpMatcher`].
    pub fn matching_by_tcp_request(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_request
            .find_best_match(&signature.matching)
    }

    /// Lower-level lookup for SYN+ACK observations.
    pub fn matching_by_tcp_response(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_response
            .find_best_match(&signature.matching)
    }

    /// Lower-level MTU lookup. Returns the matching link name and its raw
    /// MTU value if a known link in the database advertises this exact MTU.
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

/// Owned wrapper around an `Arc<TcpDatabase>`. Implements
/// [`TcpMatcher`] so it can be plugged into
/// [`huginn_net_tcp::HuginnNetTcp::new`] / `with_config`.
pub struct SharedTcpSignatureMatcher {
    database: Arc<TcpDatabase>,
}

impl SharedTcpSignatureMatcher {
    pub fn new(database: Arc<TcpDatabase>) -> Self {
        Self { database }
    }

    /// Convenience constructor for callers that already have an `Arc` of the
    /// composed [`crate::Database`]. Clones the inner [`TcpDatabase`] once;
    /// after that, lookups are zero-copy.
    ///
    /// Available only when both `tcp` and `http` features are enabled (the
    /// composed [`crate::Database`] requires both).
    #[cfg(all(feature = "tcp", feature = "http"))]
    pub fn from_database(database: &crate::Database) -> Self {
        Self { database: Arc::new(database.tcp.clone()) }
    }

    /// Borrow the underlying database, e.g. to construct a borrowed
    /// [`TcpSignatureMatcher`] for low-level access.
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
