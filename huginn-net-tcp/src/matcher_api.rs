//! Matching boundary between this crate and any database/matcher implementation.
//!
//! `huginn-net-tcp` is intentionally agnostic of where TCP signatures live.
//! Anything wishing to provide OS/MTU matches simply implements [`TcpMatcher`]
//! and is plugged into [`crate::HuginnNetTcp`] (or used directly from
//! [`crate::process_ipv4_packet`] / [`crate::process_ipv6_packet`]).
//!
//! In the default workspace setup, `huginn-net-db` provides
//! `TcpSignatureMatcher`, which loads p0f-style signatures and implements this
//! trait.

use crate::observable::TcpObservation;
use crate::output::{MatchRank, OperativeSystem};

/// A matched OS for a single observed TCP fingerprint.
#[derive(Debug, Clone)]
pub struct TcpMatch {
    /// Operating system / application identified by the matcher.
    pub os: OperativeSystem,
    /// Tier the match landed in, carrying the tolerance that was applied when
    /// the fit is not exact. Implementers must report a stretched fit as
    /// [`MatchRank::Fuzzy`] rather than as an exact one.
    pub rank: MatchRank,
    /// Hop distance reported in `Dist:` (signature hops, or `guess_dist`).
    pub dist: u8,
    /// Winning signature used a randomised TTL (`nnn-` / `bad_ttl`).
    pub random_ttl: bool,
    /// Reported [`Self::dist`] exceeds p0f's `MAX_DIST` (35).
    pub excess_dist: bool,
}

/// A matched MTU/link-type estimate.
#[derive(Debug, Clone)]
pub struct MtuMatch {
    /// Human-readable link type, e.g. `"Ethernet or modem"`.
    pub link: String,
}

/// Pluggable TCP fingerprint matcher.
///
/// Implementations are typically backed by a fingerprint database. The
/// canonical implementation in this workspace is
/// `huginn_net_db::TcpSignatureMatcher`.
pub trait TcpMatcher: Send + Sync {
    /// Match an observed client (SYN) fingerprint.
    fn match_tcp_request(&self, obs: &TcpObservation) -> Option<TcpMatch>;

    /// Match an observed server (SYN+ACK) fingerprint.
    fn match_tcp_response(&self, obs: &TcpObservation) -> Option<TcpMatch>;

    /// Match an observed MTU value to a known link type.
    fn match_mtu(&self, mtu: u16) -> Option<MtuMatch>;
}
