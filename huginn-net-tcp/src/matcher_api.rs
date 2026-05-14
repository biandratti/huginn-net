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
use crate::output::OperativeSystem;

/// A matched OS for a single observed TCP fingerprint.
///
/// `quality` is a similarity score in `[0.0, 1.0]`, where `1.0` is a perfect
/// match. The exact distance/score formula is up to the matcher implementer.
#[derive(Debug, Clone)]
pub struct TcpMatch {
    /// Operating system / application identified by the matcher.
    pub os: OperativeSystem,
    /// Quality of the match, in `[0.0, 1.0]`.
    pub quality: f32,
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
