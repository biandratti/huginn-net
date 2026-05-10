// When the db feature is active, TcpObservation comes from huginn-net-db so that
// it is type-compatible with the matching logic in the DB crate.
// When db is off, we use a local definition built on our own tcp types.
#[cfg(feature = "db")]
pub use huginn_net_db::observable_signals::TcpObservation;

#[cfg(not(feature = "db"))]
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};

/// Observed TCP characteristics extracted from a network packet.
/// Available without the `db` feature.
#[cfg(not(feature = "db"))]
#[derive(Clone, Debug, PartialEq)]
pub struct TcpObservation {
    pub version: IpVersion,
    pub ittl: Ttl,
    pub olen: u8,
    pub mss: Option<u16>,
    pub wsize: WindowSize,
    pub wscale: Option<u8>,
    pub olayout: Vec<TcpOption>,
    pub quirks: Vec<Quirk>,
    pub pclass: PayloadSize,
}

#[derive(Debug, Clone)]
pub struct ObservableTcp {
    /// Core matching data for fingerprinting.
    pub matching: TcpObservation,
}

/// Observable MTU signals.
pub struct ObservableMtu {
    pub value: u16,
}

/// Observable Uptime signals.
#[derive(Debug, Clone)]
pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}
