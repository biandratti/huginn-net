use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};

/// Represents observed TCP characteristics from network traffic.
///
/// Pure data: no matching/scoring methods. The matcher in `huginn-net-db`
/// borrows this struct and computes a distance against database signatures.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpObservation {
    /// IP version
    pub version: IpVersion,
    /// Initial TTL used by the OS.
    pub ittl: Ttl,
    /// Length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// Maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// Window size.
    pub wsize: WindowSize,
    /// Window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// Layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// Properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<Quirk>,
    /// Payload size classification.
    pub pclass: PayloadSize,
}

#[derive(Debug, Clone)]
pub struct ObservableTcp {
    /// Core matching data for fingerprinting.
    pub matching: TcpObservation,
}

// Observable MTU signals
pub struct ObservableMtu {
    pub value: u16,
}

// Observable Uptime signals
#[derive(Debug, Clone)]
pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}
