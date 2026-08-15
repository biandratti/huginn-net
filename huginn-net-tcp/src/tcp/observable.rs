use super::window_size::{detect_win_multi, WindowMultiplier};
use super::{IpVersion, PayloadSize, Quirk, QuirkSet, TcpOption, Ttl};
use core::fmt;
use std::fmt::Formatter;

/// Represents observed TCP characteristics from network traffic.
///
/// Pure data: no matching/scoring methods. The matcher in `huginn-net-db`
/// borrows this struct and compares it against database signatures.
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
    /// Window size as seen on the wire.
    pub wsize: u16,
    /// IP + TCP header bytes, options included.
    pub tot_hdr: u16,
    /// Window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// Layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// Properties and quirks observed in IP or TCP headers.
    pub quirks: QuirkSet,
    /// Payload size classification.
    pub pclass: PayloadSize,
    /// Peer SYN MSS on a SYN+ACK, when the SYN was seen. Always `None` on a SYN.
    pub peer_mss: Option<u16>,
    /// IPv4 DSCP / IPv6 traffic-class bits 2-7. Zero omits `tos:` from params.
    pub tos: u8,
}

impl TcpObservation {
    /// Window as an MSS/MTU multiple, when it is one.
    pub fn window_multiplier(&self) -> Option<WindowMultiplier> {
        detect_win_multi(
            self.wsize,
            self.mss,
            self.tot_hdr,
            self.own_timestamp_is_nonzero(),
            self.version,
            self.peer_mss,
        )
    }

    /// Timestamp option present and non-zero.
    fn own_timestamp_is_nonzero(&self) -> bool {
        self.olayout.contains(&TcpOption::TS) && !self.quirks.contains(Quirk::OwnTimestampZero)
    }
}

#[derive(Debug, Clone)]
pub struct ObservableTcp {
    /// Core matching data for fingerprinting.
    pub matching: TcpObservation,
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl fmt::Display for TcpObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}:", self.version, self.ittl, self.olen)?;

        match self.mss {
            Some(mss) => write!(f, "{mss}")?,
            None => f.write_str("*")?,
        }

        f.write_str(":")?;

        match self.window_multiplier() {
            Some(WindowMultiplier { multiple, of_mtu: true }) => write!(f, "mtu*{multiple}")?,
            Some(WindowMultiplier { multiple, of_mtu: false }) => write!(f, "mss*{multiple}")?,
            None => write!(f, "{}", self.wsize)?,
        }

        f.write_str(",")?;

        match self.wscale {
            Some(scale) => write!(f, "{scale}")?,
            None => f.write_str("*")?,
        }

        f.write_str(":")?;

        for (i, o) in self.olayout.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{o}")?;
        }

        write!(f, ":{}:{}", self.quirks, self.pclass)
    }
}

impl fmt::Display for ObservableTcp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.matching.fmt(f)
    }
}
