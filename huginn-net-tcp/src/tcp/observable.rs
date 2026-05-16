use super::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
use core::fmt;
use std::fmt::Formatter;

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

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

trait TcpDisplayFormat {
    fn get_version(&self) -> IpVersion;
    fn get_ittl(&self) -> Ttl;
    fn get_olen(&self) -> u8;
    fn get_mss(&self) -> Option<u16>;
    fn get_wsize(&self) -> WindowSize;
    fn get_wscale(&self) -> Option<u8>;
    fn get_olayout(&self) -> &[TcpOption];
    fn get_quirks(&self) -> &[Quirk];
    fn get_pclass(&self) -> PayloadSize;

    fn format_tcp_display(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}:", self.get_version(), self.get_ittl(), self.get_olen())?;

        if let Some(mss) = self.get_mss() {
            write!(f, "{mss}")?;
        } else {
            f.write_str("*")?;
        }

        write!(f, ":{},", self.get_wsize())?;

        if let Some(scale) = self.get_wscale() {
            write!(f, "{scale}")?;
        } else {
            f.write_str("*")?;
        }

        f.write_str(":")?;

        for (i, o) in self.get_olayout().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{o}")?;
        }

        f.write_str(":")?;

        for (i, q) in self.get_quirks().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{q}")?;
        }

        write!(f, ":{}", self.get_pclass())
    }
}

impl TcpDisplayFormat for ObservableTcp {
    fn get_version(&self) -> IpVersion {
        self.matching.version
    }
    fn get_ittl(&self) -> Ttl {
        self.matching.ittl.clone()
    }
    fn get_olen(&self) -> u8 {
        self.matching.olen
    }
    fn get_mss(&self) -> Option<u16> {
        self.matching.mss
    }
    fn get_wsize(&self) -> WindowSize {
        self.matching.wsize.clone()
    }
    fn get_wscale(&self) -> Option<u8> {
        self.matching.wscale
    }
    fn get_olayout(&self) -> &[TcpOption] {
        &self.matching.olayout
    }
    fn get_quirks(&self) -> &[Quirk] {
        &self.matching.quirks
    }
    fn get_pclass(&self) -> PayloadSize {
        self.matching.pclass
    }
}

impl fmt::Display for ObservableTcp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_tcp_display(f)
    }
}

impl TcpDisplayFormat for TcpObservation {
    fn get_version(&self) -> IpVersion {
        self.version
    }
    fn get_ittl(&self) -> Ttl {
        self.ittl.clone()
    }
    fn get_olen(&self) -> u8 {
        self.olen
    }
    fn get_mss(&self) -> Option<u16> {
        self.mss
    }
    fn get_wsize(&self) -> WindowSize {
        self.wsize.clone()
    }
    fn get_wscale(&self) -> Option<u8> {
        self.wscale
    }
    fn get_olayout(&self) -> &[TcpOption] {
        &self.olayout
    }
    fn get_quirks(&self) -> &[Quirk] {
        &self.quirks
    }
    fn get_pclass(&self) -> PayloadSize {
        self.pclass
    }
}

impl fmt::Display for TcpObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_tcp_display(f)
    }
}
