use super::window_size::{detect_win_multi, WindowMultiplier};
use super::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl};
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
    /// Window size, exactly as it came off the wire.
    ///
    /// Never pre-classified into a multiple of the MSS or the MTU: that would
    /// throw away the raw value a signature with a literal window needs. Use
    /// [`TcpObservation::window_multiplier`] when a multiple is what's wanted.
    pub wsize: u16,
    /// Bytes of IP plus TCP header, options included, which is one of the
    /// divisors a window can turn out to be a multiple of.
    pub tot_hdr: u16,
    /// Window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// Layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// Properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<Quirk>,
    /// Payload size classification.
    pub pclass: PayloadSize,
}

impl TcpObservation {
    /// The observed window expressed as a multiple of the MSS or the MTU, when
    /// it is one. Derived, never stored.
    pub fn window_multiplier(&self) -> Option<WindowMultiplier> {
        detect_win_multi(
            self.wsize,
            self.mss,
            self.tot_hdr,
            self.own_timestamp_is_nonzero(),
            self.version,
        )
    }

    /// Whether the packet carried a timestamp of its own, which is p0f's
    /// `if (ts->ts1)`: the option is present and its value is not zero.
    fn own_timestamp_is_nonzero(&self) -> bool {
        self.olayout.contains(&TcpOption::TS) && !self.quirks.contains(&Quirk::OwnTimestampZero)
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
    /// Renders the observation in `p0f.fp` syntax.
    ///
    /// The window is written as `mss*n` or `mtu*n` when it is a multiple of one
    /// of them and as the raw value otherwise, which is what p0f's `dump_sig`
    /// prints. The form is computed here, not read off the observation.
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

        f.write_str(":")?;

        for (i, q) in self.quirks.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{q}")?;
        }

        write!(f, ":{}", self.pclass)
    }
}

impl fmt::Display for ObservableTcp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.matching.fmt(f)
    }
}
