use core::fmt;
use std::fmt::Formatter;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub version: super::IpVersion,
    /// initial TTL used by the OS.
    pub ittl: super::Ttl,
    /// length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// window size.
    pub wsize: super::WindowSize,
    /// window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// layout and ordering of TCP options, if any.
    pub olayout: Vec<super::TcpOption>,
    /// properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<super::Quirk>,
    /// payload size classification
    pub pclass: super::PayloadSize,
}

// Shared p0f format: `version:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass`.
trait TcpDisplayFormat {
    fn get_version(&self) -> super::IpVersion;
    fn get_ittl(&self) -> super::Ttl;
    fn get_olen(&self) -> u8;
    fn get_mss(&self) -> Option<u16>;
    fn get_wsize(&self) -> super::WindowSize;
    fn get_wscale(&self) -> Option<u8>;
    fn get_olayout(&self) -> &[super::TcpOption];
    fn get_quirks(&self) -> &[super::Quirk];
    fn get_pclass(&self) -> super::PayloadSize;

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

impl TcpDisplayFormat for Signature {
    fn get_version(&self) -> super::IpVersion {
        self.version
    }
    fn get_ittl(&self) -> super::Ttl {
        self.ittl.clone()
    }
    fn get_olen(&self) -> u8 {
        self.olen
    }
    fn get_mss(&self) -> Option<u16> {
        self.mss
    }
    fn get_wsize(&self) -> super::WindowSize {
        self.wsize.clone()
    }
    fn get_wscale(&self) -> Option<u8> {
        self.wscale
    }
    fn get_olayout(&self) -> &[super::TcpOption] {
        &self.olayout
    }
    fn get_quirks(&self) -> &[super::Quirk] {
        &self.quirks
    }
    fn get_pclass(&self) -> super::PayloadSize {
        self.pclass
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_tcp_display(f)
    }
}
