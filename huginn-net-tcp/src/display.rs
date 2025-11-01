use crate::observable::ObservableTcp;
use core::fmt;
use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
use std::fmt::Formatter;

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
