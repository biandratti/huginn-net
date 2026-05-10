use crate::observable::ObservableTcp;
#[cfg(not(feature = "db"))]
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
use core::fmt;
#[cfg(feature = "db")]
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

// Display impls for local TCP types — only needed when the db feature is OFF.
// When db is ON, the Display impls come from huginn-net-db/src/display.rs.
#[cfg(not(feature = "db"))]
mod local_display {
    use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
    use core::fmt;
    use std::fmt::Formatter;

    impl fmt::Display for IpVersion {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                IpVersion::V4 => "4",
                IpVersion::V6 => "6",
                IpVersion::Any => "*",
            })
        }
    }

    impl fmt::Display for Ttl {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Ttl::Value(ttl) => write!(f, "{ttl}"),
                Ttl::Distance(ttl, distance) => write!(f, "{ttl}+{distance}"),
                Ttl::Guess(ttl) => write!(f, "{ttl}+?"),
                Ttl::Bad(ttl) => write!(f, "{ttl}-"),
            }
        }
    }

    impl fmt::Display for WindowSize {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                WindowSize::Mss(n) => write!(f, "mss*{n}"),
                WindowSize::Mtu(n) => write!(f, "mtu*{n}"),
                WindowSize::Value(n) => write!(f, "{n}"),
                WindowSize::Mod(n) => write!(f, "%{n}"),
                WindowSize::Any => f.write_str("*"),
            }
        }
    }

    impl fmt::Display for TcpOption {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                TcpOption::Eol(n) => write!(f, "eol+{n}"),
                TcpOption::Nop => f.write_str("nop"),
                TcpOption::Mss => f.write_str("mss"),
                TcpOption::Ws => f.write_str("ws"),
                TcpOption::Sok => f.write_str("sok"),
                TcpOption::Sack => f.write_str("sack"),
                TcpOption::TS => f.write_str("ts"),
                TcpOption::Unknown(n) => write!(f, "?{n}"),
            }
        }
    }

    impl fmt::Display for Quirk {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use Quirk::*;
            match self {
                Df => f.write_str("df"),
                NonZeroID => f.write_str("id+"),
                ZeroID => f.write_str("id-"),
                Ecn => f.write_str("ecn"),
                MustBeZero => f.write_str("0+"),
                FlowID => f.write_str("flow"),
                SeqNumZero => f.write_str("seq-"),
                AckNumNonZero => f.write_str("ack+"),
                AckNumZero => f.write_str("ack-"),
                NonZeroURG => f.write_str("uptr+"),
                Urg => f.write_str("urgf+"),
                Push => f.write_str("pushf+"),
                OwnTimestampZero => f.write_str("ts1-"),
                PeerTimestampNonZero => f.write_str("ts2+"),
                TrailinigNonZero => f.write_str("opt+"),
                ExcessiveWindowScaling => f.write_str("exws"),
                OptBad => f.write_str("bad"),
            }
        }
    }

    impl fmt::Display for PayloadSize {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                PayloadSize::Zero => "0",
                PayloadSize::NonZero => "+",
                PayloadSize::Any => "*",
            })
        }
    }
}
