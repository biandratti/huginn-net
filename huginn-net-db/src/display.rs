use crate::db::Label;
use core::fmt;
use std::fmt::Formatter;

impl fmt::Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.ty,
            self.class.as_deref().unwrap_or_default(),
            self.name,
            self.flavor.as_deref().unwrap_or_default()
        )
    }
}

mod tcp {
    use crate::observable_signals::TcpObservation;
    use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};
    use core::fmt;
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
            write!(
                f,
                "{}:{}:{}:",
                self.get_version(),
                self.get_ittl(),
                self.get_olen()
            )?;

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

    impl TcpDisplayFormat for Signature {
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

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_tcp_display(f)
        }
    }

    impl fmt::Display for IpVersion {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use IpVersion::*;

            f.write_str(match self {
                V4 => "4",
                V6 => "6",
                Any => "*",
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
            use WindowSize::*;

            match self {
                Mss(n) => write!(f, "mss*{n}"),
                Mtu(n) => write!(f, "mtu*{n}"),
                Value(n) => write!(f, "{n}"),
                Mod(n) => write!(f, "%{n}"),
                Any => f.write_str("*"),
            }
        }
    }

    impl fmt::Display for TcpOption {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use TcpOption::*;

            match self {
                Eol(n) => write!(f, "eol+{n}"),
                Nop => f.write_str("nop"),
                Mss => f.write_str("mss"),
                Ws => f.write_str("ws"),
                Sok => f.write_str("sok"),
                Sack => f.write_str("sack"),
                TS => f.write_str("ts"),
                Unknown(n) => write!(f, "?{n}"),
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
            use PayloadSize::*;

            f.write_str(match self {
                Zero => "0",
                NonZero => "+",
                Any => "*",
            })
        }
    }
}

mod http {
    use crate::http::{Header, HttpDiagnosis, Signature, Version};
    use crate::observable_signals::{HttpRequestObservation, HttpResponseObservation};
    use core::fmt;
    use std::fmt::Formatter;

    trait HttpDisplayFormat {
        fn get_version(&self) -> Version;
        fn get_horder(&self) -> &[Header];
        fn get_habsent(&self) -> &[Header];
        fn get_expsw(&self) -> &str;

        fn format_http_display(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}:", self.get_version())?;

            for (i, h) in self.get_horder().iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                write!(f, "{h}")?;
            }

            f.write_str(":")?;

            for (i, h) in self.get_habsent().iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                write!(f, "{h}")?;
            }

            write!(f, ":{}", self.get_expsw())
        }
    }

    impl HttpDisplayFormat for HttpRequestObservation {
        fn get_version(&self) -> Version {
            self.version
        }
        fn get_horder(&self) -> &[Header] {
            &self.horder
        }
        fn get_habsent(&self) -> &[Header] {
            &self.habsent
        }
        fn get_expsw(&self) -> &str {
            &self.expsw
        }
    }

    impl HttpDisplayFormat for HttpResponseObservation {
        fn get_version(&self) -> Version {
            self.version
        }
        fn get_horder(&self) -> &[Header] {
            &self.horder
        }
        fn get_habsent(&self) -> &[Header] {
            &self.habsent
        }
        fn get_expsw(&self) -> &str {
            &self.expsw
        }
    }

    impl HttpDisplayFormat for Signature {
        fn get_version(&self) -> Version {
            self.version
        }
        fn get_horder(&self) -> &[Header] {
            &self.horder
        }
        fn get_habsent(&self) -> &[Header] {
            &self.habsent
        }
        fn get_expsw(&self) -> &str {
            &self.expsw
        }
    }

    impl fmt::Display for HttpRequestObservation {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_http_display(f)
        }
    }

    impl fmt::Display for HttpResponseObservation {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_http_display(f)
        }
    }

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_http_display(f)
        }
    }

    impl fmt::Display for Version {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Version::V10 => "0",
                Version::V11 => "1",
                Version::V20 => "2",
                Version::V30 => "3",
                Version::Any => "*",
            })
        }
    }

    impl fmt::Display for Header {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.optional {
                f.write_str("?")?;
            }

            f.write_str(&self.name)?;

            if let Some(ref value) = self.value {
                write!(f, "=[{value}]")?;
            }

            Ok(())
        }
    }
    impl fmt::Display for HttpDiagnosis {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use crate::http::HttpDiagnosis::*;

            f.write_str(match self {
                Dishonest => "dishonest",
                Anonymous => "anonymous",
                Generic => "generic",
                None => "none",
            })
        }
    }
}
