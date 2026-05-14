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

#[cfg(feature = "tcp")]
mod tcp {
    use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};
    use core::fmt;
    use std::fmt::Formatter;

    // Display for `Signature` mirrors the format used by `TcpObservation`
    // (whose Display lives in `huginn-net-tcp`). Both produce the canonical
    // p0f text form: `version:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass`.
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

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_tcp_display(f)
        }
    }
}

#[cfg(feature = "http")]
mod http {
    use crate::http::Signature;
    use core::fmt;
    use huginn_net_http::display::HttpDisplayFormat;
    use huginn_net_http::http::{Header, Version};
    use std::fmt::Formatter;

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

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            self.format_http_display(f)
        }
    }
}
