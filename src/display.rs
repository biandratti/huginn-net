use core::fmt;

use crate::{Label, Type};

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.ty,
            self.class.as_ref().map(|s| s.as_str()).unwrap_or_default(),
            self.name,
            self.flavor.as_ref().map(|s| s.as_str()).unwrap_or_default()
        )
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Type::Specified => "s",
            Type::Generic => "g",
        })
    }
}

mod tcp {
    use core::fmt;

    use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, WindowSize, TTL};

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}:{}:{}:", self.version, self.ittl, self.olen)?;

            if let Some(mss) = self.mss {
                write!(f, "{}", mss)?;
            } else {
                f.write_str("*")?;
            }

            write!(f, ":{},", self.wsize)?;

            if let Some(scale) = self.wscale {
                write!(f, "{}", scale)?;
            } else {
                f.write_str("*")?;
            }

            f.write_str(":")?;

            for (i, o) in self.olayout.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }

                write!(f, "{}", o)?;
            }

            f.write_str(":")?;

            for (i, q) in self.quirks.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }

                write!(f, "{}", q)?;
            }

            write!(f, ":{}", self.pclass)
        }
    }

    impl fmt::Display for IpVersion {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use IpVersion::*;

            f.write_str(match self {
                V4 => "4",
                V6 => "6",
                Any => "*",
            })
        }
    }

    impl fmt::Display for TTL {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                TTL::Value(ttl) => write!(f, "{}", ttl),
                TTL::Distance(ttl, distance) => write!(f, "{}+{}", ttl, distance),
                TTL::Guess(ttl) => write!(f, "{}+?", ttl),
                TTL::Bad(ttl) => write!(f, "{}-", ttl),
            }
        }
    }

    impl fmt::Display for WindowSize {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use WindowSize::*;

            match self {
                MSS(n) => write!(f, "mss*{}", n),
                MTU(n) => write!(f, "mtu*{}", n),
                Value(n) => write!(f, "{}", n),
                Mod(n) => write!(f, "%{}", n),
                Any => f.write_str("*"),
            }
        }
    }

    impl fmt::Display for TcpOption {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use TcpOption::*;

            match self {
                EOL(n) => write!(f, "eol+{}", n),
                NOP => f.write_str("nop"),
                MSS => f.write_str("mss"),
                WS => f.write_str("ws"),
                SOK => f.write_str("sok"),
                SACK => f.write_str("sack"),
                TS => f.write_str("ts"),
                Unknown(n) => write!(f, "?{}", n),
            }
        }
    }

    impl fmt::Display for Quirk {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use Quirk::*;

            match self {
                DF => f.write_str("df"),
                NonZeroID => f.write_str("id+"),
                ZeroID => f.write_str("id-"),
                ECN => f.write_str("ecn"),
                MustBeZero => f.write_str("0+"),
                FlowID => f.write_str("flow"),
                SeqNumZero => f.write_str("seq-"),
                AckNumNonZero => f.write_str("ack+"),
                AckNumZero => f.write_str("ack-"),
                NonZeroURG => f.write_str("uptr+"),
                URG => f.write_str("urgf+"),
                PUSH => f.write_str("pushf+"),
                OwnTimestampZero => f.write_str("ts1-"),
                PeerTimestampNonZero => f.write_str("ts2+"),
                TrailinigNonZero => f.write_str("opt+"),
                ExcessiveWindowScaling => f.write_str("exws"),
                OptBad => f.write_str("bad"),
            }
        }
    }

    impl fmt::Display for PayloadSize {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    use core::fmt;

    use crate::http::{Header, Signature, Version};

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}:", self.version)?;

            for (i, h) in self.horder.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }

                write!(f, "{}", h)?;
            }

            f.write_str(":")?;

            for (i, h) in self.habsent.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }

                write!(f, "{}", h)?;
            }

            write!(f, ":{}", self.expsw)
        }
    }

    impl fmt::Display for Version {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(match self {
                Version::V10 => "0",
                Version::V11 => "1",
                Version::Any => "*",
            })
        }
    }

    impl fmt::Display for Header {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if self.optional {
                f.write_str("?")?;
            }

            f.write_str(&self.name)?;

            if let Some(ref value) = self.value {
                write!(f, "=[{}]", value)?;
            }

            Ok(())
        }
    }
}
