use std::fmt;

/// TLS version for fingerprinting
/// Includes legacy SSL versions for complete JA4 specification compatibility.
/// Note: SSL 2.0 is not supported by tls-parser (too legacy/vulnerable)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    V1_3,
    V1_2,
    V1_1,
    V1_0,
    Ssl3_0,
    Ssl2_0,
    Unknown(u16),
}

impl TlsVersion {
    /// Map a TLS protocol version wire value (e.g. `0x0304`) to JA4's version token.
    pub(crate) fn from_wire(code: u16) -> Self {
        match code {
            0x0304 => TlsVersion::V1_3,
            0x0303 => TlsVersion::V1_2,
            0x0302 => TlsVersion::V1_1,
            0x0301 => TlsVersion::V1_0,
            0x0300 => TlsVersion::Ssl3_0,
            0x0002 => TlsVersion::Ssl2_0,
            _ => TlsVersion::Unknown(code),
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::V1_3 => write!(f, "13"),
            TlsVersion::V1_2 => write!(f, "12"),
            TlsVersion::V1_1 => write!(f, "11"),
            TlsVersion::V1_0 => write!(f, "10"),
            TlsVersion::Ssl3_0 => write!(f, "s3"),
            TlsVersion::Ssl2_0 => write!(f, "s2"),
            TlsVersion::Unknown(_) => write!(f, "00"),
        }
    }
}
