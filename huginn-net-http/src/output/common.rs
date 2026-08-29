use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct IpPort {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl IpPort {
    pub fn new(ip: std::net::IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Whether a matched browser/web server label was a *specified* (concrete)
/// or *generic* (catch-all) entry in the underlying database.
///
/// Defined locally so `huginn-net-http` does not depend on `huginn-net-db`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum OsKind {
    Specified,
    Generic,
}

impl fmt::Display for OsKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OsKind::Specified => "Specified",
            OsKind::Generic => "Generic",
        })
    }
}

/// Which tier an HTTP match landed in: `Specific` beats `Generic`.
///
/// HTTP signatures have no tolerances: a field that disagrees rejects the
/// signature, so there is no fuzzy tier here, unlike TCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchRank {
    /// Fit against a signature naming a concrete product.
    Specific,
    /// Fit against a catch-all signature.
    Generic,
}

impl MatchRank {
    /// Score in `[0.0, 1.0]` for this tier. The ordering is the contract; the
    /// values are free to be recalibrated.
    pub fn as_quality(&self) -> f32 {
        match self {
            MatchRank::Specific => 1.0,
            MatchRank::Generic => 0.8,
        }
    }
}

/// Quality classification for an HTTP match.
///
/// - `Matched(rank)` a signature was matched, in the carried tier.
/// - `NotMatched` the matcher was active but no signature was a viable fit.
/// - `Disabled` matching was disabled (no matcher plugged in).
#[derive(Clone, Debug)]
pub enum MatchQuality {
    Matched(MatchRank),
    NotMatched,
    Disabled,
}

/// The wire format keeps the tier numeric: `Matched` serializes as its score.
#[cfg(feature = "json")]
impl serde::Serialize for MatchQuality {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            MatchQuality::Matched(rank) => serializer.serialize_newtype_variant(
                "MatchQuality",
                0,
                "Matched",
                &rank.as_quality(),
            ),
            MatchQuality::NotMatched => {
                serializer.serialize_unit_variant("MatchQuality", 1, "NotMatched")
            }
            MatchQuality::Disabled => {
                serializer.serialize_unit_variant("MatchQuality", 2, "Disabled")
            }
        }
    }
}

/// Represents a browser identified from an HTTP request signature.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct Browser {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

/// Represents a web server identified from an HTTP response signature.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct WebServer {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}
