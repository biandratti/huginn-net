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

/// Quality classification for an HTTP match.
///
/// - `Matched(score)` a signature was matched with the given quality score
///   (higher is better, typically in `[0.0, 1.0]`).
/// - `NotMatched` the matcher was active but no signature was a viable fit.
/// - `Disabled` matching was disabled (no matcher plugged in).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum MatchQuality {
    Matched(f32),
    NotMatched,
    Disabled,
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
