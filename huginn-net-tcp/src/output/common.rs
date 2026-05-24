use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone, PartialEq)]
pub struct IpPort {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl IpPort {
    pub fn new(ip: std::net::IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Marker telling whether a fingerprint is a "specific" definition or a
/// "generic" fall-back. Equivalent to p0f's `s` / `g` label prefix but
/// expressed as a TCP-local enum, so this crate stays decoupled from any
/// particular database format.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Outcome of matching an observation against a fingerprint database.
///
/// Independent of any specific database type so that consumers of this
/// crate don't need to depend on `huginn-net-db`.
#[derive(Clone, Debug)]
pub enum MatchQuality {
    /// Successful match. ScThe sre is in `[0.0, 1.0]` with `1.0` being a
    /// perfect match and lower scores indicating fuzzier matches.
    Matched(f32),
    /// A matcher was attached b,ut no signature matched the observation.
    NotMatched,
    /// No matcher was attached, so matching was skipped entirely.
    Disabled,
}

/// Represents an operative system.
///
/// Examples:
/// - `name: "Linux"`, `family: Some("unix")`, `variant: Some("2.2.x-3.x")`, `kind: OsKind::Specified`
/// - `name: "Windows"`, `family: Some("win")`, `variant: Some("NT kernel 6.x")`, `kind: OsKind::Specified`
#[derive(Debug, Clone)]
pub struct OperativeSystem {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

/// The operative system with the highest quality that matches the packet.
#[derive(Debug)]
pub struct OSQualityMatched {
    pub os: Option<OperativeSystem>,
    pub quality: MatchQuality,
}
