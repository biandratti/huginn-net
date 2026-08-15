use crate::tcp::Quirk;
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

/// Marker telling whether a fingerprint is a "specific" definition or a
/// "generic" fall-back. Equivalent to p0f's `s` / `g` label prefix but
/// expressed as a TCP-local enum, so this crate stays decoupled from any
/// particular database format.
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

/// Why a match only holds approximately.
///
/// A signature is otherwise made of gates: a field that disagrees rejects it.
/// These are the two exceptions, the tolerances p0f documents, and both can
/// apply to the same signature, so at least one field here is always set.
#[derive(Clone, Debug, PartialEq)]
pub struct FuzzyReason {
    /// Hops between the initial TTL the signature declares and the observed
    /// one, when that count is too large to be plausible. A packet crossing
    /// more routers than this cannot be told apart from one whose OS simply
    /// uses a different initial TTL.
    pub implausible_hop_distance: Option<u32>,
    /// Quirks the traffic showed that the signature does not declare. Only
    /// `id-` and `ecn` ever appear here; anything else rejects the signature.
    pub added_quirks: Vec<Quirk>,
    /// Quirks the signature declares that the traffic did not show. Only `df`
    /// and `id+` ever appear here.
    pub missing_quirks: Vec<Quirk>,
}

impl fmt::Display for FuzzyReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut separate = |f: &mut Formatter<'_>| -> fmt::Result {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            Ok(())
        };

        if let Some(hops) = self.implausible_hop_distance {
            separate(f)?;
            write!(f, "{hops} hops")?;
        }
        if !self.missing_quirks.is_empty() {
            separate(f)?;
            write!(f, "missing {}", join_quirks(&self.missing_quirks))?;
        }
        if !self.added_quirks.is_empty() {
            separate(f)?;
            write!(f, "extra {}", join_quirks(&self.added_quirks))?;
        }

        Ok(())
    }
}

fn join_quirks(quirks: &[Quirk]) -> String {
    quirks
        .iter()
        .map(|quirk| quirk.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Outcome of matching an observation against a fingerprint database.
///
/// Independent of any specific database type so that consumers of this
/// crate don't need to depend on `huginn-net-db`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum MatchQuality {
    /// A signature matched.
    Matched {
        /// Which tier the match landed in, as a number in `[0.0, 1.0]`: an
        /// exact fit against a signature naming a concrete product scores
        /// highest, a catch-all signature lower, and a match that needed a
        /// tolerance lowest. The ordering is the contract; the values are free
        /// to be recalibrated.
        quality: f32,
        /// Set when the match only holds because a tolerance was applied. The
        /// matched product is still the best explanation available, but it was
        /// not an exact fit.
        #[cfg_attr(
            feature = "json",
            serde(serialize_with = "super::serialize_optional_display")
        )]
        fuzzy: Option<FuzzyReason>,
    },
    /// A matcher was attached but no signature matched the observation.
    NotMatched,
    /// No matcher was attached, so matching was skipped entirely.
    Disabled,
}

impl MatchQuality {
    /// A match that fit every field exactly.
    pub fn exact(quality: f32) -> Self {
        MatchQuality::Matched { quality, fuzzy: None }
    }
}

/// Represents an operative system.
///
/// Examples:
/// - `name: "Linux"`, `family: Some("unix")`, `variant: Some("2.2.x-3.x")`, `kind: OsKind::Specified`
/// - `name: "Windows"`, `family: Some("win")`, `variant: Some("NT kernel 6.x")`, `kind: OsKind::Specified`
#[derive(Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct OperativeSystem {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

/// The operative system with the highest quality that matches the packet.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct OSQualityMatched {
    pub os: Option<OperativeSystem>,
    pub quality: MatchQuality,
}

impl OSQualityMatched {
    /// Flags qualifying the match, in p0f's `params` vocabulary, or `"none"`.
    ///
    /// p0f also reports `random_ttl` and `excess_dist` here, which need data
    /// this crate does not carry yet.
    pub fn params(&self) -> String {
        let mut flags = Vec::new();

        if self
            .os
            .as_ref()
            .is_some_and(|os| os.kind == OsKind::Generic)
        {
            flags.push("generic".to_string());
        }
        if let MatchQuality::Matched { fuzzy: Some(reason), .. } = &self.quality {
            flags.push(format!("fuzzy ({reason})"));
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(" ")
        }
    }
}
