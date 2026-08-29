use crate::observable::TcpObservation;
use crate::tcp::ttl::{guess_distance, observed_ttl, MAX_DIST};
use crate::tcp::QuirkSet;
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
    pub added_quirks: QuirkSet,
    /// Quirks the signature declares that the traffic did not show. Only `df`
    /// and `id+` ever appear here.
    pub missing_quirks: QuirkSet,
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
            write!(f, "missing {}", self.missing_quirks)?;
        }
        if !self.added_quirks.is_empty() {
            separate(f)?;
            write!(f, "extra {}", self.added_quirks)?;
        }

        Ok(())
    }
}

/// Which tier a match landed in, in preference order: `Specific` beats
/// `Generic`, and both beat `Fuzzy`.
///
/// The tier and the tolerance are the same fact, so they are one value: a match
/// is fuzzy exactly when there is a [`FuzzyReason`] to report, which makes a
/// "perfect fuzzy match" unrepresentable.
///
/// Distinct from [`OsKind`], which describes the matched *label* rather than
/// the fit: a fuzzy match against a specified signature is `Fuzzy` here and
/// `Specified` there.
#[derive(Clone, Debug, PartialEq)]
pub enum MatchRank {
    /// Exact fit against a signature naming a concrete product.
    Specific,
    /// Exact fit against a catch-all signature.
    Generic,
    /// Only holds because the carried tolerance was applied. The matched
    /// product is still the best explanation available, but it was not an
    /// exact fit.
    Fuzzy(FuzzyReason),
}

impl MatchRank {
    /// Score in `[0.0, 1.0]` for this tier. The ordering is the contract; the
    /// values are free to be recalibrated.
    pub fn as_quality(&self) -> f32 {
        match self {
            MatchRank::Specific => 1.0,
            MatchRank::Generic => 0.8,
            MatchRank::Fuzzy(_) => 0.5,
        }
    }

    /// The tolerance that was applied, or `None` for an exact fit.
    pub fn fuzzy(&self) -> Option<&FuzzyReason> {
        match self {
            MatchRank::Specific | MatchRank::Generic => None,
            MatchRank::Fuzzy(reason) => Some(reason),
        }
    }
}

/// Outcome of matching an observation against a fingerprint database.
///
/// Independent of any specific database type so that consumers of this
/// crate don't need to depend on `huginn-net-db`.
#[derive(Clone, Debug)]
pub enum MatchQuality {
    /// A signature matched, in the carried tier.
    Matched(MatchRank),
    /// A matcher was attached but no signature matched the observation.
    NotMatched,
    /// No matcher was attached, so matching was skipped entirely.
    Disabled,
}

impl MatchQuality {
    /// The tolerance the winning signature needed, if any. `None` for an exact
    /// fit and for every non-match.
    pub fn fuzzy(&self) -> Option<&FuzzyReason> {
        match self {
            MatchQuality::Matched(rank) => rank.fuzzy(),
            MatchQuality::NotMatched | MatchQuality::Disabled => None,
        }
    }
}

/// The wire format keeps the tier numeric: `Matched` serializes as a
/// `quality` score plus a stringified `fuzzy`.
#[cfg(feature = "json")]
impl serde::Serialize for MatchQuality {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;

        match self {
            MatchQuality::Matched(rank) => {
                let mut variant =
                    serializer.serialize_struct_variant("MatchQuality", 0, "Matched", 2)?;
                variant.serialize_field("quality", &rank.as_quality())?;
                variant.serialize_field("fuzzy", &rank.fuzzy().map(ToString::to_string))?;
                variant.end()
            }
            MatchQuality::NotMatched => {
                serializer.serialize_unit_variant("MatchQuality", 1, "NotMatched")
            }
            MatchQuality::Disabled => {
                serializer.serialize_unit_variant("MatchQuality", 2, "Disabled")
            }
        }
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
    /// Hop distance for the `Dist:` line (post-match or `guess_dist`).
    pub dist: u8,
    /// Winning signature used a randomised TTL (`nnn-`).
    pub random_ttl: bool,
    /// [`Self::dist`] is above p0f's `MAX_DIST` (35).
    pub excess_dist: bool,
    /// IPv4 DSCP / IPv6 traffic-class bits 2–7; `0` omits `tos:` from params.
    pub tos: u8,
}

impl OSQualityMatched {
    /// No OS match (or matching disabled): `Dist:` uses `guess_dist`, ToS from the observation.
    pub fn without_match(quality: MatchQuality, obs: &TcpObservation) -> Self {
        let dist = guess_distance(observed_ttl(&obs.ittl));
        Self {
            os: None,
            quality,
            dist,
            random_ttl: false,
            excess_dist: dist > MAX_DIST,
            tos: obs.tos,
        }
    }

    /// `generic`, `fuzzy (…)`, `random_ttl`, `excess_dist`, `tos:0xNN`, or `"none"`.
    pub fn params(&self) -> String {
        let mut flags = Vec::new();

        if self
            .os
            .as_ref()
            .is_some_and(|os| os.kind == OsKind::Generic)
        {
            flags.push("generic".to_string());
        }
        if let Some(reason) = self.quality.fuzzy() {
            flags.push(format!("fuzzy ({reason})"));
        }
        if self.random_ttl {
            flags.push("random_ttl".to_string());
        }
        if self.excess_dist {
            flags.push("excess_dist".to_string());
        }
        if self.tos != 0 {
            flags.push(format!("tos:0x{:02x}", self.tos));
        }

        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(" ")
        }
    }
}
