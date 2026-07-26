use crate::database::Label;
use std::fmt::Debug;
use std::hash::Hash;

/// An observed fingerprint from live network traffic.
pub trait ObservedFingerprint: Clone + Debug {
    /// The type of key used to index database signatures compatible with this observed fingerprint.
    type Key: IndexKey;

    /// Generates an index key from this observed fingerprint.
    fn generate_index_key(&self) -> Self::Key;
}

/// How well a database signature fits an observation, when it fits at all.
///
/// There is no accumulated score here. Every field is either a gate the
/// signature passes or fails, plus the two narrow tolerances p0f documents,
/// so what a comparison yields is "does it hold, and did it need a tolerance".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureFit {
    /// A tolerance had to be stretched for the match to hold, which ranks this
    /// candidate below every signature that fit exactly.
    pub fuzzy: bool,
    /// How far this candidate sits from the observation *within* its tier.
    /// Used only to break ties between candidates of the same rank; lower is
    /// closer. Protocols with nothing to measure report `0`.
    pub deviation: u32,
}

impl SignatureFit {
    /// Every field matched, nothing was stretched.
    pub fn exact(deviation: u32) -> Self {
        Self { fuzzy: false, deviation }
    }

    /// The match only holds because a tolerance was applied.
    pub fn fuzzy(deviation: u32) -> Self {
        Self { fuzzy: true, deviation }
    }
}

/// A fingerprint signature as defined in a database.
/// `OF` is the type of `ObservedFingerprint` that this database signature can be compared against.
pub trait DatabaseSignature<OF: ObservedFingerprint> {
    /// Compares this signature against an observation. `None` rejects it: a
    /// signature that fails any gate is not a worse candidate, it is not a
    /// candidate.
    fn fit(&self, observed: &OF) -> Option<SignatureFit>;

    /// Generates index keys from this database signature.
    /// It's a Vec because some DB signatures (like IpVersion::Any) might map to multiple keys.
    /// The Option<OF::Key> in the Vec allows for cases where a specific DB sig might not produce a key
    /// for a certain specific version (e.g. an IpVersion::Any sig, when asked to produce a V4 key, will).
    fn generate_index_keys_for_db_entry(&self) -> Vec<OF::Key>;
}

/// Base trait for keys used in fingerprint indexes.
pub trait IndexKey: Debug + Clone + Eq + Hash {}

/// Where a candidate sits in p0f's order of preference.
///
/// p0f returns the first exact match on a specific signature and only falls
/// back to a generic one after exhausting the list; a match that needed a
/// tolerance is the last resort, and does *not* keep its specific/generic
/// distinction (`fp_tcp.c:221-271`). Declaration order is the preference
/// order, so `Ord` sorts best-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchRank {
    /// Exact fit against a signature naming a concrete product.
    Specific,
    /// Exact fit against a catch-all signature.
    Generic,
    /// Only holds because a documented tolerance was applied.
    Fuzzy,
}

impl MatchRank {
    /// Quality score reported to consumers.
    ///
    /// The contract is the ordering, not the numbers: a specific match always
    /// scores above a generic one, which always scores above a fuzzy one. The
    /// values themselves are free to be recalibrated.
    pub fn as_quality(self) -> f32 {
        match self {
            MatchRank::Specific => 1.0,
            MatchRank::Generic => 0.8,
            MatchRank::Fuzzy => 0.5,
        }
    }
}

/// Represents a collection of database signatures of a specific type.
/// `OF` is the `ObservedFingerprint` type.
/// `DS` is the `DatabaseSignature` type that can be compared against `OF`.
pub trait FingerprintDb<OF: ObservedFingerprint, DS: DatabaseSignature<OF>> {
    /// Finds the best match for an observed fingerprint within this database.
    /// Returns the label of the match, the matching database signature, and a quality score.
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, f32)>;
}
