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
/// signature passes or fails, plus the narrow tolerances p0f documents, so what
/// a comparison yields is "does it hold, and did it need a tolerance".
///
/// `F` describes the tolerance that was applied, which is protocol-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFit<F> {
    /// The tolerance that had to be stretched for the match to hold, which ranks
    /// this candidate below every signature that fit exactly.
    pub fuzzy: Option<F>,
}

impl<F> SignatureFit<F> {
    /// Every field matched, nothing was stretched.
    pub fn exact() -> Self {
        Self { fuzzy: None }
    }

    /// The match only holds because `reason` was tolerated.
    pub fn fuzzy(reason: F) -> Self {
        Self { fuzzy: Some(reason) }
    }
}

/// Placeholder for a protocol with no tolerances at all: being uninhabited, it
/// makes a fuzzy HTTP match unrepresentable rather than merely unused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoFuzziness {}

/// A fingerprint signature as defined in a database.
/// `OF` is the type of `ObservedFingerprint` that this database signature can be compared against.
pub trait DatabaseSignature<OF: ObservedFingerprint> {
    /// How this protocol describes an applied tolerance. [`NoFuzziness`] for
    /// protocols that have none.
    type Fuzziness;

    /// Compares this signature against an observation. `None` rejects it: a
    /// signature that fails any gate is not a worse candidate, it is not a
    /// candidate.
    fn fit(&self, observed: &OF) -> Option<SignatureFit<Self::Fuzziness>>;

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

/// The candidate that won selection.
#[derive(Debug)]
pub struct DatabaseMatch<'a, DS, F> {
    /// Label of the matched entry.
    pub label: &'a Label,
    /// The signature that matched, as written in the database.
    pub signature: &'a DS,
    /// Quality score derived from the tier the match landed in.
    pub quality: f32,
    /// The tolerance that was applied, when the match is not exact.
    pub fuzzy: Option<F>,
}

/// Represents a collection of database signatures of a specific type.
/// `OF` is the `ObservedFingerprint` type.
/// `DS` is the `DatabaseSignature` type that can be compared against `OF`.
pub trait FingerprintDb<OF: ObservedFingerprint, DS: DatabaseSignature<OF>> {
    /// Finds the best match for an observed fingerprint within this database.
    fn find_best_match(&self, observed: &OF) -> Option<DatabaseMatch<'_, DS, DS::Fuzziness>>;
}
