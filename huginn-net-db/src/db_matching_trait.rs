use crate::db::Label;
use std::fmt::Debug;
use std::hash::Hash;

/// An observed fingerprint from live network traffic or a test case.
pub trait ObservedFingerprint: Clone + Debug {
    /// The type of key used to index database signatures compatible with this observed fingerprint.
    type Key: IndexKey;

    /// Generates an index key from this observed fingerprint.
    fn generate_index_key(&self) -> Self::Key;
}

/// A fingerprint signature as defined in a database.
/// `OF` is the type of `ObservedFingerprint` that this database signature can be compared against.
pub trait DatabaseSignature<OF: ObservedFingerprint> {
    /// Calculates a distance or dissimilarity score. Lower is better.
    fn calculate_distance(&self, observed: &OF) -> Option<u32>;

    /// Returns the quality score based on the distance.
    fn get_quality_score(&self, distance: u32) -> f32;

    /// Generates index keys from this database signature.
    /// It's a Vec because some DB signatures (like IpVersion::Any) might map to multiple keys.
    /// The Option<OF::Key> in the Vec allows for cases where a specific DB sig might not produce a key
    /// for a certain specific version (e.g. an IpVersion::Any sig, when asked to produce a V4 key, will).
    fn generate_index_keys_for_db_entry(&self) -> Vec<OF::Key>;
}

/// Base trait for keys used in fingerprint indexes.
pub trait IndexKey: Debug + Clone + Eq + Hash {}

/// Represents a collection of database signatures of a specific type.
/// `OF` is the `ObservedFingerprint` type.
/// `DS` is the `DatabaseSignature` type that can be compared against `OF`.
pub trait FingerprintDb<OF: ObservedFingerprint, DS: DatabaseSignature<OF>> {
    /// Finds the best match for an observed fingerprint within this database.
    /// Returns the label of the match, the matching database signature, and a quality score.
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, f32)>;
}

pub trait MatchQuality {
    /// Maximum possible distance for this quality type
    const MAX_DISTANCE: u32;

    /// Converts distance to a quality score between 0.0 and 1.0
    fn distance_to_score(distance: u32) -> f32;
}
