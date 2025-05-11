use crate::db::Label;
use std::fmt::{Debug, Display};

/// Represents a quality score for a match. Values (0.0 to 1.0), where 1.0 is a perfect match.
pub type MatchQuality = f32;

/// An observed fingerprint from live network traffic or a test case.
pub trait ObservedFingerprint: Clone + Debug {}

/// A fingerprint signature as defined in a database.
/// `OF` is the type of `ObservedFingerprint` that this database signature can be compared against.
pub trait DatabaseSignature<OF: ObservedFingerprint>: Clone + Debug + Display {
    /// Calculates a distance or dissimilarity score. Lower is better.
    fn calculate_distance(&self, observed: &OF) -> Option<u32>;
}

/// Marker trait for signature types that should use the generic (linear scan)
/// implementation of `FingerprintDb`. Specialized types (like TCP, HTTP)
/// will not implement this.
pub trait UseGenericFingerprintDbImpl {}

/// Represents a collection of database signatures of a specific type.
/// `OF` is the `ObservedFingerprint` type.
/// `DS` is the `DatabaseSignature` type that can be compared against `OF`.
pub trait FingerprintDb<OF: ObservedFingerprint, DS: DatabaseSignature<OF>> {
    /// Finds the best match for an observed fingerprint within this database.
    /// Returns the label of the match, the matching database signature, and a quality score.
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, MatchQuality)>;
}
