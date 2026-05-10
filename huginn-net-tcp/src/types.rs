//! Shared types for huginn-net-tcp.

/// Represents the quality of a match between an observed fingerprint and a database signature.
#[derive(Clone, Debug)]
pub enum MatchQualityType {
    /// Matched with a quality score between 0.05 (worst) and 1.0 (perfect).
    Matched(f32),
    NotMatched,
    Disabled,
}
