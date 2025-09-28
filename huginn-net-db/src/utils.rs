/// Represents the quality of a match between an observed fingerprint and a database signature.
#[derive(Clone, Debug)]
pub enum MatchQualityType {
    Matched(f32), // 0.05 to 1.0 (quality score: 1.0 = perfect match, 0.05 = worst match)
    NotMatched,
    Disabled,
}
