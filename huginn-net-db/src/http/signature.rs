use crate::db_matching_trait::MatchQuality;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// HTTP version
    pub version: super::Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<super::Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<super::Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMatchQuality {
    High,
    Medium,
    Low,
    Bad,
}

impl HttpMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            HttpMatchQuality::High => 0,
            HttpMatchQuality::Medium => 1,
            HttpMatchQuality::Low => 2,
            HttpMatchQuality::Bad => 3,
        }
    }
}

impl MatchQuality for HttpMatchQuality {
    // HTTP has 4 components, each can contribute max 3 points (Bad)
    const MAX_DISTANCE: u32 = 12;

    fn distance_to_score(distance: u32) -> f32 {
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3 => 0.80,
            4..=5 => 0.70,
            6..=7 => 0.60,
            8..=9 => 0.40,
            10..=11 => 0.20,
            d if d <= Self::MAX_DISTANCE => 0.10,
            _ => 0.05,
        }
    }
}
