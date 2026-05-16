use crate::db_matching_trait::MatchQuality;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMatchQuality {
    High,
    Medium,
    Low,
}

impl TcpMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            TcpMatchQuality::High => 0,
            TcpMatchQuality::Medium => 1,
            TcpMatchQuality::Low => 2,
        }
    }
}

impl MatchQuality for TcpMatchQuality {
    // TCP has 9 components, each can contribute max 2 points (Low)
    const MAX_DISTANCE: u32 = 18;

    fn distance_to_score(distance: u32) -> f32 {
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3..=4 => 0.80,
            5..=6 => 0.70,
            7..=9 => 0.60,
            10..=12 => 0.40,
            13..=15 => 0.20,
            d if d <= Self::MAX_DISTANCE => 0.10,
            _ => 0.05,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub version: super::IpVersion,
    /// initial TTL used by the OS.
    pub ittl: super::Ttl,
    /// length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// window size.
    pub wsize: super::WindowSize,
    /// window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// layout and ordering of TCP options, if any.
    pub olayout: Vec<super::TcpOption>,
    /// properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<super::Quirk>,
    /// payload size classification
    pub pclass: super::PayloadSize,
}
