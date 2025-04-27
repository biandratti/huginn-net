#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub version: IpVersion,
    /// initial TTL used by the OS.
    pub ittl: Ttl,
    /// length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// window size.
    pub wsize: WindowSize,
    /// window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<Quirk>,
    /// payload size classification
    pub pclass: PayloadSize,
}

impl Signature {

    fn distance_olen(&self, other: &Self) -> Option<u32> {
        if self.olen == other.olen {
            Some(0)
        } else {
            Some(5)
        }
    }

    fn distance_mss(&self, other: &Self) -> Option<u32> {
        if other.mss.is_none() {
            Some(0) // TODO: analize if is not better to return 1 to avoid lack of quality
        } else {            
            if self.mss == other.mss {
                Some(0)
            } else {
                Some(5)
            }
        }
    }

    fn distance_wscale(&self, other: &Self) -> Option<u32> {
        if other.wscale.is_none() {
            Some(0) // TODO: analize if is not better to return 1 to avoid lack of quality
        } else {            
            if self.wscale == other.wscale {
                Some(0)
            } else {
                Some(5)
            }
        }
    }

    fn distance_olayout(&self, other: &Self) -> Option<u32> {
        if self.olayout == other.olayout {
            Some(0)
        } else {
            None
        }
    }

    fn distance_quirks(&self, other: &Self) -> Option<u32> {
        if self.quirks == other.quirks {
            Some(0)
        } else {
            None
        }
    }

    // Function to calculate the distance between two signatures
    fn calculate_distance(&self, other: &Self) -> Option<u32> {

        let distance = self.version.distance_ip_version(&other.version)?
            + self.ittl.distance_ttl(&other.ittl)?  
            + self.distance_olen(other)?
            + self.distance_mss(&other)?
            + self.wsize.distance_window_size(&other.wsize, self.mss)?
            + self.distance_wscale(&other)?
            + self.distance_olayout(&other)?
            + self.distance_quirks(&other)?
            + self.pclass.distance_payload_size(&other.pclass)?;

        Some(distance)
    }

    pub fn find_closest_signature<'a>(&self, db_signatures: &'a [Self]) -> Option<&'a Self> {
        let mut closest_signature = None;
        let mut min_distance = u32::MAX;

        for db_signature in db_signatures {
            if let Some(distance) = self.calculate_distance(db_signature) {
                if distance < min_distance {
                    min_distance = distance;
                    closest_signature = Some(db_signature);
                }
            }
        }

        closest_signature
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}
impl IpVersion {

    pub fn distance_ip_version(&self, other: &IpVersion) -> Option<u32> {
        if other == &IpVersion::Any {
            Some(0) // TODO: analize if is not better to return 1 to avoid lack of quality
        } else {
            match (self, other) {
                (IpVersion::V4, IpVersion::V4) | (IpVersion::V6, IpVersion::V6) => Some(0),
                _ => None,
            }
        }
    }
}

/// Time To Live (TTL) representation used for OS fingerprinting and network distance calculation
#[derive(Clone, Debug, PartialEq)]
pub enum Ttl {
    /// Raw TTL value when we don't have enough context to determine initial TTL
    /// Contains the observed TTL value from the IP header
    Value(u8),

    /// TTL with calculated network distance
    /// First u8 is the observed TTL value
    /// Second u8 is the estimated number of hops (distance = initial_ttl - observed_ttl)
    Distance(u8, u8),

    /// TTL value that's been guessed based on common OS initial values
    /// Contains the estimated initial TTL (e.g., 64 for Linux, 128 for Windows)
    Guess(u8),

    /// Invalid or problematic TTL value
    /// Contains the raw TTL value that was deemed invalid (e.g., 0)
    Bad(u8),
}

impl Ttl {
    // pub fn matches_ttl(&self, other: &Ttl) -> bool {
    //     match (self, other) {
    //         (Ttl::Value(a), Ttl::Value(b)) => a == b,
    //         (Ttl::Distance(a1, a2), Ttl::Distance(b1, b2)) => a1 == b1 && a2 == b2,
    //         (Ttl::Distance(a1, _a2), Ttl::Value(b1)) => a1 == b1,
    //         (Ttl::Guess(a), Ttl::Guess(b)) => a == b,
    //         (Ttl::Bad(a), Ttl::Bad(b)) => a == b,
    //         (Ttl::Guess(a), Ttl::Value(b)) => a == b,
    //         (Ttl::Value(a), Ttl::Guess(b)) => a == b,
    //         _ => false,
    //     }
    // }

    // Function to calculate the distance between two TTL values
    pub fn distance_ttl(&self, other: &Ttl) -> Option<u32> {
        match (self, other) {
            (Ttl::Value(a), Ttl::Value(b)) => {
                if a == b {
                    Some(0)
                } else {
                    Some(((*a as i32) - (*b as i32)).abs() as u32)
                }
            }
            (Ttl::Distance(a1, a2), Ttl::Distance(b1, b2)) => {
                if a1 == b1 && a2 == b2 {
                    Some(0)
                } else {
                    Some(5)
                }
            }
            (Ttl::Distance(a1, _), Ttl::Value(b1)) => {
                if a1 == b1 {
                    Some(0)
                } else {
                    Some(5)
                }
            }
            (Ttl::Guess(a), Ttl::Guess(b)) => {
                if a == b {
                    Some(0)
                } else {
                    Some(5)
                }
            }
            (Ttl::Bad(a), Ttl::Bad(b)) => {
                if a == b {
                    Some(0)
                } else {
                    Some(5)
                }
            }
            (Ttl::Guess(_), Ttl::Value(_)) | (Ttl::Value(_), Ttl::Guess(_)) => {
                Some(5)
            }
            _ => None,
        }
    }
}

/// TCP Window Size representation used for fingerprinting different TCP stacks
#[derive(Clone, Debug, PartialEq)]
pub enum WindowSize {
    /// Window size is a multiple of MSS (Maximum Segment Size)
    /// The u8 value represents the multiplier (e.g., Mss(4) means window = MSS * 4)
    Mss(u8),

    /// Window size is a multiple of MTU (Maximum Transmission Unit)
    /// The u8 value represents the multiplier (e.g., Mtu(4) means window = MTU * 4)
    Mtu(u8),

    /// Raw window size value when it doesn't match any pattern
    /// Contains the actual window size value from the TCP header
    Value(u16),

    /// Window size follows a modulo pattern
    /// The u16 value represents the modulo base (e.g., Mod(1024) means window % 1024 == 0)
    Mod(u16),

    /// Represents any window size (wildcard matcher)
    Any,
}

impl WindowSize {
    // pub fn matches_window_size(&self, other: &WindowSize, mss: Option<u16>) -> bool {
    //     match (self, other) {
    //         (WindowSize::Mss(a), WindowSize::Mss(b)) => a == b,
    //         (WindowSize::Mtu(a), WindowSize::Mtu(b)) => a == b,
    //         (WindowSize::Value(a), WindowSize::Value(b)) => a == b,
    //         (WindowSize::Value(a), WindowSize::Mss(b)) => {
    //             if let Some(mss_value) = mss {
    //                 let ratio_self = a / mss_value;
    //                 ratio_self == *b as u16
    //             } else {
    //                 false
    //             }
    //         }
    //         (WindowSize::Mss(a), WindowSize::Value(b)) => {
    //             if let Some(mss_value) = mss {
    //                 let ratio_other = b / mss_value;
    //                 *a as u16 == ratio_other
    //             } else {
    //                 false
    //             }
    //         }
    //         (WindowSize::Mod(a), WindowSize::Mod(b)) => a == b,
    //         (_, WindowSize::Any) => true,
    //         _ => false,
    //     }
    // }

    // Function to calculate the distance between two window sizes
    pub fn distance_window_size(&self, other: &WindowSize, mss: Option<u16>) -> Option<u32> {
        match (self, other) {
            (WindowSize::Mss(a), WindowSize::Mss(b)) => {
                if a == b {
                    Some(0)
                } else {
                    None
                }
            }
            (WindowSize::Mtu(a), WindowSize::Mtu(b)) => {   
                if a == b {
                    Some(0)
                } else {
                    None    
                }
            }
            (WindowSize::Value(a), WindowSize::Value(b)) => {
                if a == b {
                    Some(0)
                } else {
                    None
                }
            }
           (WindowSize::Value(a), WindowSize::Mss(b)) => {
                if let Some(mss_value) = mss {
                    let ratio_self = a / mss_value;
                    if ratio_self == *b as u16 {
                        Some(0)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            (WindowSize::Mss(a), WindowSize::Value(b)) => {
                if let Some(mss_value) = mss {
                    let ratio_other = b / mss_value;
                    if *a as u16 == ratio_other {
                        Some(0)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            (WindowSize::Mod(a), WindowSize::Mod(b)) => {
                if a == b {
                    Some(0)
                } else {
                    None
                }
            }
            (_, WindowSize::Any) | (WindowSize::Any, _) => Some(0),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TcpOption {
    /// eol+n  - explicit end of options, followed by n bytes of padding
    Eol(u8),
    /// nop    - no-op option
    Nop,
    /// mss    - maximum segment size
    Mss,
    /// ws     - window scaling
    Ws,
    /// sok    - selective ACK permitted
    Sok,
    /// sack   - selective ACK (should not be seen)
    Sack,
    /// ts     - timestamp
    TS,
    /// ?n     - unknown option ID n
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Quirk {
    /// df     - "don't fragment" set (probably PMTUD); ignored for IPv6
    Df,
    /// id+    - DF set but IPID non-zero; ignored for IPv6
    NonZeroID,
    /// id-    - DF not set but IPID is zero; ignored for IPv6
    ZeroID,
    /// ecn    - explicit congestion notification support
    Ecn,
    /// 0+     - "must be zero" field not zero; ignored for IPv6
    MustBeZero,
    /// flow   - non-zero IPv6 flow ID; ignored for IPv4
    FlowID,
    /// seq-   - sequence number is zero
    SeqNumZero,
    /// ack+   - ACK number is non-zero, but ACK flag not set
    AckNumNonZero,
    /// ack-   - ACK number is zero, but ACK flag set
    AckNumZero,
    /// uptr+  - URG pointer is non-zero, but URG flag not set
    NonZeroURG,
    /// urgf+  - URG flag used
    Urg,
    /// pushf+ - PUSH flag used
    Push,
    /// ts1-   - own timestamp specified as zero
    OwnTimestampZero,
    /// ts2+   - non-zero peer timestamp on initial SYN
    PeerTimestampNonZero,
    /// opt+   - trailing non-zero data in options segment
    TrailinigNonZero,
    /// exws   - excessive window scaling factor (> 14)
    ExcessiveWindowScaling,
    /// bad    - malformed TCP options
    OptBad,
}

/// Classification of TCP payload sizes used in fingerprinting
#[derive(Clone, Debug, PartialEq)]
pub enum PayloadSize {
    /// Packet has no payload (empty)
    /// Common in SYN packets and some control messages
    Zero,

    /// Packet contains data in the payload
    /// Typical for data transfer packets
    NonZero,

    /// Matches any payload size
    /// Used as a wildcard in signature matching
    Any,
}

impl PayloadSize {

    pub fn distance_payload_size(&self, other: &PayloadSize) -> Option<u32> {
        if other == &PayloadSize::Any {
            Some(0) // TODO: analize if is not better to return 1 to avoid lack of quality
        } else if self == other {
            Some(0)
        } else {
            None
        }
    }

}
