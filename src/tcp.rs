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
    pub fn matches(&self, db_signature: &Self) -> bool {
        self.version.matches_ip_version(&db_signature.version)
            && self.ittl.matches_ttl(&db_signature.ittl)
            && self.olen == db_signature.olen
            && (self.mss == db_signature.mss || db_signature.mss.is_none())
            && self.wsize.matches_window_size(&db_signature.wsize)
            && (self.wscale == db_signature.wscale || db_signature.wscale.is_none())
            && self.olayout == db_signature.olayout
            && self.quirks == db_signature.quirks
            && self.pclass.matches_payload_size(&db_signature.pclass)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}
impl IpVersion {
    pub fn matches_ip_version(&self, other: &IpVersion) -> bool {
        matches!(
            (self, other),
            (IpVersion::V4, IpVersion::V4) | (IpVersion::V6, IpVersion::V6) | (_, IpVersion::Any)
        )
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
    pub fn matches_ttl(&self, other: &Ttl) -> bool {
        match (self, other) {
            (Ttl::Value(a), Ttl::Value(b)) => a == b,
            (Ttl::Distance(a1, a2), Ttl::Distance(b1, b2)) => a1 == b1 && a2 == b2,
            (Ttl::Distance(a1, _a2), Ttl::Value(b1)) => a1 == b1,
            (Ttl::Guess(a), Ttl::Guess(b)) => a == b,
            (Ttl::Bad(a), Ttl::Bad(b)) => a == b,
            (Ttl::Guess(a), Ttl::Value(b)) => a == b,
            (Ttl::Value(a), Ttl::Guess(b)) => a == b,
            _ => false,
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
    pub fn matches_window_size(&self, other: &WindowSize) -> bool {
        match (self, other) {
            (WindowSize::Mss(a), WindowSize::Mss(b)) => a == b,
            (WindowSize::Mtu(a), WindowSize::Mtu(b)) => a == b,
            (WindowSize::Value(a), WindowSize::Value(b)) => a == b,
            (WindowSize::Mod(a), WindowSize::Mod(b)) => a == b,
            // (WindowSize::Mod(mod_val), WindowSize::Value(val))
            // | (WindowSize::Value(val), WindowSize::Mod(mod_val)) => val % mod_val == 0,
            (_, WindowSize::Any) => true,
            _ => false,
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
    pub fn matches_payload_size(&self, other: &PayloadSize) -> bool {
        matches!(
            (self, other),
            (PayloadSize::Zero, PayloadSize::Zero)
                | (PayloadSize::NonZero, PayloadSize::NonZero)
                | (_, PayloadSize::Any)
        )
    }
}
