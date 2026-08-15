pub mod ip_options;
pub mod observable;
pub mod quirks;
pub mod syn_options;
pub mod ttl;
pub mod window_size;

pub use ip_options::IpOptions;
pub use observable::{ObservableTcp, TcpObservation};
pub use quirks::QuirkSet;
pub use syn_options::{parse_options_raw, ParsedTcpOptions};
pub use ttl::{calculate_ttl, guess_distance, observed_ttl, MAX_DIST};
pub use window_size::{detect_win_multi, WindowMultiplier};

use core::fmt;
use std::fmt::Formatter;

/// IP protocol version (or wildcard) seen in a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}

/// Time To Live (TTL) representation used for OS fingerprinting and
/// network-distance estimation.
#[derive(Clone, Debug, PartialEq)]
pub enum Ttl {
    /// Raw TTL value when we don't have enough context to determine the
    /// initial TTL.
    Value(u8),
    /// TTL with calculated network distance.
    /// First `u8` is the observed TTL value;
    /// second `u8` is the estimated number of hops
    /// (`distance = initial_ttl - observed_ttl`).
    Distance(u8, u8),
    /// TTL value that's been guessed based on common OS initial values
    /// (e.g. 64 for Linux, 128 for Windows).
    Guess(u8),
    /// Invalid or problematic TTL value (e.g. 0).
    Bad(u8),
}

/// TCP Window Size representation used for fingerprinting different TCP stacks.
#[derive(Clone, Debug, PartialEq)]
pub enum WindowSize {
    /// Window size is a multiple of MSS (Maximum Segment Size).
    /// The `u8` value is the multiplier (e.g. `Mss(4)` ⇒ window = MSS · 4).
    Mss(u8),
    /// Window size is a multiple of MTU.
    Mtu(u8),
    /// Raw window size value when it doesn't match any pattern.
    Value(u16),
    /// Window size follows a modulo pattern (e.g. `Mod(1024)` ⇒ window % 1024 == 0).
    Mod(u16),
    /// Wildcard matcher for any window size.
    Any,
}

/// One TCP option, in the order it appeared on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpOption {
    /// `eol+n`  - explicit end of options, followed by `n` bytes of padding.
    Eol(u8),
    /// `nop`    - no-op option.
    Nop,
    /// `mss`    - maximum segment size.
    Mss,
    /// `ws`     - window scaling.
    Ws,
    /// `sok`    - selective ACK permitted.
    Sok,
    /// `sack`   - selective ACK (should not be seen).
    Sack,
    /// `ts`     - timestamp.
    TS,
    /// `?n`     - unknown option ID `n`.
    Unknown(u8),
}

/// Deterministic FNV-1a hash of a TCP option layout, for index keys.
///
/// Stable across process runs (fixed seed). Used like p0f's `opt_hash`: bucket
/// by layout without allocating Display strings on the lookup path. Collisions
/// only widen a bucket; exact `olayout` equality in matching still filters.
pub fn hash_olayout(olayout: &[TcpOption]) -> u32 {
    const FNV_OFFSET: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET;
    for opt in olayout {
        let (tag, extra) = match *opt {
            TcpOption::Eol(n) => (0u8, Some(n)),
            TcpOption::Nop => (1, None),
            TcpOption::Mss => (2, None),
            TcpOption::Ws => (3, None),
            TcpOption::Sok => (4, None),
            TcpOption::Sack => (5, None),
            TcpOption::TS => (6, None),
            TcpOption::Unknown(n) => (7, Some(n)),
        };
        hash ^= u32::from(tag);
        hash = hash.wrapping_mul(FNV_PRIME);
        if let Some(byte) = extra {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

/// A protocol-level quirk observed in IP or TCP headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Quirk {
    /// `df`     - "don't fragment" set (probably PMTUD); ignored for IPv6.
    Df,
    /// `id+`    - DF set but IPID non-zero; ignored for IPv6.
    NonZeroID,
    /// `id-`    - DF not set but IPID is zero; ignored for IPv6.
    ZeroID,
    /// `ecn`    - explicit congestion notification support.
    Ecn,
    /// `0+`     - "must be zero" field not zero; ignored for IPv6.
    MustBeZero,
    /// `flow`   - non-zero IPv6 flow ID; ignored for IPv4.
    FlowID,
    /// `seq-`   - sequence number is zero.
    SeqNumZero,
    /// `ack+`   - ACK number is non-zero, but ACK flag not set.
    AckNumNonZero,
    /// `ack-`   - ACK number is zero, but ACK flag set.
    AckNumZero,
    /// `uptr+`  - URG pointer is non-zero, but URG flag not set.
    NonZeroURG,
    /// `urgf+`  - URG flag used.
    Urg,
    /// `pushf+` - PUSH flag used.
    Push,
    /// `ts1-`   - own timestamp specified as zero.
    OwnTimestampZero,
    /// `ts2+`   - non-zero peer timestamp on initial SYN.
    PeerTimestampNonZero,
    /// `opt+`   - trailing non-zero data in options segment.
    TrailinigNonZero,
    /// `exws`   - excessive window scaling factor (> 14).
    ExcessiveWindowScaling,
    /// `bad`    - malformed TCP options.
    OptBad,
}

/// Classification of TCP payload sizes used in fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadSize {
    /// No payload (empty). Common in SYN packets and some control messages.
    Zero,
    /// Packet contains data.
    NonZero,
    /// Wildcard for any payload size, used in signature matching.
    Any,
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------
//
// These produce the canonical p0f text form for each piece of a fingerprint.
// They live alongside the data types so consumers of the crate can render a
// fingerprint without pulling in the database.

impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IpVersion::V4 => "4",
            IpVersion::V6 => "6",
            IpVersion::Any => "*",
        })
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Ttl::Value(ttl) => write!(f, "{ttl}"),
            Ttl::Distance(ttl, distance) => write!(f, "{ttl}+{distance}"),
            Ttl::Guess(ttl) => write!(f, "{ttl}+?"),
            Ttl::Bad(ttl) => write!(f, "{ttl}-"),
        }
    }
}

impl fmt::Display for WindowSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WindowSize::Mss(n) => write!(f, "mss*{n}"),
            WindowSize::Mtu(n) => write!(f, "mtu*{n}"),
            WindowSize::Value(n) => write!(f, "{n}"),
            WindowSize::Mod(n) => write!(f, "%{n}"),
            WindowSize::Any => f.write_str("*"),
        }
    }
}

impl fmt::Display for TcpOption {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TcpOption::Eol(n) => write!(f, "eol+{n}"),
            TcpOption::Nop => f.write_str("nop"),
            TcpOption::Mss => f.write_str("mss"),
            TcpOption::Ws => f.write_str("ws"),
            TcpOption::Sok => f.write_str("sok"),
            TcpOption::Sack => f.write_str("sack"),
            TcpOption::TS => f.write_str("ts"),
            TcpOption::Unknown(n) => write!(f, "?{n}"),
        }
    }
}

impl fmt::Display for Quirk {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Quirk::Df => "df",
            Quirk::NonZeroID => "id+",
            Quirk::ZeroID => "id-",
            Quirk::Ecn => "ecn",
            Quirk::MustBeZero => "0+",
            Quirk::FlowID => "flow",
            Quirk::SeqNumZero => "seq-",
            Quirk::AckNumNonZero => "ack+",
            Quirk::AckNumZero => "ack-",
            Quirk::NonZeroURG => "uptr+",
            Quirk::Urg => "urgf+",
            Quirk::Push => "pushf+",
            Quirk::OwnTimestampZero => "ts1-",
            Quirk::PeerTimestampNonZero => "ts2+",
            Quirk::TrailinigNonZero => "opt+",
            Quirk::ExcessiveWindowScaling => "exws",
            Quirk::OptBad => "bad",
        })
    }
}

impl fmt::Display for PayloadSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PayloadSize::Zero => "0",
            PayloadSize::NonZero => "+",
            PayloadSize::Any => "*",
        })
    }
}
