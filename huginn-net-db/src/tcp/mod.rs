//! TCP signature and field-comparison helpers for the p0f database.
//!
//! Pure data types ([`IpVersion`], [`Ttl`], [`WindowSize`], [`TcpOption`],
//! [`Quirk`], [`PayloadSize`]) are re-exported from `huginn-net-tcp`. This
//! module owns the **database-specific** pieces.

pub use huginn_net_tcp::tcp::{
    IpVersion, PayloadSize, Quirk, QuirkSet, TcpOption, Ttl, WindowSize,
};

mod coverage;
mod distances;
mod matching;
mod signature;

pub use coverage::{AmbiguousExactPair, ambiguous_exact_pairs, warn_ambiguous_coverage};
pub use distances::{
    MAX_TTL_DISTANCE, TtlFit, ip_version_matches, payload_size_matches, report_hop_distance,
    ttl_fit, window_size_matches,
};
pub use signature::Signature;
