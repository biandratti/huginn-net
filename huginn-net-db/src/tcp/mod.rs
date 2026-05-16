//! TCP signature, scoring, and distance helpers for the p0f database.
//!
//! Pure data types ([`IpVersion`], [`Ttl`], [`WindowSize`], [`TcpOption`],
//! [`Quirk`], [`PayloadSize`]) are re-exported from `huginn-net-tcp`. This
//! module owns the **database-specific** pieces.

pub use huginn_net_tcp::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};

mod distances;
mod signature;

pub use distances::{
    distance_ip_version, distance_payload_size, distance_ttl, distance_window_size,
};
pub use signature::{Signature, TcpMatchQuality};
