//! Index keys for fingerprint database lookups.

#[cfg(any(feature = "tcp", feature = "http"))]
use crate::db_matching_trait::IndexKey;
#[cfg(feature = "tcp")]
use crate::tcp::{IpVersion, PayloadSize};
#[cfg(feature = "http")]
use huginn_net_http::http::Version as HttpVersion;

/// Index key for TCP signatures, used to optimize database lookups.
///
/// `olayout_hash` is [`huginn_net_tcp::tcp::hash_olayout`] of the option layout
/// (p0f's `opt_hash` role). The key is `Copy` so lookups allocate nothing.
#[cfg(feature = "tcp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpIndexKey {
    pub ip_version_key: IpVersion,
    pub olayout_hash: u32,
    pub pclass_key: PayloadSize,
}

#[cfg(feature = "tcp")]
impl IndexKey for TcpIndexKey {}

/// Index key for HTTP signatures, used to optimize database lookups.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpIndexKey {
    pub http_version_key: HttpVersion,
}

#[cfg(feature = "http")]
impl IndexKey for HttpIndexKey {}
