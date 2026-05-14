use crate::db::HttpIndexKey;
use crate::db_matching_trait::ObservedFingerprint;
use crate::http::{Header, Version};

/// `TcpObservation` is owned by `huginn-net-tcp` (so the TCP crate stays
/// independent of any database). We re-export it here for convenience and
/// continuity with prior versions of the API.
pub use huginn_net_tcp::observable::TcpObservation;

/// Represents observed HTTP request characteristics from network traffic.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpRequestObservation {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic (p0f style).
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic (p0f style).
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

/// Represents observed HTTP response characteristics from network traffic.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpResponseObservation {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic (p0f style).
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic (p0f style).
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

// ==============================
// ObservedFingerprint - HTTP
// ==============================
impl ObservedFingerprint for HttpRequestObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}

impl ObservedFingerprint for HttpResponseObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}
