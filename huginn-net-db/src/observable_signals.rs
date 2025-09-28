use crate::db::HttpIndexKey;
use crate::db_matching_trait::ObservedFingerprint;
use crate::http::{Header, Version};
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};

/// Represents observed TCP characteristics from network traffic.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpObservation {
    /// IP version
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
        HttpIndexKey {
            http_version_key: self.version,
        }
    }
}

impl ObservedFingerprint for HttpResponseObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey {
            http_version_key: self.version,
        }
    }
}
