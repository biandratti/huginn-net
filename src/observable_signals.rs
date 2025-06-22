use crate::http::{Header, Version};
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, WindowSize};
use crate::tls::{Ja4Payload, TlsVersion};
use crate::Ttl;

// Observable TCP signals
#[derive(Debug, Clone)]
pub struct ObservableTcp {
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

// Observable TLS Client signals
#[derive(Debug, Clone)]
pub struct ObservableTlsClient {
    /// TLS version from ClientHello
    pub version: TlsVersion,
    /// Server Name Indication (SNI) if present
    pub sni: Option<String>,
    /// Application-Layer Protocol Negotiation (ALPN) if present
    pub alpn: Option<String>,
    /// Cipher suites from ClientHello
    pub cipher_suites: Vec<u16>,
    /// Extensions from ClientHello
    pub extensions: Vec<u16>,
    /// Signature algorithms from extensions
    pub signature_algorithms: Vec<u16>,
    /// Elliptic curves from extensions
    pub elliptic_curves: Vec<u16>,
    /// Generated JA4 fingerprint from ClientHello
    pub ja4: Ja4Payload,
    /// Generated JA4 fingerprint from original ClientHello
    pub ja4_original: Ja4Payload,
}

// Observable HTTP signals
#[derive(Debug, Clone)]
pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

// Observable HTTP response signals
#[derive(Debug, Clone)]
pub struct ObservableHttpResponse {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

// Observable MTU signals
pub struct ObservableMtu {
    pub value: u16,
}

// Observable Uptime signals
pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}
