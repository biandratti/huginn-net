use crate::tls::{Ja4Payload, TlsVersion};

/// Observable TLS Client signals
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

/// Result of TLS packet processing
#[derive(Debug)]
pub struct ObservableTlsPackage {
    pub tls_client: Option<ObservableTlsClient>,
}
