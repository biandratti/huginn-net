use sha2::{Digest, Sha256};
use std::fmt::{self};
use tracing::debug;

/// TLS version enumeration for fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
    Unknown(u16),
}

/// JA4 Ja4Payload structure following official FoxIO specification
#[derive(Debug, Clone, PartialEq)]
pub struct Ja4Payload {
    /// JA4_a: TLS version + SNI + cipher count + extension count + ALPN
    pub ja4_a: String,
    /// JA4_b: Cipher suites (sorted, normalized)
    pub ja4_b: String,
    /// JA4_c: Extensions (sorted, normalized) + signature algorithms
    pub ja4_c: String,
    /// Full JA4 Ja4Payload (a_b_c format)
    pub ja4_full: String,
    /// JA4 hash (SHA256 of full Ja4Payload, first 12 chars)
    pub ja4_hash: String,
}

/// See <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Check if a value is a GREASE value according to RFC 8701
fn is_grease_value(value: u16) -> bool {
    TLS_GREASE_VALUES.contains(&value)
}

/// Filter out GREASE values from a list of u16 values
fn filter_grease_values(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .filter(|&&v| !is_grease_value(v))
        .copied()
        .collect()
}

/// TLS ClientHello Signature
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub version: TlsVersion,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub elliptic_curve_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

impl Signature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    /// Format: JA4 = JA4_a + "_" + JA4_b_hash + "_" + JA4_c_hash
    /// Example: t13d1717h2_5b57614c22b0_3cbfd9057e0d
    pub fn generate_ja4(&self) -> Ja4Payload {
        todo!()
    }
}
