use sha2::{Digest, Sha256};
use std::fmt::{self};

/// TLS version enumeration for fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
    Unknown(u16),
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::V1_0 => write!(f, "10"),
            TlsVersion::V1_1 => write!(f, "11"),
            TlsVersion::V1_2 => write!(f, "12"),
            TlsVersion::V1_3 => write!(f, "13"),
            TlsVersion::Unknown(_) => write!(f, "00"),
        }
    }
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

/// Extract first and last characters from ALPN string, replacing non-ASCII with '9'
fn first_last_alpn(s: &str) -> (char, char) {
    let replace_nonascii_with_9 = |c: char| {
        if c.is_ascii() {
            c
        } else {
            '9'
        }
    };
    let mut chars = s.chars();
    let first = chars.next().map(replace_nonascii_with_9).unwrap_or('0');
    let last = chars
        .next_back()
        .map(replace_nonascii_with_9)
        .unwrap_or('0');
    (first, if s.len() == 1 { '0' } else { last })
}

/// Generate 12-character hash (first 12 chars of SHA256)
fn hash12(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))[..12].to_string()
}

impl Signature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    /// Format: JA4 = JA4_a + "_" + JA4_b_hash + "_" + JA4_c_hash
    pub fn generate_ja4(&self) -> Ja4Payload {
        // Filter out GREASE values from cipher suites for JA4_b and JA4_c processing
        let filtered_ciphers = filter_grease_values(&self.cipher_suites);
        let filtered_extensions = filter_grease_values(&self.extensions);
        let filtered_sig_algs = filter_grease_values(&self.signature_algorithms);

        // Protocol marker (always 't' for TLS, 'q' for QUIC)
        let protocol = "t";

        // TLS version
        let tls_version_str = format!("{}", self.version);

        // SNI indicator: 'd' if SNI present, 'i' if not
        let sni_indicator = if self.sni.is_some() { "d" } else { "i" };

        // Cipher count in 2-digit decimal (max 99) - use ORIGINAL count before filtering
        let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));

        // Extension count in 2-digit decimal (max 99) - use ORIGINAL count before filtering
        let extension_count = format!("{:02}", self.extensions.len().min(99));

        // ALPN first and last characters
        let (alpn_first, alpn_last) = match &self.alpn {
            Some(alpn) => first_last_alpn(alpn),
            None => ('0', '0'),
        };

        // JA4_a format: protocol + version + sni + cipher_count + extension_count + alpn_first + alpn_last
        let ja4_a = format!(
            "{}{}{}{}{}{}{}",
            protocol,
            tls_version_str,
            sni_indicator,
            cipher_count,
            extension_count,
            alpn_first,
            alpn_last
        );

        // JA4_b: Cipher suites (sorted, comma-separated, 4-digit hex) - GREASE filtered
        let mut sorted_ciphers = filtered_ciphers;
        sorted_ciphers.sort_unstable();
        let ja4_b_raw = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<String>>()
            .join(",");

        // JA4_c: Extensions (sorted, comma-separated, 4-digit hex) + "_" + signature algorithms
        // According to official spec: Remove SNI (0x0000) and ALPN (0x0010) from extensions for JA4_c
        // AND filter GREASE values
        let mut extensions_for_c = filtered_extensions.clone();
        extensions_for_c.retain(|&ext| ext != 0x0000 && ext != 0x0010);
        extensions_for_c.sort_unstable();

        let extensions_str = extensions_for_c
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<String>>()
            .join(",");

        // Signature algorithms are NOT sorted according to the official spec
        // But GREASE values are filtered
        let sig_algs_str = filtered_sig_algs
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<String>>()
            .join(",");

        // According to the specification, "if there are no signature algorithms in the
        // Hello packet, then the string ends without an underscore".
        let ja4_c_raw = if sig_algs_str.is_empty() {
            extensions_str.clone()
        } else if extensions_str.is_empty() {
            sig_algs_str.clone()
        } else {
            format!("{}_{}", extensions_str, sig_algs_str)
        };

        // Generate hashes for JA4_b and JA4_c (first 12 characters of SHA256)
        let ja4_b_hash = hash12(&ja4_b_raw);
        let ja4_c_hash = hash12(&ja4_c_raw);

        let ja4_full = format!("{}_{}_{}", ja4_a, ja4_b_raw, ja4_c_raw);
        let mut ja4_hash = ja4_a.clone();
        ja4_hash.push('_');
        ja4_hash.push_str(&ja4_b_hash);
        ja4_hash.push('_');
        ja4_hash.push_str(&ja4_c_hash);

        Ja4Payload {
            ja4_a,
            ja4_b: ja4_b_raw,
            ja4_c: ja4_c_raw,
            ja4_full,
            ja4_hash,
        }
    }
}
