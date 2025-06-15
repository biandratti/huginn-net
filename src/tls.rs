use std::fmt::{self, Display};
use sha2::{Sha256, Digest};
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

impl From<u16> for TlsVersion {
    fn from(version: u16) -> Self {
        match version {
            0x0301 => TlsVersion::V1_0,
            0x0302 => TlsVersion::V1_1,
            0x0303 => TlsVersion::V1_2,
            0x0304 => TlsVersion::V1_3,
            v => TlsVersion::Unknown(v),
        }
    }
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

/// GREASE values according to RFC 8701
const TLS_GREASE_VALUES_INT: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Check if a value is a GREASE value according to RFC 8701
fn is_grease_value(value: u16) -> bool {
    TLS_GREASE_VALUES_INT.contains(&value)
}

/// Filter out GREASE values from a list of u16 values
fn filter_grease_values(values: &[u16]) -> Vec<u16> {
    values.iter().filter(|&&v| !is_grease_value(v)).copied().collect()
}

/// Generate 12-character hash (first 12 chars of SHA256)
fn hash12(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))[..12].to_string()
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
    let last = chars.next_back().map(replace_nonascii_with_9).unwrap_or('0');
    (first, if s.len() == 1 { '0' } else { last })
}

/// TLS Extension representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

/// JA4 Fingerprint structure following official FoxIO specification
#[derive(Debug, Clone, PartialEq)]
pub struct Ja4Fingerprint {
    /// JA4_a: TLS version + SNI + cipher count + extension count + ALPN
    pub ja4_a: String,
    /// JA4_b: Cipher suites (sorted, normalized)
    pub ja4_b: String,
    /// JA4_c: Extensions (sorted, normalized) + signature algorithms
    pub ja4_c: String,
    /// Full JA4 fingerprint (a_b_c format)
    pub ja4_full: String,
    /// JA4 hash (SHA256 of full fingerprint, first 12 chars)
    pub ja4_hash: String,
}

/// TLS ClientHello signature for fingerprinting
#[derive(Debug, Clone, PartialEq)]
pub struct TlsSignature {
    pub version: TlsVersion,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub elliptic_curve_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

impl TlsSignature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    /// Format: JA4 = JA4_a + "_" + JA4_b_hash + "_" + JA4_c_hash
    /// Example: t13d1717h2_5b57614c22b0_3cbfd9057e0d
    pub fn generate_ja4(&self) -> Ja4Fingerprint {
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
        // According to official spec, count includes GREASE values
        let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));
        
        // Extension count in 2-digit decimal (max 99) - use ORIGINAL count before filtering  
        // According to official spec, count includes GREASE values
        let extension_count = format!("{:02}", self.extensions.len().min(99));
        
        // ALPN first and last characters
        let (alpn_first, alpn_last) = match &self.alpn {
            Some(alpn) => first_last_alpn(alpn),
            None => ('0', '0'),
        };

        // JA4_a format: protocol + version + sni + cipher_count + extension_count + alpn_first + alpn_last
        let ja4_a = format!("{}{}{}{}{}{}{}", 
            protocol, tls_version_str, sni_indicator, cipher_count, extension_count, alpn_first, alpn_last);

        // JA4_b: Cipher suites (sorted, comma-separated, 4-digit hex) - GREASE filtered
        let mut sorted_ciphers = filtered_ciphers;
        sorted_ciphers.sort_unstable();
        let ja4_b_raw = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
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
            .collect::<Vec<_>>()
            .join(",");

        // Signature algorithms are NOT sorted according to the official spec
        // But GREASE values are filtered
        let sig_algs_str = filtered_sig_algs.clone()
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
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

        // Debug JA4_c calculation
        debug!("JA4_C DEBUG - Original extensions: {:04x?}", self.extensions);
        debug!("JA4_C DEBUG - Filtered extensions: {:04x?}", filtered_extensions);
        debug!("JA4_C DEBUG - Extensions for JA4_c (no SNI/ALPN): {:04x?}", extensions_for_c);
        debug!("JA4_C DEBUG - Extensions string: '{}'", extensions_str);
        debug!("JA4_C DEBUG - Original signature algorithms: {:04x?}", self.signature_algorithms);
        debug!("JA4_C DEBUG - Filtered signature algorithms: {:04x?}", filtered_sig_algs);
        debug!("JA4_C DEBUG - Signature algorithms string: '{}'", sig_algs_str);
        debug!("JA4_C DEBUG - Full JA4_c raw: '{}'", ja4_c_raw);
        debug!("JA4_C DEBUG - JA4_c hash: '{}'", ja4_c_hash);

        // Final JA4 fingerprint in official format
        let ja4_full = format!("{}_{}_{}_{}", ja4_a, ja4_b_raw, ja4_c_raw, "");
        let ja4_hash = format!("{}_{}_{}",ja4_a, ja4_b_hash, ja4_c_hash);

        Ja4Fingerprint {
            ja4_a,
            ja4_b: ja4_b_raw,
            ja4_c: ja4_c_raw,
            ja4_full,
            ja4_hash,
        }
    }
}

/// Quality matching for TLS fingerprints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMatchQuality {
    High,
    Medium,
    Low,
}

impl TlsMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            TlsMatchQuality::High => 0,
            TlsMatchQuality::Medium => 1,
            TlsMatchQuality::Low => 2,
        }
    }
}

impl crate::db_matching_trait::MatchQuality for TlsMatchQuality {
    const MAX_DISTANCE: u32 = 10; // TLS has fewer components than TCP

    fn distance_to_score(distance: u32) -> f32 {
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3..=4 => 0.80,
            5..=6 => 0.70,
            7..=8 => 0.60,
            d if d <= Self::MAX_DISTANCE => 0.40,
            _ => 0.20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        // Test known GREASE values
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0x2a2a));
        assert!(is_grease_value(0x3a3a));
        assert!(is_grease_value(0x4a4a));
        assert!(is_grease_value(0x5a5a));
        assert!(is_grease_value(0x6a6a));
        assert!(is_grease_value(0x7a7a));
        assert!(is_grease_value(0x8a8a));
        assert!(is_grease_value(0x9a9a));
        assert!(is_grease_value(0xaaaa));
        assert!(is_grease_value(0xbaba));
        assert!(is_grease_value(0xcaca));
        assert!(is_grease_value(0xdada));
        assert!(is_grease_value(0xeaea));
        assert!(is_grease_value(0xfafa));

        // Test non-GREASE values
        assert!(!is_grease_value(0x0000));
        assert!(!is_grease_value(0x1301));
        assert!(!is_grease_value(0x002f));
        assert!(!is_grease_value(0xc02f));
        assert!(!is_grease_value(0x0a0b)); // Different nibbles
    }

    #[test]
    fn test_grease_filtering() {
        let values = vec![0x002f, 0x1a1a, 0x1301, 0x5a5a, 0xc02f, 0xaaaa];
        let filtered = filter_grease_values(&values);
        assert_eq!(filtered, vec![0x002f, 0x1301, 0xc02f]);
    }

    #[test]
    fn test_first_last_alpn() {
        assert_eq!(first_last_alpn(""), ('0', '0'));
        assert_eq!(first_last_alpn("h"), ('h', '0'));
        assert_eq!(first_last_alpn("h2"), ('h', '2'));
        assert_eq!(first_last_alpn("http/1.1"), ('h', '1'));
    }

    #[test]
    fn test_ja4_generation() {
        // Test case from official FoxIO implementation
        let signature = TlsSignature {
            version: TlsVersion::V1_3,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
            extensions: vec![0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015],
            elliptic_curves: vec![],
            elliptic_curve_point_formats: vec![],
            signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            sni: Some("example.com".to_string()),
            alpn: Some("h2".to_string()),
        };

        let ja4 = signature.generate_ja4();
        assert_eq!(ja4.ja4_hash, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }
} 