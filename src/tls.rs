use sha2::{Digest, Sha256};
use std::fmt;

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
            TlsVersion::V1_0 => write!(f, "TLS 1.0"),
            TlsVersion::V1_1 => write!(f, "TLS 1.1"),
            TlsVersion::V1_2 => write!(f, "TLS 1.2"),
            TlsVersion::V1_3 => write!(f, "TLS 1.3"),
            TlsVersion::Unknown(v) => write!(f, "TLS Unknown(0x{:04x})", v),
        }
    }
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
    /// JA4_a: TLS version + SNI + cipher count + extension count
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
}

impl TlsSignature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    /// Format: JA4 = TLS_VERSION + SNI + CIPHER_COUNT + EXTENSION_COUNT + "_" + CIPHERS + "_" + EXTENSIONS + SIGNATURE_ALGORITHMS
    pub fn generate_ja4(&self) -> Ja4Fingerprint {
        // JA4_a: TLS version (2 chars) + SNI (d/i) + cipher count (2 hex) + extension count (2 hex)
        let tls_version_str = match self.version {
            TlsVersion::V1_0 => "10",
            TlsVersion::V1_1 => "11", 
            TlsVersion::V1_2 => "12",
            TlsVersion::V1_3 => "13",
            TlsVersion::Unknown(_) => "00",
        };

        let sni_indicator = if self.sni.is_some() { "d" } else { "i" };
        
        // Cipher count in 2-digit hex (max 99 -> "63" in hex)
        let cipher_count = format!("{:02x}", self.cipher_suites.len().min(99));
        
        // Extension count in 2-digit hex (max 99 -> "63" in hex)  
        let extension_count = format!("{:02x}", self.extensions.len().min(99));
        
        let ja4_a = format!("{}{}{}{}", tls_version_str, sni_indicator, cipher_count, extension_count);

        // JA4_b: Cipher suites (sorted, comma-separated, 4-digit hex)
        let mut sorted_ciphers = self.cipher_suites.clone();
        sorted_ciphers.sort_unstable();
        let ja4_b = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");

        // JA4_c: Extensions (sorted, comma-separated, 4-digit hex) + "_" + signature algorithms
        let mut sorted_extensions = self.extensions.clone();
        // Remove SNI (0x0000) and ALPN (0x0010) from extensions for JA4_c as per spec
        sorted_extensions.retain(|&ext| ext != 0x0000 && ext != 0x0010);
        sorted_extensions.sort_unstable();
        
        let extensions_str = sorted_extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");

        let mut sorted_sig_algs = self.signature_algorithms.clone();
        sorted_sig_algs.sort_unstable();
        let sig_algs_str = sorted_sig_algs
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");

        let ja4_c = if sig_algs_str.is_empty() {
            extensions_str
        } else if extensions_str.is_empty() {
            sig_algs_str
        } else {
            format!("{}_{}", extensions_str, sig_algs_str)
        };

        // Full JA4 fingerprint in a_b_c format
        let ja4_full = format!("{}_{}_{}", ja4_a, ja4_b, ja4_c);
        
        // Generate SHA256 hash and take first 12 characters
        let ja4_hash = format!("{:x}", Sha256::digest(ja4_full.as_bytes()));
        let ja4_hash_short = ja4_hash[..12].to_string();

        Ja4Fingerprint {
            ja4_a,
            ja4_b,
            ja4_c,
            ja4_full,
            ja4_hash: ja4_hash_short,
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