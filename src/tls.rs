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
    /// JA4 Raw Ja4Payload (a_b_c format)
    pub ja4_raw: String,
    /// JA4 hash (SHA256 of full Ja4Payload, first 12 chars)
    pub ja4_hash: String,
    /// JA4_original (original order) Raw: Original JA4 (a_b_c format)
    pub ja4_original_raw: String,
    /// JA4_original_hash (original order): SHA256 of JA4_original_full, first 12 chars
    pub ja4_original_hash: String,
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
        let mut sorted_ciphers = filtered_ciphers.clone();
        sorted_ciphers.sort_unstable();
        let ja4_b_raw = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<String>>()
            .join(",");

        // JA4_b_original: Cipher suites in original order for JA4_o
        let ja4_b_original_raw = filtered_ciphers
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

        // JA4_original (JA4_o): Keep original order and include SNI/ALPN
        // Extensions for JA4_original: keep original order, DO NOT remove SNI/ALPN, still filter GREASE
        let extensions_original_str = filtered_extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<String>>()
            .join(",");

        let ja4_c_original_raw = if sig_algs_str.is_empty() {
            extensions_original_str
        } else if extensions_original_str.is_empty() {
            sig_algs_str.clone()
        } else {
            format!("{}_{}", extensions_original_str, sig_algs_str)
        };

        // Generate hashes for JA4_b and JA4_c (first 12 characters of SHA256)
        let ja4_b_hash = hash12(&ja4_b_raw);
        let ja4_c_hash = hash12(&ja4_c_raw);
        let ja4_b_original_hash = hash12(&ja4_b_original_raw);
        let ja4_c_original_hash = hash12(&ja4_c_original_raw);

        // JA4 (sorted): ja4_a + "_" + ja4_b_hash + "_" + ja4_c_hash
        let ja4_full = format!("{}_{}_{}", ja4_a, ja4_b_raw, ja4_c_raw);
        let ja4_hash = format!("{}_{}_{}", ja4_a, ja4_b_hash, ja4_c_hash);

        // JA4_original (original order): ja4_a + "_" + ja4_b_original_raw + "_" + ja4_c_original_raw
        let ja4_original_full = format!("{}_{}_{}", ja4_a, ja4_b_original_raw, ja4_c_original_raw);
        let ja4_original_hash =
            format!("{}_{}_{}", ja4_a, ja4_b_original_hash, ja4_c_original_hash);

        Ja4Payload {
            ja4_a,
            ja4_b: ja4_b_raw,
            ja4_c: ja4_c_raw,
            ja4_raw: ja4_full,
            ja4_hash,
            ja4_original_raw: ja4_original_full,
            ja4_original_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test signature with typical values
    fn create_test_signature() -> Signature {
        Signature {
            version: TlsVersion::V1_3,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
            elliptic_curve_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            sni: Some("example.com".to_string()),
            alpn: Some("h2".to_string()),
        }
    }

    #[test]
    fn test_ja4_generation() {
        let sig = create_test_signature();
        let ja4 = sig.generate_ja4();

        // Test JA4_a format: protocol + version + sni + cipher_count + extension_count + alpn_first + alpn_last
        assert_eq!(ja4.ja4_a, "t13d1516h2");

        // Test that cipher suites are sorted and properly formatted
        assert!(ja4.ja4_b.contains("002f"));
        assert!(ja4.ja4_b.contains("1301"));

        // Test that extensions exclude SNI (0x0000) and ALPN (0x0010)
        assert!(!ja4.ja4_c.contains("0000"));
        assert!(!ja4.ja4_c.contains("0010"));

        // Test that signature algorithms are included
        assert!(ja4.ja4_c.contains("0403"));

        // Test hash lengths (should be 12 characters)
        let hash_part = ja4.ja4_hash.split('_').nth(1).unwrap();
        assert_eq!(hash_part.len(), 12);
        let hash_part = ja4.ja4_hash.split('_').nth(2).unwrap();
        assert_eq!(hash_part.len(), 12);
    }

    #[test]
    fn test_ja4_original_order() {
        let sig = create_test_signature();
        let ja4 = sig.generate_ja4();

        // JA4_original should differ from JA4 in both cipher and extension order
        assert_ne!(ja4.ja4_original_raw, ja4.ja4_raw);
        assert_eq!(
            ja4.ja4_original_raw.split('_').nth(0),
            ja4.ja4_raw.split('_').nth(0)
        ); // Same JA4_a

        // JA4_b should be different due to cipher order (original vs sorted)
        assert_ne!(
            ja4.ja4_original_raw.split('_').nth(1),
            ja4.ja4_raw.split('_').nth(1)
        ); // Different JA4_b

        // JA4_c should be different due to extension order and SNI/ALPN inclusion
        assert_ne!(
            ja4.ja4_original_raw.split('_').nth(2),
            ja4.ja4_raw.split('_').nth(2)
        );

        // JA4_original should include SNI (0000) and ALPN (0010)
        assert!(ja4.ja4_original_raw.contains("0000")); // SNI
        assert!(ja4.ja4_original_raw.contains("0010")); // ALPN

        // JA4 (sorted) should NOT include SNI and ALPN
        assert!(!ja4.ja4_raw.contains("0000")); // SNI
        assert!(!ja4.ja4_raw.contains("0010")); // ALPN
    }

    #[test]
    fn test_grease_filtering() {
        let mut sig = create_test_signature();
        // Add GREASE values
        sig.cipher_suites.push(0x0a0a);
        sig.extensions.push(0x1a1a);
        sig.signature_algorithms.push(0x2a2a);

        let ja4 = sig.generate_ja4();

        // GREASE values should be filtered out
        assert!(!ja4.ja4_b.contains("0a0a"));
        assert!(!ja4.ja4_c.contains("1a1a"));
        assert!(!ja4.ja4_c.contains("2a2a"));
    }

    #[test]
    fn test_alpn_first_last() {
        // Test single character ALPN
        assert_eq!(first_last_alpn("h"), ('h', '0'));

        // Test two character ALPN
        assert_eq!(first_last_alpn("h2"), ('h', '2'));

        // Test longer ALPN
        assert_eq!(first_last_alpn("http/1.1"), ('h', '1'));

        // Test non-ASCII replacement
        assert_eq!(first_last_alpn("hñ"), ('h', '9'));

        // Test empty (should not happen in practice)
        assert_eq!(first_last_alpn(""), ('0', '0'));
    }

    #[test]
    fn test_sni_indicator() {
        let mut sig = create_test_signature();
        sig.sni = Some("example.com".to_string());
        let ja4_with_sni = sig.generate_ja4();
        assert!(ja4_with_sni.ja4_a.contains('d'));

        sig.sni = None;
        let ja4_without_sni = sig.generate_ja4();
        assert!(ja4_without_sni.ja4_a.contains('i'));
    }

    #[test]
    fn test_no_signature_algorithms() {
        let mut sig = create_test_signature();
        sig.signature_algorithms.clear();

        let ja4 = sig.generate_ja4();

        // Should not end with underscore when no signature algorithms
        assert!(!ja4.ja4_c.ends_with('_'));
        assert!(!ja4.ja4_raw.contains("__"));
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(format!("{}", TlsVersion::V1_0), "10");
        assert_eq!(format!("{}", TlsVersion::V1_1), "11");
        assert_eq!(format!("{}", TlsVersion::V1_2), "12");
        assert_eq!(format!("{}", TlsVersion::V1_3), "13");
        assert_eq!(format!("{}", TlsVersion::Unknown(0x0305)), "00");
    }

    #[test]
    fn test_hash12_function() {
        let input = "test_string";
        let hash = hash12(input);
        assert_eq!(hash.len(), 12);

        // Same input should produce same hash
        assert_eq!(hash12(input), hash12(input));

        // Different input should produce different hash
        assert_ne!(hash12("different"), hash12(input));
    }

    #[test]
    fn test_cipher_extension_count_limits() {
        let mut sig = create_test_signature();

        // First, let's understand the format with a normal signature
        let ja4_normal = sig.generate_ja4();
        println!("Normal JA4_a: '{}'", ja4_normal.ja4_a);

        // Test with more than 99 ciphers
        sig.cipher_suites = (0..150).map(|i| i as u16).collect();
        let ja4 = sig.generate_ja4();

        println!("JA4_a with many ciphers: '{}'", ja4.ja4_a);
        println!("Length: {}", ja4.ja4_a.len());

        // JA4_a format: protocol(1) + version(2) + sni(1) + cipher_count(2) + extension_count(2) + alpn_first(1) + alpn_last(1)
        // Example: "t13d9999h2" = t + 13 + d + 99 + 99 + h + 2
        let cipher_count = &ja4.ja4_a[4..6]; // positions 4-5 for cipher count
        assert_eq!(cipher_count, "99");

        // Test with more than 99 extensions
        sig.extensions = (0..200).map(|i| i as u16).collect();
        let ja4 = sig.generate_ja4();

        // Should be limited to 99
        let ext_count = &ja4.ja4_a[6..8]; // positions 6-7 for extension count
        assert_eq!(ext_count, "99");
    }

    #[test]
    fn test_ja4_format_consistency() {
        let sig = create_test_signature();
        let ja4 = sig.generate_ja4();

        println!("JA4 full: '{}'", ja4.ja4_raw);
        println!("JA4 hash: '{}'", ja4.ja4_hash);
        println!("JA4 original full: '{}'", ja4.ja4_original_raw);
        println!("JA4 original hash: '{}'", ja4.ja4_original_hash);

        // JA4 hash should have exactly 2 underscores (ja4_a_ja4_b_hash_ja4_c_hash)
        assert_eq!(ja4.ja4_hash.matches('_').count(), 2);
        assert_eq!(ja4.ja4_original_hash.matches('_').count(), 2);

        // JA4 full format can have more underscores due to internal structure (extensions_sig_algs)
        // The main structure should be ja4_a_ja4_b_ja4_c where ja4_c might contain internal underscores
        let ja4_full_parts: Vec<&str> = ja4.ja4_raw.split('_').collect();
        let ja4_original_full_parts: Vec<&str> = ja4.ja4_original_raw.split('_').collect();

        // Should have at least 3 parts: ja4_a, ja4_b, and ja4_c (which might contain more underscores)
        assert!(ja4_full_parts.len() >= 3);
        assert!(ja4_original_full_parts.len() >= 3);

        // All parts should start with the same JA4_a
        assert!(ja4.ja4_hash.starts_with(&ja4.ja4_a));
        assert!(ja4.ja4_raw.starts_with(&ja4.ja4_a));
        assert!(ja4.ja4_original_raw.starts_with(&ja4.ja4_a));
        assert!(ja4.ja4_original_hash.starts_with(&ja4.ja4_a));

        // First parts should be identical (ja4_a)
        assert_eq!(ja4_full_parts[0], ja4_original_full_parts[0]);

        // JA4 vs JA4_original differences:
        // - JA4 uses sorted cipher suites, JA4_original uses original order
        // - JA4 excludes SNI/ALPN and sorts extensions, JA4_original includes SNI/ALPN in original order

        // Verify JA4 (sorted) excludes SNI/ALPN
        assert!(!ja4.ja4_raw.contains("0000")); // No SNI
        assert!(!ja4.ja4_raw.contains("0010")); // No ALPN

        // Verify JA4_original includes SNI/ALPN
        assert!(ja4.ja4_original_raw.contains("0000")); // Has SNI
        assert!(ja4.ja4_original_raw.contains("0010")); // Has ALPN

        println!("✅ JA4 format consistency verified!");
    }

    #[test]
    fn test_ja4_variants_demo() {
        let sig = create_test_signature();
        let ja4 = sig.generate_ja4();

        println!("\n=== JA4 Variants Demo ===");
        println!("ja4 (hashed, sorted):           {}", ja4.ja4_hash);
        println!("ja4_r (raw/full, sorted):       {}", ja4.ja4_raw);
        println!("ja4_o (hashed, original):       {}", ja4.ja4_original_hash);
        println!("ja4_ro (raw/full, original):    {}", ja4.ja4_original_raw);
        println!("=========================\n");

        // Show the key differences
        let ja4_parts: Vec<&str> = ja4.ja4_raw.split('_').collect();
        let ja4_orig_parts: Vec<&str> = ja4.ja4_original_raw.split('_').collect();

        println!("Cipher suites (sorted):   {}", ja4_parts[1]);
        println!("Cipher suites (original): {}", ja4_orig_parts[1]);
        println!();
        println!("Extensions (sorted, no SNI/ALPN):   {}", ja4_parts[2]);
        println!(
            "Extensions (original, with SNI/ALPN): {}",
            ja4_orig_parts[2]
        );

        // Verify correct lengths for hashed versions
        assert_eq!(ja4.ja4_hash.split('_').nth(1).unwrap().len(), 12); // ja4_b hash
        assert_eq!(ja4.ja4_hash.split('_').nth(2).unwrap().len(), 12); // ja4_c hash
        assert_eq!(ja4.ja4_original_hash.split('_').nth(1).unwrap().len(), 12); // ja4_b original hash
        assert_eq!(ja4.ja4_original_hash.split('_').nth(2).unwrap().len(), 12); // ja4_c original hash

        // Verify that raw versions contain actual cipher/extension values
        assert!(ja4.ja4_raw.contains("1301")); // TLS_AES_128_GCM_SHA256
        assert!(ja4.ja4_original_raw.contains("1301"));

        // Verify hashed versions don't contain raw cipher values
        assert!(!ja4.ja4_hash.contains("1301"));
        assert!(!ja4.ja4_original_hash.contains("1301"));

        // Verify SNI/ALPN behavior
        assert!(!ja4.ja4_raw.contains("0000")); // JA4 sorted excludes SNI
        assert!(!ja4.ja4_raw.contains("0010")); // JA4 sorted excludes ALPN
        assert!(ja4.ja4_original_raw.contains("0000")); // JA4 original includes SNI
        assert!(ja4.ja4_original_raw.contains("0010")); // JA4 original includes ALPN
    }

    #[test]
    fn test_browserleaks_comparison() {
        // Expected results from tls11.browserleaks.com (from the webpage)
        let expected_ja4_ro = "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0023,0010,0000,0017,001b,000b,0033,44cd,0005,000d,ff01,002d,0012,000a,fe0d,002b_0403,0804,0401,0503,0805,0501,0806,0601";

        // Parse expected extension order from the webpage result
        let parts: Vec<&str> = expected_ja4_ro.split('_').collect();
        let expected_extensions_str = parts[2];
        let expected_extensions: Vec<u16> = expected_extensions_str
            .split(",")
            .filter_map(|s| u16::from_str_radix(s, 16).ok())
            .collect();

        println!("Expected extension order from browserleaks:");
        for (i, ext) in expected_extensions.iter().enumerate() {
            println!("  {}: 0x{:04x}", i, ext);
        }

        // Create a signature that matches the browserleaks order
        let browserleaks_sig = Signature {
            version: TlsVersion::V1_3,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: expected_extensions,
            elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
            elliptic_curve_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            sni: Some("tls11.browserleaks.com".to_string()),
            alpn: Some("h2".to_string()),
        };

        let ja4 = browserleaks_sig.generate_ja4();

        println!("\nGenerated from expected extension order:");
        println!("JA4_ro: {}", ja4.ja4_original_raw);
        println!("Expected: {}", expected_ja4_ro);

        // This should now match exactly
        assert_eq!(ja4.ja4_original_raw, expected_ja4_ro);
    }

    #[test]
    fn test_captured_traffic_ja4() {
        // Using the actual extension order from captured traffic
        // First packet: 0012,000d,000b,ff01,0000,0023,001b,44cd,fe0d,0033,0005,0010,000a,002d,0017,002b
        let captured_extensions = vec![
            0x0012, 0x000d, 0x000b, 0xff01, 0x0000, 0x0023, 0x001b, 0x44cd, 0xfe0d, 0x0033, 0x0005,
            0x0010, 0x000a, 0x002d, 0x0017, 0x002b,
        ];

        let captured_sig = Signature {
            version: TlsVersion::V1_3,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: captured_extensions,
            elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
            elliptic_curve_point_formats: vec![0x00],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            sni: Some("tls11.browserleaks.com".to_string()),
            alpn: Some("h2".to_string()),
        };

        let ja4 = captured_sig.generate_ja4();

        println!("\n=== Captured Traffic JA4 ===");
        println!("JA4:    {}", ja4.ja4_hash);
        println!("JA4_r:  {}", ja4.ja4_raw);
        println!("JA4_o:  {}", ja4.ja4_original_hash);
        println!("JA4_ro: {}", ja4.ja4_original_raw);

        // Verify the JA4_a part is correct
        assert_eq!(ja4.ja4_a, "t13d1516h2");

        // Verify JA4_ro uses original order and includes SNI/ALPN
        let expected_ja4_ro = "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0012,000d,000b,ff01,0000,0023,001b,44cd,fe0d,0033,0005,0010,000a,002d,0017,002b_0403,0804,0401,0503,0805,0501,0806,0601";
        assert_eq!(ja4.ja4_original_raw, expected_ja4_ro);

        // Verify JA4_r excludes SNI and ALPN and sorts extensions
        assert!(!ja4.ja4_raw.contains("0000")); // No SNI
        assert!(!ja4.ja4_raw.contains("0010")); // No ALPN

        // Verify JA4_ro includes SNI and ALPN in original order
        assert!(ja4.ja4_original_raw.contains("0000")); // Has SNI
        assert!(ja4.ja4_original_raw.contains("0010")); // Has ALPN

        println!("✅ All assertions passed - JA4 implementation is working correctly!");
    }
}
