use huginn_net_tls::*;

fn create_test_signature() -> Signature {
    Signature {
        version: TlsVersion::V1_3,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ],
        elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
        elliptic_curve_point_formats: vec![0x00],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
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

    // Test hash lengths (should be 12 characters) - use the new enum structure
    let parts: Vec<&str> = ja4.full.value().split('_').collect();
    assert!(parts.len() >= 3, "JA4 should have at least 3 parts separated by underscores");
    assert_eq!(parts[1].len(), 12, "Second JA4 hash part should be 12 characters");
    assert_eq!(parts[2].len(), 12, "Third JA4 hash part should be 12 characters");
}

#[test]
fn test_ja4_original_order() {
    let sig = create_test_signature();
    let ja4_sorted = sig.generate_ja4();
    let ja4_original = sig.generate_ja4_original();

    // JA4_original should differ from JA4 in both cipher and extension order
    assert_ne!(ja4_original.raw.value(), ja4_sorted.raw.value());
    assert_eq!(
        ja4_original.raw.value().split('_').next(),
        ja4_sorted.raw.value().split('_').next()
    ); // Same JA4_a

    // JA4_b should be different due to cipher order (original vs sorted)
    assert_ne!(
        ja4_original.raw.value().split('_').nth(1),
        ja4_sorted.raw.value().split('_').nth(1)
    ); // Different JA4_b

    // JA4_c should be different due to extension order and SNI/ALPN inclusion
    assert_ne!(
        ja4_original.raw.value().split('_').nth(2),
        ja4_sorted.raw.value().split('_').nth(2)
    );

    // JA4_original should include SNI (0000) and ALPN (0010)
    assert!(ja4_original.raw.value().contains("0000")); // SNI
    assert!(ja4_original.raw.value().contains("0010")); // ALPN

    // JA4 (sorted) should NOT include SNI and ALPN
    assert!(!ja4_sorted.raw.value().contains("0000")); // SNI
    assert!(!ja4_sorted.raw.value().contains("0010")); // ALPN
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
    assert!(!ja4.raw.value().contains("__"));
}

#[test]
fn test_tls_version_display() {
    assert_eq!(format!("{}", TlsVersion::V1_0), "10");
    assert_eq!(format!("{}", TlsVersion::V1_1), "11");
    assert_eq!(format!("{}", TlsVersion::V1_2), "12");
    assert_eq!(format!("{}", TlsVersion::V1_3), "13");
    assert_eq!(format!("{}", TlsVersion::Ssl3_0), "s3");
    assert_eq!(format!("{}", TlsVersion::Ssl2_0), "s2");
    assert_eq!(format!("{}", TlsVersion::Unknown(0x0305)), "00");
}

#[test]
fn test_ssl_version_in_ja4() {
    // Test that SSL 3.0 appears correctly in JA4 fingerprint
    let mut signature = create_test_signature();
    signature.version = TlsVersion::Ssl3_0;

    let ja4 = signature.generate_ja4();
    let ja4_string = ja4.full.value();

    // Should start with "ts3d" (t=TLS, s3=SSL3.0, d=SNI present)
    assert!(
        ja4_string.starts_with("ts3d"),
        "JA4 should start with 'ts3d' for SSL 3.0, got: {ja4_string}"
    );
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

    // Test with more than 99 ciphers
    sig.cipher_suites = (0..150).map(|i| i as u16).collect();
    let ja4 = sig.generate_ja4();

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
    let ja4_sorted = sig.generate_ja4();
    let ja4_original = sig.generate_ja4_original();

    // JA4 hash should have exactly 2 underscores (ja4_a_ja4_b_hash_ja4_c_hash)
    assert_eq!(ja4_sorted.full.value().matches('_').count(), 2);
    assert_eq!(ja4_original.full.value().matches('_').count(), 2);

    // JA4 full format can have more underscores due to internal structure (extensions_sig_algs)
    // The main structure should be ja4_a_ja4_b_ja4_c where ja4_c might contain internal underscores
    let ja4_full_parts: Vec<&str> = ja4_sorted.raw.value().split('_').collect();
    let ja4_original_full_parts: Vec<&str> = ja4_original.raw.value().split('_').collect();

    // Should have at least 3 parts: ja4_a, ja4_b, and ja4_c (which might contain more underscores)
    assert!(ja4_full_parts.len() >= 3);
    assert!(ja4_original_full_parts.len() >= 3);

    // All parts should start with the same JA4_a
    assert!(ja4_sorted.full.value().starts_with(&ja4_sorted.ja4_a));
    assert!(ja4_sorted.raw.value().starts_with(&ja4_sorted.ja4_a));
    assert!(ja4_original.raw.value().starts_with(&ja4_original.ja4_a));
    assert!(ja4_original.full.value().starts_with(&ja4_original.ja4_a));

    // First parts should be identical (ja4_a)
    assert_eq!(ja4_full_parts[0], ja4_original_full_parts[0]);

    // JA4 vs JA4_original differences:
    // - JA4 uses sorted cipher suites, JA4_original uses original order
    // - JA4 excludes SNI/ALPN and sorts extensions, JA4_original includes SNI/ALPN in original order

    // Verify JA4 (sorted) excludes SNI/ALPN
    assert!(!ja4_sorted.raw.value().contains("0000")); // No SNI
    assert!(!ja4_sorted.raw.value().contains("0010")); // No ALPN

    // Verify JA4_original includes SNI/ALPN
    assert!(ja4_original.raw.value().contains("0000")); // Has SNI
    assert!(ja4_original.raw.value().contains("0010")); // Has ALPN
}

#[test]
fn test_known_ja4_comparison() {
    let sig = Signature {
        version: TlsVersion::V1_3,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x000d, 0x0012, 0x0033,
            0x002b, 0x002d, 0x0015, 0x001b, 0x001c,
        ],
        elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
        elliptic_curve_point_formats: vec![0x00],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    let ja4_original = sig.generate_ja4_original();

    // Expected JA4_ro (original order with SNI/ALPN)
    let expected_ja4_ro = "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0000,0017,0018,ff01,000a,000b,0023,0010,000d,0012,0033,002b,002d,0015,001b,001c_0403,0804,0401,0503,0805,0501,0806,0601";

    // This should now match exactly
    assert_eq!(ja4_original.raw.value(), expected_ja4_ro);
}

#[test]
fn test_captured_traffic_ja4() {
    // Test with captured traffic data from a real browser
    let sig = Signature {
        version: TlsVersion::V1_3,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        // First packet: 0012,000d,000b,ff01,0000,0023,001b,44cd,fe0d,0033,0005,0010,000a,002d,0017,002b
        extensions: vec![
            0x0012, 0x000d, 0x000b, 0xff01, 0x0000, 0x0023, 0x001b, 0x44cd, 0xfe0d, 0x0033, 0x0005,
            0x0010, 0x000a, 0x002d, 0x0017, 0x002b,
        ],
        elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
        elliptic_curve_point_formats: vec![0x00],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    let ja4_sorted = sig.generate_ja4();
    let ja4_original = sig.generate_ja4_original();

    // Verify the JA4_a part is correct
    assert_eq!(ja4_sorted.ja4_a, "t13d1516h2");
    assert_eq!(ja4_original.ja4_a, "t13d1516h2");

    // Verify JA4_ro uses original order and includes SNI/ALPN
    let expected_ja4_ro = "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0012,000d,000b,ff01,0000,0023,001b,44cd,fe0d,0033,0005,0010,000a,002d,0017,002b_0403,0804,0401,0503,0805,0501,0806,0601";
    assert_eq!(ja4_original.raw.value(), expected_ja4_ro);

    // Verify JA4_r excludes SNI and ALPN and sorts extensions
    assert!(!ja4_sorted.raw.value().contains("0000")); // No SNI
    assert!(!ja4_sorted.raw.value().contains("0010")); // No ALPN

    // Verify JA4_ro includes SNI and ALPN in original order
    assert!(ja4_original.raw.value().contains("0000")); // Has SNI
    assert!(ja4_original.raw.value().contains("0010")); // Has ALPN
}
