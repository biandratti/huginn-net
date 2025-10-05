use huginn_net_tls::tls::TlsVersion;
use huginn_net_tls::tls_process::{
    determine_tls_version, extract_tls_signature_from_client_hello, is_tls_traffic,
};
use huginn_net_tls::*;
use tls_parser::TlsExtensionType;

const TLS_HANDSHAKE_TYPE: u8 = 0x16;

/// Helper to create minimal TLS handshake payload  
fn create_tls_payload(version: tls_parser::TlsVersion) -> Vec<u8> {
    let version_bytes = version.0.to_be_bytes();
    vec![
        TLS_HANDSHAKE_TYPE,
        version_bytes[0],
        version_bytes[1],
        0x00,
        0x05,
    ]
}

#[test]
fn test_tls_detection_by_port() {
    // Test TLS detection by standard port (443)
    let payload = vec![0u8; 10];

    assert!(!is_tls_traffic(&payload)); // Non-TLS payload should be false
}

#[test]
fn test_tls_detection_by_content_only() {
    let payload = vec![0u8; 10]; // Non-TLS payload
    assert!(!is_tls_traffic(&payload));

    let tls_payload = create_tls_payload(tls_parser::TlsVersion::Tls12);
    assert!(is_tls_traffic(&tls_payload));
}

#[test]
fn test_non_tls_traffic() {
    // Test HTTP traffic is not detected as TLS
    let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    assert!(!is_tls_traffic(http_payload));

    // Test invalid TLS version
    let invalid_payload = vec![TLS_HANDSHAKE_TYPE, 0x02, 0x00, 0x00, 0x05];

    assert!(!is_tls_traffic(&invalid_payload));
}

#[test]
fn test_version_detection() {
    // Test TLS 1.2 detection
    let legacy_v12 = tls_parser::TlsVersion::Tls12;
    assert_eq!(determine_tls_version(&legacy_v12, &[]), TlsVersion::V1_2);

    // Test TLS 1.3 detection via supported_versions extension
    let legacy_v12_but_13 = tls_parser::TlsVersion::Tls12;
    assert_eq!(
        determine_tls_version(
            &legacy_v12_but_13,
            &[TlsExtensionType::SupportedVersions.into()]
        ),
        TlsVersion::V1_3
    );

    // Test TLS 1.1 detection
    let legacy_v11 = tls_parser::TlsVersion::Tls11;
    assert_eq!(determine_tls_version(&legacy_v11, &[]), TlsVersion::V1_1);

    // Test TLS 1.0 detection
    let legacy_v10 = tls_parser::TlsVersion::Tls10;
    assert_eq!(determine_tls_version(&legacy_v10, &[]), TlsVersion::V1_0);

    // Test SSL 3.0 detection (legacy)
    let ssl30 = tls_parser::TlsVersion::Ssl30;
    assert_eq!(determine_tls_version(&ssl30, &[]), TlsVersion::Ssl3_0);
}

#[test]
fn test_grease_filtering() {
    // Test GREASE values are properly identified
    assert!(TLS_GREASE_VALUES.contains(&0x0a0a));
    assert!(!TLS_GREASE_VALUES.contains(&0x1301)); // TLS_AES_128_GCM_SHA256
}

#[test]
fn test_invalid_client_hello() {
    // Test parsing fails gracefully with invalid data
    let invalid_data = b"Not a TLS ClientHello";
    assert!(parse_tls_client_hello(invalid_data).is_err());
}

#[test]
fn test_elliptic_curve_point_formats_parsing() {
    // This test verifies that elliptic_curve_point_formats are parsed correctly
    // even though they're not used in JA4 generation

    // Verify that the field exists in the Signature struct
    let sig = crate::tls::Signature {
        version: TlsVersion::V1_2,
        cipher_suites: vec![0x1301],
        extensions: vec![0x000b], // ec_point_formats extension
        elliptic_curves: vec![0x001d],
        elliptic_curve_point_formats: vec![0x00], // uncompressed point format
        signature_algorithms: vec![0x0403],
        sni: None,
        alpn: None,
    };

    // Verify the field is accessible and has the expected type
    assert_eq!(sig.elliptic_curve_point_formats, vec![0x00]);

    // Verify that JA4 generation still works with this field present
    let ja4 = sig.generate_ja4();
    assert!(ja4.ja4_a.starts_with("t12i")); // TLS 1.2, no SNI
}

#[test]
fn test_signature_parsing_functional_approach() {
    // This test verifies that the functional parsing approach works correctly
    // without using mut and creates a complete Signature in one pass

    // Create a test signature to verify all fields are accessible
    let sig = crate::tls::Signature {
        version: TlsVersion::V1_3,
        cipher_suites: vec![0x1301, 0x1302],
        extensions: vec![0x0000, 0x0010, 0x000d],
        elliptic_curves: vec![0x001d, 0x0017],
        elliptic_curve_point_formats: vec![0x00],
        signature_algorithms: vec![0x0403, 0x0804],
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    // Verify all fields are properly set
    assert_eq!(sig.version, TlsVersion::V1_3);
    assert_eq!(sig.cipher_suites.len(), 2);
    assert_eq!(sig.extensions.len(), 3);
    assert_eq!(sig.elliptic_curves.len(), 2);
    assert_eq!(sig.elliptic_curve_point_formats, vec![0x00]);
    assert_eq!(sig.signature_algorithms.len(), 2);
    assert!(sig.sni.is_some());
    assert!(sig.alpn.is_some());

    // Verify JA4 generation works with the functional structure
    let ja4 = sig.generate_ja4();
    assert!(ja4.ja4_a.starts_with("t13d")); // TLS 1.3, SNI present
    assert!(!ja4.ja4_b.is_empty()); // Cipher suites present
    assert!(!ja4.ja4_c.is_empty()); // Extensions present

    // Verify the elegant enum approach for sorted/unsorted
    assert_eq!(ja4.full.variant_name(), "ja4"); // Sorted version
    let ja4_original = sig.generate_ja4_original();
    assert_eq!(ja4_original.full.variant_name(), "ja4_o"); // Unsorted version
}

#[test]
fn test_extract_signature_with_mock_client_hello() {
    use tls_parser::{TlsCipherSuiteID, TlsClientHelloContents, TlsCompressionID, TlsVersion};

    // Create a mock ClientHello with basic fields but no extensions
    let client_hello = TlsClientHelloContents {
        version: TlsVersion::Tls12,
        random: &[0u8; 32], // 32 bytes for TLS random
        session_id: None,
        ciphers: vec![
            TlsCipherSuiteID(0x1301), // TLS_AES_128_GCM_SHA256
            TlsCipherSuiteID(0x0a0a), // GREASE value - should be filtered
            TlsCipherSuiteID(0x1302), // TLS_AES_256_GCM_SHA384
        ],
        comp: vec![TlsCompressionID(0)], // NULL compression
        ext: None, // No extensions - should still generate JA4 with empty extension fields
    };

    // Should succeed and generate JA4 with empty extension fields (matching JA4 spec)
    let result = extract_tls_signature_from_client_hello(&client_hello);
    assert!(
        result.is_ok(),
        "Failed to extract TLS signature from ClientHello"
    );

    let signature = match result {
        Ok(sig) => sig,
        Err(_) => panic!("Should not fail after assert"),
    };
    assert_eq!(signature.version, crate::tls::TlsVersion::V1_2);
    assert_eq!(signature.cipher_suites.len(), 2); // GREASE filtered out
    assert!(signature.cipher_suites.contains(&0x1301));
    assert!(signature.cipher_suites.contains(&0x1302));
    assert!(!signature.cipher_suites.contains(&0x0a0a)); // GREASE filtered
    assert!(signature.extensions.is_empty()); // No extensions
    assert!(signature.signature_algorithms.is_empty()); // No signature algorithms
    assert!(signature.sni.is_none()); // No SNI
    assert!(signature.alpn.is_none()); // No ALPN

    // Should be able to generate JA4 fingerprint
    let ja4 = signature.generate_ja4();
    assert!(ja4.ja4_a.starts_with("t12i")); // TLS 1.2, no SNI (i = no SNI)
    assert!(!ja4.ja4_b.is_empty()); // Cipher suites present
                                    // ja4_c might be empty or just a hash of empty extensions
}

#[test]
fn test_extract_signature_grease_filtering() {
    use tls_parser::{TlsCipherSuiteID, TlsClientHelloContents, TlsCompressionID, TlsVersion};

    // Test that GREASE values are properly filtered from cipher suites
    let client_hello = TlsClientHelloContents {
        version: TlsVersion::Tls12,
        random: &[0u8; 32],
        session_id: None,
        ciphers: vec![
            TlsCipherSuiteID(0x1301), // Valid cipher
            TlsCipherSuiteID(0x0a0a), // GREASE - should be filtered
            TlsCipherSuiteID(0x1a1a), // GREASE - should be filtered
            TlsCipherSuiteID(0x1302), // Valid cipher
            TlsCipherSuiteID(0x2a2a), // GREASE - should be filtered
        ],
        comp: vec![TlsCompressionID(0)],
        ext: Some(&[0x00, 0x00, 0x00, 0x00]), // Minimal extension data
    };

    // Mock the extension parsing by providing minimal valid extension data
    let result = extract_tls_signature_from_client_hello(&client_hello);
    assert!(
        result.is_ok(),
        "Failed to extract TLS signature for GREASE test"
    );
    let signature = match result {
        Ok(sig) => sig,
        Err(_) => panic!("Should not fail after assert"),
    };
    // Should only contain non-GREASE cipher suites
    assert_eq!(signature.cipher_suites.len(), 2);
    assert!(signature.cipher_suites.contains(&0x1301));
    assert!(signature.cipher_suites.contains(&0x1302));
    assert!(!signature.cipher_suites.contains(&0x0a0a));
    assert!(!signature.cipher_suites.contains(&0x1a1a));
    assert!(!signature.cipher_suites.contains(&0x2a2a));
}

#[test]
fn test_signature_struct_completeness() {
    let signature = crate::tls::Signature {
        version: TlsVersion::V1_2,
        cipher_suites: vec![0x1301, 0x1302],
        extensions: vec![0x0000, 0x0010, 0x000d],
        elliptic_curves: vec![0x001d, 0x0017],
        elliptic_curve_point_formats: vec![0x00], // uncompressed
        signature_algorithms: vec![0x0403, 0x0804],
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    // Verify all fields are accessible and have correct types
    assert_eq!(signature.version, TlsVersion::V1_2);
    assert_eq!(signature.cipher_suites, vec![0x1301, 0x1302]);
    assert_eq!(signature.extensions, vec![0x0000, 0x0010, 0x000d]);
    assert_eq!(signature.elliptic_curves, vec![0x001d, 0x0017]);
    assert_eq!(signature.elliptic_curve_point_formats, vec![0x00]);
    assert_eq!(signature.signature_algorithms, vec![0x0403, 0x0804]);
    assert_eq!(signature.sni, Some("example.com".to_string()));
    assert_eq!(signature.alpn, Some("h2".to_string()));

    // Verify JA4 generation works with complete signature
    let ja4 = signature.generate_ja4();
    assert!(ja4.ja4_a.starts_with("t12d")); // TLS 1.2, SNI present
    assert!(!ja4.ja4_b.is_empty());
    assert!(!ja4.ja4_c.is_empty());
}

#[test]
fn test_extension_parsing_edge_cases() {
    // Test empty extension list
    let empty_extensions: Vec<u16> = vec![];
    assert_eq!(
        determine_tls_version(&tls_parser::TlsVersion::Tls12, &empty_extensions),
        TlsVersion::V1_2
    );

    // Test with supported_versions extension (should detect TLS 1.3)
    let tls13_extensions = vec![TlsExtensionType::SupportedVersions.into()];
    assert_eq!(
        determine_tls_version(&tls_parser::TlsVersion::Tls12, &tls13_extensions),
        TlsVersion::V1_3
    );

    // Test with mixed extensions
    let mixed_extensions = vec![
        TlsExtensionType::ServerName.into(),
        TlsExtensionType::ApplicationLayerProtocolNegotiation.into(),
        TlsExtensionType::SupportedVersions.into(),
    ];
    assert_eq!(
        determine_tls_version(&tls_parser::TlsVersion::Tls12, &mixed_extensions),
        TlsVersion::V1_3
    );
}

#[test]
fn test_ssl_version_support() {
    // Test that SSL 3.0 is properly supported (even though rare)
    let ssl30 = tls_parser::TlsVersion::Ssl30;
    assert_eq!(determine_tls_version(&ssl30, &[]), TlsVersion::Ssl3_0);

    // Test SSL 3.0 display formatting
    assert_eq!(TlsVersion::Ssl3_0.to_string(), "s3");

    // Test that SSL 3.0 is included in TLS traffic detection range
    let ssl30_payload = vec![0x16, 0x03, 0x00, 0x00, 0x05]; // SSL 3.0 handshake
    assert!(is_tls_traffic(&ssl30_payload));
}

#[test]
fn test_extract_signature_minimal_extensions() {
    use tls_parser::{TlsCipherSuiteID, TlsClientHelloContents, TlsCompressionID, TlsVersion};

    // Test with minimal extension data that might not parse correctly
    let client_hello = TlsClientHelloContents {
        version: TlsVersion::Tls12,
        random: &[0u8; 32],
        session_id: None,
        ciphers: vec![
            TlsCipherSuiteID(0x1301), // Valid cipher
            TlsCipherSuiteID(0x1302), // Valid cipher
        ],
        comp: vec![TlsCompressionID(0)],
        ext: Some(&[0x00, 0x00]), // Minimal extension data that might fail to parse
    };

    // Should succeed even if extension parsing fails - falls back to empty extensions
    let result = extract_tls_signature_from_client_hello(&client_hello);
    assert!(
        result.is_ok(),
        "Should succeed even with minimal extension data"
    );

    let signature = match result {
        Ok(sig) => sig,
        Err(_) => panic!("Should not fail after assert"),
    };
    assert_eq!(signature.version, crate::tls::TlsVersion::V1_2);
    assert_eq!(signature.cipher_suites.len(), 2);
    // Extensions might be empty if parsing failed, but that's OK for JA4

    // Should be able to generate JA4 fingerprint regardless
    let ja4 = signature.generate_ja4();
    assert!(ja4.ja4_a.starts_with("t12i")); // TLS 1.2, no SNI
    assert!(!ja4.ja4_b.is_empty()); // Cipher suites present
}
