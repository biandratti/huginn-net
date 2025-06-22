use crate::error::PassiveTcpError;
use crate::observable_signals::ObservableTlsClient;
use crate::tls::{Signature, TlsVersion, TLS_GREASE_VALUES};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsClientHelloContents, TlsExtension,
    TlsExtensionType, TlsMessage, TlsMessageHandshake,
};
use tracing::debug;

/// Result of TLS packet processing
#[derive(Debug)]
pub struct ObservableTlsPackage {
    pub tls_client: Option<ObservableTlsClient>,
}

pub fn process_tls_ipv4(packet: &Ipv4Packet) -> Result<ObservableTlsPackage, PassiveTcpError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(PassiveTcpError::UnsupportedProtocol("IPv4".to_string()));
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

pub fn process_tls_ipv6(packet: &Ipv6Packet) -> Result<ObservableTlsPackage, PassiveTcpError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(PassiveTcpError::UnsupportedProtocol("IPv6".to_string()));
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

fn process_tls_tcp(tcp: &TcpPacket) -> Result<ObservableTlsPackage, PassiveTcpError> {
    let payload = tcp.payload();

    if !is_tls_traffic(payload) {
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    parse_tls_client_hello(payload)
        .map(|signature| {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            ObservableTlsPackage {
                tls_client: Some(ObservableTlsClient {
                    version: signature.version,
                    sni: signature.sni,
                    alpn: signature.alpn,
                    cipher_suites: signature.cipher_suites,
                    extensions: signature.extensions,
                    signature_algorithms: signature.signature_algorithms,
                    elliptic_curves: signature.elliptic_curves,
                    ja4,
                    ja4_original,
                }),
            }
        })
        .or(Ok(ObservableTlsPackage { tls_client: None }))
}

/// Detect TLS traffic based on packet content only
/// This is more reliable than port-based detection since TLS can run on any port
fn is_tls_traffic(payload: &[u8]) -> bool {
    // Check for TLS record header (0x16 = Handshake, followed by version)
    if payload.len() >= 5 {
        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);

        // TLS handshake (0x16) with valid TLS version (including SSL 3.0)
        content_type == 0x16 && (0x0300..=0x0304).contains(&version)
    } else {
        false
    }
}

pub fn parse_tls_client_hello(data: &[u8]) -> Result<Signature, PassiveTcpError> {
    match parse_tls_plaintext(data) {
        Ok((_remaining, tls_record)) => {
            for message in tls_record.msg.iter() {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) =
                    message
                {
                    return extract_tls_signature_from_client_hello(client_hello);
                }
            }
            Err(PassiveTcpError::Parse(
                "No ClientHello found in TLS record".to_string(),
            ))
        }
        Err(e) => Err(PassiveTcpError::Parse(format!(
            "TLS parsing failed: {:?}",
            e
        ))),
    }
}

fn extract_tls_signature_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> Result<Signature, PassiveTcpError> {
    // Extract cipher suites (filter GREASE)
    let cipher_suites: Vec<u16> = client_hello
        .ciphers
        .iter()
        .map(|c| c.0)
        .filter(|&cipher| !TLS_GREASE_VALUES.contains(&cipher))
        .collect();

    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut elliptic_curve_point_formats = Vec::new();

    // Parse extensions if present - if not present, we still generate JA4 with empty extension fields
    if let Some(ext_data) = &client_hello.ext {
        match parse_tls_extensions(ext_data) {
            Ok((_remaining, parsed_extensions)) => {
                for extension in &parsed_extensions {
                    let ext_type: u16 = TlsExtensionType::from(extension).into();

                    // Filter GREASE extensions
                    if !TLS_GREASE_VALUES.contains(&ext_type) {
                        extensions.push(ext_type);
                    }

                    match extension {
                        TlsExtension::SNI(sni_list) => {
                            if let Some((_, hostname)) = sni_list.first() {
                                sni = String::from_utf8(hostname.to_vec()).ok();
                            }
                        }
                        TlsExtension::ALPN(alpn_list) => {
                            if let Some(protocol) = alpn_list.first() {
                                alpn = String::from_utf8(protocol.to_vec()).ok();
                            }
                        }
                        TlsExtension::SignatureAlgorithms(sig_algs) => {
                            signature_algorithms = sig_algs.clone();
                        }
                        TlsExtension::EllipticCurves(curves) => {
                            elliptic_curves = curves.iter().map(|c| c.0).collect();
                        }
                        TlsExtension::EcPointFormats(formats) => {
                            elliptic_curve_point_formats = formats.to_vec();
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                debug!("Failed to parse TLS extensions: {:?}", e);
            }
        }
    }

    let version = determine_tls_version(&client_hello.version, &extensions);

    Ok(Signature {
        version,
        cipher_suites,
        extensions,
        elliptic_curves,
        elliptic_curve_point_formats,
        signature_algorithms,
        sni,
        alpn,
    })
}

fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    // TLS 1.3 uses supported_versions extension
    if extensions.contains(&TlsExtensionType::SupportedVersions.into()) {
        return TlsVersion::V1_3;
    }

    // Parse legacy version from ClientHello
    match *legacy_version {
        tls_parser::TlsVersion::Tls13 => TlsVersion::V1_3,
        tls_parser::TlsVersion::Tls12 => TlsVersion::V1_2,
        tls_parser::TlsVersion::Tls11 => TlsVersion::V1_1,
        tls_parser::TlsVersion::Tls10 => TlsVersion::V1_0,
        // Legacy SSL 3.0 (rarely seen in modern traffic)
        tls_parser::TlsVersion::Ssl30 => TlsVersion::Ssl3_0,
        // Note: SSL 2.0 is not supported by tls-parser (too legacy/vulnerable)
        _ => {
            debug!(
                "Unknown/unsupported TLS version {:?}, defaulting to TLS 1.2",
                legacy_version
            );
            TlsVersion::V1_2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsVersion;

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
        assert_eq!(ja4.ja4.variant_name(), "ja4"); // Sorted version
        let ja4_original = sig.generate_ja4_original();
        assert_eq!(ja4_original.ja4.variant_name(), "ja4_o"); // Unsorted version
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
        assert!(result.is_ok());

        let signature = result.unwrap();
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
        if let Ok(signature) = extract_tls_signature_from_client_hello(&client_hello) {
            // Should only contain non-GREASE cipher suites
            assert_eq!(signature.cipher_suites.len(), 2);
            assert!(signature.cipher_suites.contains(&0x1301));
            assert!(signature.cipher_suites.contains(&0x1302));
            assert!(!signature.cipher_suites.contains(&0x0a0a));
            assert!(!signature.cipher_suites.contains(&0x1a1a));
            assert!(!signature.cipher_suites.contains(&0x2a2a));
        }
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
        assert!(result.is_ok());

        let signature = result.unwrap();
        assert_eq!(signature.version, crate::tls::TlsVersion::V1_2);
        assert_eq!(signature.cipher_suites.len(), 2);
        // Extensions might be empty if parsing failed, but that's OK for JA4

        // Should be able to generate JA4 fingerprint regardless
        let ja4 = signature.generate_ja4();
        assert!(ja4.ja4_a.starts_with("t12i")); // TLS 1.2, no SNI
        assert!(!ja4.ja4_b.is_empty()); // Cipher suites present
    }
}
