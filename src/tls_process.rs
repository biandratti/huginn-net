use crate::error::PassiveTcpError;
use crate::observable_signals::ObservableTls;
use crate::tls::{Signature, TlsVersion, TLS_GREASE_VALUES};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tls_parser::{parse_tls_plaintext, TlsClientHelloContents, TlsMessage, TlsMessageHandshake};
use tracing::debug;

/// Result of TLS packet processing
#[derive(Debug)]
pub struct ObservableTlsPackage {
    pub tls_client: Option<ObservableTls>,
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

    if !is_likely_tls_traffic(tcp, payload) {
        return Ok(ObservableTlsPackage { tls_client: None });
    }
    match parse_tls_client_hello(payload) {
        Ok(tls_signature) => {
            let observable_tls = ObservableTls {
                version: tls_signature.version,
                sni: tls_signature.sni.clone(),
                alpn: tls_signature.alpn.clone(),
                cipher_suites: tls_signature.cipher_suites.clone(),
                extensions: tls_signature.extensions.clone(),
                signature_algorithms: tls_signature.signature_algorithms.clone(),
                elliptic_curves: tls_signature.elliptic_curves.clone(),
                ja4: tls_signature.generate_ja4(),
            };

            Ok(ObservableTlsPackage {
                tls_client: Some(observable_tls),
            })
        }
        //TODO: handler error
        Err(_) => Ok(ObservableTlsPackage { tls_client: None }),
    }
}

//TODO: Check valid TLS ports
const TLS_PORTS: [u16; 4] = [443, 8443, 8080, 8443];

/// Heuristic to determine if this might be TLS traffic
fn is_likely_tls_traffic(tcp: &TcpPacket, payload: &[u8]) -> bool {
    if TLS_PORTS.contains(&tcp.get_destination()) || TLS_PORTS.contains(&tcp.get_source()) {
        return true;
    }

    // Check for TLS record header (0x16 = Handshake, followed by version)
    if payload.len() >= 5 {
        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);

        // TLS handshake (0x16) with valid TLS version
        if content_type == 0x16 && (0x0301..=0x0304).contains(&version) {
            return true;
        }
    }
    false
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
    let (extensions, sni, alpn, signature_algorithms, elliptic_curves) =
        parse_extensions_from_client_hello(client_hello);

    let version = determine_tls_version(&client_hello.version, &extensions);

    // Extract cipher suites (filter GREASE)
    let cipher_suites: Vec<u16> = client_hello
        .ciphers
        .iter()
        .map(|c| c.0)
        .filter(|&cipher| !TLS_GREASE_VALUES.contains(&cipher))
        .collect();

    //TODO: WIP...
    let elliptic_curve_point_formats = Vec::new(); // Not commonly used in modern TLS

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

#[allow(clippy::type_complexity)]
fn parse_extensions_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> (Vec<u16>, Option<String>, Option<String>, Vec<u16>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();

    if let Some(ext_data) = &client_hello.ext {
        let (parsed_extensions, parsed_sni, parsed_alpn, parsed_sig_algs, parsed_curves) =
            parse_extensions_from_raw_detailed(ext_data);

        extensions = parsed_extensions;
        sni = parsed_sni;
        alpn = parsed_alpn;
        signature_algorithms = parsed_sig_algs;
        elliptic_curves = parsed_curves;
    } else {
        debug!("No extension data found in ClientHello.ext field");
    }

    (extensions, sni, alpn, signature_algorithms, elliptic_curves)
}

#[allow(clippy::type_complexity)]
fn parse_extensions_from_raw_detailed(
    ext_data: &[u8],
) -> (Vec<u16>, Option<String>, Option<String>, Vec<u16>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut offset = 0;

    // rusticata lib already parsed and removed the extensions length field. The ext_data starts directly with the first extension type
    let extensions_end = ext_data.len();

    // Parse individual extensions
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]);
        let extension_length =
            u16::from_be_bytes([ext_data[offset + 2], ext_data[offset + 3]]) as usize;
        offset += 4;

        // Validate extension length
        if offset + extension_length > extensions_end {
            debug!(
                "Extension 0x{:04x} length ({}) extends beyond data boundary (offset={}, end={})",
                extension_type, extension_length, offset, extensions_end
            );
            break;
        }

        let extension_data = &ext_data[offset..offset + extension_length];

        // Filter GREASE extensions
        if !TLS_GREASE_VALUES.contains(&extension_type) {
            extensions.push(extension_type);
            debug!("Added extension 0x{:04x} to list", extension_type);
        }

        match extension_type {
            0x0000 => {
                // Server Name Indication (SNI)
                if let Some(parsed_sni) = parse_sni_extension(extension_data) {
                    sni = Some(parsed_sni);
                }
            }
            0x0010 => {
                // Application-Layer Protocol Negotiation (ALPN)
                if let Some(parsed_alpn) = parse_alpn_extension(extension_data) {
                    alpn = Some(parsed_alpn);
                }
            }
            0x000d => {
                // Signature Algorithms
                let parsed_sig_algs = parse_signature_algorithms_extension(extension_data);
                if !parsed_sig_algs.is_empty() {
                    signature_algorithms = parsed_sig_algs;
                }
            }
            0x000a => {
                // Supported Groups (Elliptic Curves)
                let parsed_curves = parse_supported_groups_extension(extension_data);
                if !parsed_curves.is_empty() {
                    elliptic_curves = parsed_curves;
                }
            }
            _ => {}
        }

        offset += extension_length;
    }

    (extensions, sni, alpn, signature_algorithms, elliptic_curves)
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let mut offset = 0;

    // Server name list length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + list_length > data.len() {
        return None;
    }

    // Parse first server name entry
    if offset + 3 <= data.len() {
        let name_type = data[offset]; // Should be 0 for hostname
        offset += 1;

        if name_type == 0 {
            let name_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + name_length <= data.len() {
                let hostname = String::from_utf8_lossy(&data[offset..offset + name_length]);
                return Some(hostname.to_string());
            }
        }
    }

    None
}

fn parse_alpn_extension(data: &[u8]) -> Option<String> {
    if data.len() < 3 {
        return None;
    }

    let mut offset = 0;

    // Protocol name list length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + list_length > data.len() {
        return None;
    }

    // Parse first protocol name
    if offset < data.len() {
        let protocol_length = data[offset] as usize;
        offset += 1;

        if offset + protocol_length <= data.len() {
            let protocol = String::from_utf8_lossy(&data[offset..offset + protocol_length]);
            return Some(protocol.to_string());
        }
    }

    None
}

/// Generic function to parse TLS extensions that contain a list of u16 values
/// Used for signature algorithms, supported groups, etc.
fn parse_u16_list_extension(data: &[u8], extension_name: &str) -> Vec<u16> {
    let mut items = Vec::new();

    if data.len() < 2 {
        debug!("{} extension too short", extension_name);
        return items;
    }

    let mut offset = 0;

    // List length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + list_length > data.len() {
        debug!("{} list extends beyond data boundary", extension_name);
        return items;
    }

    let list_end = offset + list_length;

    // Parse items (2 bytes each)
    while offset + 2 <= list_end {
        let item = u16::from_be_bytes([data[offset], data[offset + 1]]);
        items.push(item);
        offset += 2;
    }

    items
}

fn parse_signature_algorithms_extension(data: &[u8]) -> Vec<u16> {
    parse_u16_list_extension(data, "Signature algorithms")
}

fn parse_supported_groups_extension(data: &[u8]) -> Vec<u16> {
    parse_u16_list_extension(data, "Supported groups")
}

//TODO: Compare with TLS types from library
fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    // In TLS 1.3, the ClientHello legacy_version field is always 0x0303 (TLS 1.2)
    // The real version is indicated in the supported_versions extension (0x002b)

    // Check for supported_versions extension (0x002b) which indicates TLS 1.3
    if extensions.contains(&0x002b) {
        debug!("Found supported_versions extension (0x002b), this is TLS 1.3");
        return TlsVersion::V1_3;
    }

    // Check for TLS 1.3 specific extensions as additional indicators
    let tls13_indicators = [
        0x0033, // key_share
        0x002b, // supported_versions (already checked above)
        0x0029, // pre_shared_key
        0x002a, // early_data
        0x002c, // supported_versions (server)
        0x002d, // cookie
        0x002e, // certificate_authorities
        0x002f, // oid_filters
        0x0030, // post_handshake_auth
    ];

    let tls13_ext_count = extensions
        .iter()
        .filter(|&ext| tls13_indicators.contains(ext))
        .count();

    if tls13_ext_count >= 2 {
        return TlsVersion::V1_3;
    }

    // Fall back to legacy version
    let version_u16 = legacy_version.0;
    debug!("Using legacy TLS version: 0x{:04x}", version_u16);

    match version_u16 {
        0x0304 => TlsVersion::V1_3,
        0x0303 => TlsVersion::V1_2,
        0x0302 => TlsVersion::V1_1,
        0x0301 => TlsVersion::V1_0,
        _ => {
            debug!(
                "Unknown TLS version 0x{:04x}, defaulting to TLS 1.2",
                version_u16
            );
            TlsVersion::V1_2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsVersion;
    use pnet::packet::tcp::MutableTcpPacket;

    const TLS_HANDSHAKE_TYPE: u8 = 0x16;
    const TLS_1_2_VERSION: [u8; 2] = [0x03, 0x03];
    const TLS_1_3_VERSION: [u8; 2] = [0x03, 0x04];

    /// Helper function to create a TLS handshake packet with version
    fn create_tls_handshake_payload(version: [u8; 2], length: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(TLS_HANDSHAKE_TYPE);
        payload.extend_from_slice(&version);
        payload.extend_from_slice(&length.to_be_bytes());
        payload
    }

    /// Helper function to create a readable TLS ClientHello payload
    fn create_tls_client_hello_payload(version: [u8; 2]) -> Vec<u8> {
        create_tls_handshake_payload(version, 5)
    }

    /// Helper function to create HTTP-like payload for non-TLS tests
    fn create_http_payload() -> &'static [u8] {
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    }

    /// Helper function to create SNI extension data
    fn create_sni_extension_data(hostname: &str) -> Vec<u8> {
        let mut data = Vec::new();
        let hostname_bytes = hostname.as_bytes();
        let total_length = 1 + 2 + hostname_bytes.len(); // name_type + name_length + hostname

        // Server name list length
        data.extend_from_slice(&(total_length as u16).to_be_bytes());
        // Name type (0 = hostname)
        data.push(0x00);
        // Name length
        data.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        // Hostname
        data.extend_from_slice(hostname_bytes);

        data
    }

    /// Helper function to create ALPN extension data
    fn create_alpn_extension_data(protocol: &str) -> Vec<u8> {
        let mut data = Vec::new();
        let protocol_bytes = protocol.as_bytes();
        let total_length = 1 + protocol_bytes.len(); // protocol_length + protocol

        // Protocol name list length
        data.extend_from_slice(&(total_length as u16).to_be_bytes());
        // Protocol name length
        data.push(protocol_bytes.len() as u8);
        // Protocol name
        data.extend_from_slice(protocol_bytes);

        data
    }

    fn dummy_tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut tcp_buffer = vec![0u8; 20 + payload.len()];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(0);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(0);
        tcp_packet.set_window(8192);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_payload(payload);

        tcp_buffer
    }

    #[test]
    fn test_is_likely_tls_traffic_by_port() {
        let payload = vec![0u8; 10];
        let tcp_buffer = dummy_tcp_packet(12345, 443, &payload);
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_is_likely_tls_traffic_tls_1_2_by_content_type() {
        let payload = create_tls_client_hello_payload(TLS_1_2_VERSION);
        let tcp_buffer = dummy_tcp_packet(12345, 9090, &payload); // Non-TLS port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();
        assert!(is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_is_likely_tls_traffic_tls_1_3_by_content_type() {
        let payload = create_tls_client_hello_payload(TLS_1_3_VERSION);
        let tcp_buffer = dummy_tcp_packet(12345, 9090, &payload); // Non-TLS port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_is_not_likely_tls_traffic() {
        let payload = create_http_payload();
        let tcp_buffer = dummy_tcp_packet(12345, 9090, payload); // Non-TLS port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(!is_likely_tls_traffic(&tcp_packet, payload));
    }

    #[test]
    fn test_is_likely_tls_traffic_invalid_version() {
        // Invalid TLS version (0x0200 - too old)
        let payload = create_tls_handshake_payload([0x02, 0x00], 5);
        let tcp_buffer = dummy_tcp_packet(12345, 9090, &payload); // Non-TLS port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(!is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_is_likely_tls_traffic_short_payload() {
        // Too short payload (only 2 bytes)
        let payload = vec![TLS_HANDSHAKE_TYPE, 0x03];
        let tcp_buffer = dummy_tcp_packet(12345, 9090, &payload); // Non-TLS port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(!is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_parse_sni_extension_valid() {
        // SNI extension data for "example.com"
        let sni_data = create_sni_extension_data("example.com");
        let result = parse_sni_extension(&sni_data);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_sni_extension_different_hostnames() {
        let test_cases = vec![
            "google.com",
            "github.com",
            "stackoverflow.com",
            "rust-lang.org",
        ];

        for hostname in test_cases {
            let sni_data = create_sni_extension_data(hostname);
            let result = parse_sni_extension(&sni_data);
            assert_eq!(result, Some(hostname.to_string()));
        }
    }

    #[test]
    fn test_parse_sni_extension_too_short() {
        let sni_data = vec![0x00, 0x01];
        let result = parse_sni_extension(&sni_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_alpn_extension_valid() {
        // ALPN extension data for "h2"
        let alpn_data = create_alpn_extension_data("h2");
        let result = parse_alpn_extension(&alpn_data);
        assert_eq!(result, Some("h2".to_string()));
    }

    #[test]
    fn test_parse_alpn_extension_different_protocols() {
        // Test with different protocols
        let test_cases = vec!["h2", "http/1.1", "spdy/3.1", "h2c"];

        for protocol in test_cases {
            let alpn_data = create_alpn_extension_data(protocol);
            let result = parse_alpn_extension(&alpn_data);
            assert_eq!(result, Some(protocol.to_string()));
        }
    }

    #[test]
    fn test_parse_alpn_extension_too_short() {
        let alpn_data = vec![0x00];
        let result = parse_alpn_extension(&alpn_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_signature_algorithms_extension() {
        // Signature algorithms extension with RSA-PSS-SHA256 (0x0804) and ECDSA-SHA256 (0x0403)
        let sig_alg_data = vec![
            0x00, 0x04, // List length (4 bytes)
            0x08, 0x04, // RSA-PSS-SHA256
            0x04, 0x03, // ECDSA-SHA256
        ];

        let result = parse_signature_algorithms_extension(&sig_alg_data);
        assert_eq!(result, vec![0x0804, 0x0403]);
    }

    #[test]
    fn test_parse_supported_groups_extension() {
        // Supported groups extension with secp256r1 (0x0017) and x25519 (0x001d)
        let groups_data = vec![
            0x00, 0x04, // List length (4 bytes)
            0x00, 0x17, // secp256r1
            0x00, 0x1d, // x25519
        ];

        let result = parse_supported_groups_extension(&groups_data);
        assert_eq!(result, vec![0x0017, 0x001d]);
    }

    #[test]
    fn test_determine_tls_version_1_2() {
        let legacy_version = tls_parser::TlsVersion::Tls12;
        let extensions = vec![]; // No supported_versions extension

        let result = determine_tls_version(&legacy_version, &extensions);
        assert_eq!(result, TlsVersion::V1_2);
    }

    #[test]
    fn test_determine_tls_version_1_3_with_extension() {
        let legacy_version = tls_parser::TlsVersion::Tls12; // Often shows as 1.2 in legacy field
        let extensions = vec![0x002b]; // supported_versions extension

        let result = determine_tls_version(&legacy_version, &extensions);
        assert_eq!(result, TlsVersion::V1_3);
    }

    #[test]
    fn test_parse_tls_client_hello_invalid_data() {
        let invalid_data = create_http_payload();
        let result = parse_tls_client_hello(invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_grease_filtering() {
        // Test that GREASE values are properly filtered
        let grease_cipher = 0x0a0a; // GREASE value
        let normal_cipher = 0x1301; // TLS_AES_128_GCM_SHA256

        assert!(TLS_GREASE_VALUES.contains(&grease_cipher));
        assert!(!TLS_GREASE_VALUES.contains(&normal_cipher));
    }
}
