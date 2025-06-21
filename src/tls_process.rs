use crate::error::PassiveTcpError;
use crate::observable_signals::ObservableTls;
use crate::tls::{Signature, TlsVersion, TLS_GREASE_VALUES};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tls_parser::{
    parse_tls_plaintext, TlsClientHelloContents, TlsExtensionType, TlsMessage, TlsMessageHandshake,
};
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

    parse_tls_client_hello(payload)
        .map(|signature| {
            let ja4 = signature.generate_ja4();
            ObservableTlsPackage {
                tls_client: Some(ObservableTls {
                    version: signature.version,
                    sni: signature.sni,
                    alpn: signature.alpn,
                    cipher_suites: signature.cipher_suites,
                    extensions: signature.extensions,
                    signature_algorithms: signature.signature_algorithms,
                    elliptic_curves: signature.elliptic_curves,
                    ja4,
                }),
            }
        })
        .or(Ok(ObservableTlsPackage { tls_client: None }))
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
        }

        match extension_type {
            ext if ext == TlsExtensionType::ServerName.into() => {
                // Server Name Indication (SNI)
                if let Some(parsed_sni) = parse_sni_extension(extension_data) {
                    sni = Some(parsed_sni);
                }
            }
            ext if ext == TlsExtensionType::ApplicationLayerProtocolNegotiation.into() => {
                // Application-Layer Protocol Negotiation (ALPN)
                if let Some(parsed_alpn) = parse_alpn_extension(extension_data) {
                    alpn = Some(parsed_alpn);
                }
            }
            ext if ext == TlsExtensionType::SignatureAlgorithms.into() => {
                // Signature Algorithms
                let parsed_sig_algs = parse_signature_algorithms_extension(extension_data);
                if !parsed_sig_algs.is_empty() {
                    signature_algorithms = parsed_sig_algs;
                }
            }
            ext if ext == TlsExtensionType::SupportedGroups.into() => {
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

fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    // Check for supported_versions extension which indicates TLS 1.3
    if extensions.contains(&TlsExtensionType::SupportedVersions.into()) {
        debug!("Found supported_versions extension, this is TLS 1.3");
        return TlsVersion::V1_3;
    }

    match *legacy_version {
        tls_parser::TlsVersion::Tls13 => TlsVersion::V1_3,
        tls_parser::TlsVersion::Tls12 => TlsVersion::V1_2,
        tls_parser::TlsVersion::Tls11 => TlsVersion::V1_1,
        tls_parser::TlsVersion::Tls10 => TlsVersion::V1_0,
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
    use pnet::packet::tcp::MutableTcpPacket;

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

    /// Helper to create TCP packet for testing
    fn create_tcp_packet(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; 20 + payload.len()];
        let mut packet = MutableTcpPacket::new(&mut buffer).unwrap();
        packet.set_source(12345);
        packet.set_destination(dst_port);
        packet.set_data_offset(5);
        packet.set_payload(payload);
        buffer
    }

    #[test]
    fn test_tls_detection_by_port() {
        // Test TLS detection by standard port (443)
        let payload = vec![0u8; 10];
        let tcp_buffer = create_tcp_packet(443, &payload);
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(is_likely_tls_traffic(&tcp_packet, &payload));
    }

    #[test]
    fn test_tls_detection_by_content() {
        // Test TLS detection by content type and version
        let tls_payload = create_tls_payload(tls_parser::TlsVersion::Tls12);
        let tcp_buffer = create_tcp_packet(9090, &tls_payload); // Non-standard port
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(is_likely_tls_traffic(&tcp_packet, &tls_payload));

        // Test TLS 1.3
        let tls13_payload = create_tls_payload(tls_parser::TlsVersion::Tls13);
        let tcp_buffer = create_tcp_packet(9090, &tls13_payload);
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(is_likely_tls_traffic(&tcp_packet, &tls13_payload));
    }

    #[test]
    fn test_non_tls_traffic() {
        // Test HTTP traffic is not detected as TLS
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let tcp_buffer = create_tcp_packet(80, http_payload);
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(!is_likely_tls_traffic(&tcp_packet, http_payload));

        // Test invalid TLS version
        let invalid_payload = vec![TLS_HANDSHAKE_TYPE, 0x02, 0x00, 0x00, 0x05];
        let tcp_buffer = create_tcp_packet(9090, &invalid_payload);
        let tcp_packet = TcpPacket::new(&tcp_buffer).unwrap();

        assert!(!is_likely_tls_traffic(&tcp_packet, &invalid_payload));
    }

    #[test]
    fn test_extension_parsing() {
        // Test SNI extension parsing
        let sni_data = {
            let hostname = b"example.com";
            let mut data = Vec::new();
            data.extend_from_slice(&(hostname.len() as u16 + 3).to_be_bytes()); // list length
            data.push(0x00); // name type
            data.extend_from_slice(&(hostname.len() as u16).to_be_bytes()); // name length
            data.extend_from_slice(hostname);
            data
        };
        assert_eq!(
            parse_sni_extension(&sni_data),
            Some("example.com".to_string())
        );
        assert_eq!(parse_sni_extension(&[0x00]), None); // Too short

        // Test ALPN extension parsing
        let alpn_data = {
            let protocol = b"h2";
            let mut data = Vec::new();
            data.extend_from_slice(&(protocol.len() as u16 + 1).to_be_bytes()); // list length
            data.push(protocol.len() as u8); // protocol length
            data.extend_from_slice(protocol);
            data
        };
        assert_eq!(parse_alpn_extension(&alpn_data), Some("h2".to_string()));
        assert_eq!(parse_alpn_extension(&[0x00]), None); // Too short
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
}
