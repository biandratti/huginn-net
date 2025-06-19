use crate::error::PassiveTcpError;
use crate::observable_signals::ObservableTls;
use crate::tls::{Signature, TlsVersion, TLS_GREASE_VALUES};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tls_parser::TlsClientHelloContents;
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
    todo!()
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
        if content_type == 0x16 && (version >= 0x0301 && version <= 0x0304) {
            return true;
        }
    }
    false
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
    todo!()
}

fn parse_alpn_extension(data: &[u8]) -> Option<String> {
    todo!()
}

fn parse_signature_algorithms_extension(data: &[u8]) -> Vec<u16> {
    todo!()
}

fn parse_supported_groups_extension(data: &[u8]) -> Vec<u16> {
    todo!()
}

fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    todo!()
}
