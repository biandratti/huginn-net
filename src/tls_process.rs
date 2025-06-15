use crate::error::PassiveTcpError;
use crate::observable_signals::ObservableTls;
use crate::tls_packet_parser::parse_tls_client_hello_rusticata;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tracing::debug;

/// Result of TLS packet processing
#[derive(Debug)]
pub struct ObservableTlsPackage {
    pub tls_client: Option<ObservableTls>,
}

/// Process IPv4 packet for TLS analysis
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

/// Process IPv6 packet for TLS analysis
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

/// Process TCP packet for TLS ClientHello
fn process_tls_tcp(tcp: &TcpPacket) -> Result<ObservableTlsPackage, PassiveTcpError> {
    let payload = tcp.payload();

    // Check if this looks like TLS traffic (port 443 or TLS record header)
    if !is_likely_tls_traffic(tcp, payload) {
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    // Try to parse as TLS ClientHello with rusticata parser
    match parse_tls_client_hello_rusticata(payload) {
        Ok(tls_signature) => {
            let ja4 = tls_signature.generate_ja4();
            debug!("RUSTICATA PARSER - JA4: {}", ja4.ja4_hash);
            debug!(
                "RUSTICATA - Cipher suites: {}, Extensions: {}, Sig algs: {}",
                tls_signature.cipher_suites.len(),
                tls_signature.extensions.len(),
                tls_signature.signature_algorithms.len()
            );

            let observable_tls = ObservableTls {
                version: tls_signature.version,
                sni: tls_signature.sni.clone(),
                alpn: tls_signature.alpn.clone(),
                cipher_suites: tls_signature.cipher_suites.clone(),
                extensions: tls_signature.extensions.clone(),
                signature_algorithms: tls_signature.signature_algorithms.clone(),
                elliptic_curves: tls_signature.elliptic_curves.clone(),
                ja4,
            };

            Ok(ObservableTlsPackage {
                tls_client: Some(observable_tls),
            })
        }
        Err(_) => {
            // Rusticata parser failed
            Ok(ObservableTlsPackage { tls_client: None })
        }
    }
}

/// Heuristic to determine if this might be TLS traffic
fn is_likely_tls_traffic(tcp: &TcpPacket, payload: &[u8]) -> bool {
    // Check common TLS ports
    let dest_port = tcp.get_destination();
    let src_port = tcp.get_source();

    if dest_port == 443 || src_port == 443 || dest_port == 8443 || src_port == 8443 {
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_tls_port_detection() {
        // This would require creating mock TCP packets
        // Implementation depends on your testing strategy
    }
}
