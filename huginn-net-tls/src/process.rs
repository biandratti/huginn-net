use crate::error::HuginnNetTlsError;
use crate::output::{IpPort, TlsClientOutput};
use crate::tls_client_hello_reader::TlsClientHelloReader;
use crate::FlowKey;
use crate::ObservableTlsClient;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use ttl_cache::TtlCache;

#[derive(Clone)]
pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tls_client: Option<ObservableTlsClient>,
}

pub fn process_ipv4_packet(
    ipv4: &pnet::packet::ipv4::Ipv4Packet,
    tcp_flows: &mut TtlCache<FlowKey, TlsClientHelloReader>,
) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv4.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTlsError::UnsupportedProtocol("IPv4".to_string()));
    }

    let tcp = match TcpPacket::new(ipv4.payload()) {
        Some(tcp) => tcp,
        None => return Ok(None),
    };

    process_tcp_packet(
        tcp,
        IpAddr::V4(ipv4.get_source()),
        IpAddr::V4(ipv4.get_destination()),
        tcp_flows,
    )
}

pub fn process_ipv6_packet(
    ipv6: &pnet::packet::ipv6::Ipv6Packet,
    tcp_flows: &mut TtlCache<FlowKey, TlsClientHelloReader>,
) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv6.get_next_header() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTlsError::UnsupportedProtocol("IPv6".to_string()));
    }

    let tcp = match TcpPacket::new(ipv6.payload()) {
        Some(tcp) => tcp,
        None => return Ok(None),
    };

    process_tcp_packet(
        tcp,
        IpAddr::V6(ipv6.get_source()),
        IpAddr::V6(ipv6.get_destination()),
        tcp_flows,
    )
}

fn process_tcp_packet(
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tcp_flows: &mut TtlCache<FlowKey, TlsClientHelloReader>,
) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);

    let payload = tcp.payload();
    if payload.is_empty() {
        return Ok(None);
    }

    // Check if it's TLS traffic
    let has_active_flow = tcp_flows.contains_key(&flow_key);
    let is_tls = if has_active_flow {
        // If we have an active flow, assume continuation data is TLS
        true
    } else {
        // Only check TLS header for new flows
        crate::tls_process::is_tls_traffic(payload)
    };

    if !is_tls {
        return Ok(None);
    }

    // Get or create reader for this flow
    use std::time::Duration;
    let reader = tcp_flows.get_mut(&flow_key);
    let reader = if let Some(reader) = reader {
        reader
    } else {
        // Create new reader for this flow
        // TTL of 20 seconds: fragmented ClientHello packets should arrive within milliseconds.
        // If no activity for 20s, the connection likely failed or ClientHello won't complete.
        let new_reader = TlsClientHelloReader::new();
        tcp_flows.insert(flow_key, new_reader, Duration::new(20, 0));
        // After insert, the entry should exist. If get_mut returns None, it's a TtlCache ttl issue.
        tcp_flows.get_mut(&flow_key).ok_or_else(|| {
            HuginnNetTlsError::Parse("Failed to retrieve flow after insert".to_string())
        })?
    };

    match reader.add_bytes(payload) {
        Ok(Some(signature)) => {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            let tls_client = ObservableTlsClient {
                version: signature.version,
                sni: signature.sni,
                alpn: signature.alpn,
                cipher_suites: signature.cipher_suites,
                extensions: signature.extensions,
                signature_algorithms: signature.signature_algorithms,
                elliptic_curves: signature.elliptic_curves,
                ja4,
                ja4_original,
            };

            tcp_flows.remove(&flow_key);

            Ok(Some(TlsClientOutput {
                source: IpPort::new(src_ip, src_port),
                destination: IpPort::new(dst_ip, dst_port),
                sig: tls_client,
            }))
        }
        Ok(None) => {
            // Still accumulating data
            Ok(None)
        }
        Err(_e) => {
            tcp_flows.remove(&flow_key);
            Ok(None)
        }
    }
}
