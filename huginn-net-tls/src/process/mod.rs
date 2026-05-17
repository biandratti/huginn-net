pub mod parallel;
pub mod tls;

pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use tls::{
    determine_tls_version, extract_tls_signature_from_client_hello, is_tls_traffic,
    parse_tls_client_hello, parse_tls_client_hello_ja4, process_tls_ipv4, process_tls_ipv6,
    process_tls_tcp,
};

use crate::error::HuginnNetTlsError;
use crate::fingerprint::ObservableTlsClient;
use crate::output::{IpPort, TlsClientOutput};
use crate::parser::TlsClientHelloReader;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use ttl_cache::TtlCache;

/// Flow key: (Source IP, Destination IP, Source Port, Destination Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

#[derive(Clone)]
pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tls_client: Option<ObservableTlsClient>,
}

#[inline]
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

#[inline]
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

    let has_active_flow = tcp_flows.contains_key(&flow_key);
    let is_tls = if has_active_flow {
        true
    } else {
        self::tls::is_tls_traffic(payload)
    };

    if !is_tls {
        return Ok(None);
    }

    use std::time::Duration;
    let reader = tcp_flows.get_mut(&flow_key);
    let reader = if let Some(reader) = reader {
        reader
    } else {
        let new_reader = TlsClientHelloReader::new();
        tcp_flows.insert(flow_key, new_reader, Duration::new(20, 0));
        tcp_flows.get_mut(&flow_key).ok_or_else(|| {
            HuginnNetTlsError::Parse("Failed to retrieve flow after insert".to_string())
        })?
    };

    match reader.add_bytes(payload) {
        Ok(Some(signature)) => {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            #[cfg(feature = "stable-v1")]
            let ja4_stable_v1 = signature.generate_ja4_stable_v1();
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
                #[cfg(feature = "stable-v1")]
                ja4_stable_v1,
            };

            tcp_flows.remove(&flow_key);

            Ok(Some(TlsClientOutput {
                source: IpPort::new(src_ip, src_port),
                destination: IpPort::new(dst_ip, dst_port),
                sig: tls_client,
            }))
        }
        Ok(None) => Ok(None),
        Err(_e) => {
            tcp_flows.remove(&flow_key);
            Ok(None)
        }
    }
}
