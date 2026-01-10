use crate::error::HuginnNetTlsError;
use crate::output::{IpPort, TlsClientOutput};
use crate::ObservableTlsClient;
use crate::tls_client_hello_reader::TlsClientHelloReader;
use crate::FlowKey;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::debug;

#[derive(Clone)]
pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tls_client: Option<ObservableTlsClient>,
}

pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
) -> std::result::Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv4.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        debug!("Not TCP, silently ignore (not an error for TLS analyzer)");
        return Ok(None);
    }
    
    let observable_package = match create_observable_package_ipv4(ipv4) {
        Ok(pkg) => pkg,
        Err(e) => {
            // If it fails for non-TCP, return None (already checked above, so this is a different error)
            let error_str = format!("{}", e);
            if error_str.contains("non-TCP protocol") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let tls_output = observable_package
        .tls_client
        .map(|observable_tls| TlsClientOutput {
            source: IpPort::new(observable_package.source.ip, observable_package.source.port),
            destination: IpPort::new(
                observable_package.destination.ip,
                observable_package.destination.port,
            ),
            sig: observable_tls,
        });

    Ok(tls_output)
}

fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
) -> std::result::Result<ObservablePackage, HuginnNetTlsError> {    
    debug!("IPv4 packet: src={}, dst={}, protocol={}", 
           ipv4.get_source(), ipv4.get_destination(), ipv4.get_next_level_protocol());
    
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| {
            debug!("Failed to parse TCP packet from IPv4 payload (len={})", ipv4.payload().len());
            HuginnNetTlsError::Parse("Invalid TCP packet".to_string())
        })?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let tls_package = crate::tls_process::process_tls_ipv4(ipv4)?;

    Ok(ObservablePackage { source, destination, tls_client: tls_package.tls_client })
}

pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
) -> std::result::Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv6.get_next_header() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        debug!("Not TCP, silently ignore (not an error for TLS analyzer)");
        return Ok(None);
    }
    
    let observable_package = match create_observable_package_ipv6(ipv6) {
        Ok(pkg) => pkg,
        Err(e) => {
            // If it fails for non-TCP, return None (already checked above, so this is a different error)
            let error_str = format!("{}", e);
            if error_str.contains("non-TCP protocol") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let tls_output = observable_package
        .tls_client
        .map(|observable_tls| TlsClientOutput {
            source: IpPort::new(observable_package.source.ip, observable_package.source.port),
            destination: IpPort::new(
                observable_package.destination.ip,
                observable_package.destination.port,
            ),
            sig: observable_tls,
        });

    Ok(tls_output)
}

fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
) -> std::result::Result<ObservablePackage, HuginnNetTlsError> {
    use tracing::debug;
    
    debug!("IPv6 packet: src={}, dst={}, next_header={}", 
           ipv6.get_source(), ipv6.get_destination(), ipv6.get_next_header());
    
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| {
            debug!("Failed to parse TCP packet from IPv6 payload (len={})", ipv6.payload().len());
            HuginnNetTlsError::Parse("Invalid TCP packet".to_string())
        })?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let tls_package = crate::tls_process::process_tls_ipv6(ipv6)?;

    Ok(ObservablePackage { source, destination, tls_client: tls_package.tls_client })
}

/// Process IPv4 packet with TCP reassembly for fragmented ClientHello
pub fn process_ipv4_with_reassembly(
    ipv4: &pnet::packet::ipv4::Ipv4Packet,
    tcp_flows: &mut HashMap<FlowKey, TlsClientHelloReader>,
) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv4.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return Ok(None);
    }
    
    let tcp = match TcpPacket::new(ipv4.payload()) {
        Some(tcp) => tcp,
        None => return Ok(None),
    };
    
    let src_ip = IpAddr::V4(ipv4.get_source());
    let dst_ip = IpAddr::V4(ipv4.get_destination());
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    
    // Only process packets from client (high port -> 443)
    let is_client = dst_port == 443 || dst_port == 8443 || (src_port > 1024 && dst_port <= 1024);
    if !is_client {
        return Ok(None);
    }
    
    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    
    let payload = tcp.payload();
    if payload.is_empty() {
        return Ok(None);
    }
    
    // Check if we already have an active flow for this connection
    let has_active_flow = tcp_flows.contains_key(&flow_key);
    
    // Check if it's TLS traffic (only if we don't have an active flow)
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
    let reader = tcp_flows.entry(flow_key).or_default();
    
    match reader.add_bytes(payload) {
        Ok(Some(signature)) => {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            
            let tls_client = crate::ObservableTlsClient {
                version: signature.version,
                sni: signature.sni.clone(),
                alpn: signature.alpn.clone(),
                cipher_suites: signature.cipher_suites.clone(),
                extensions: signature.extensions.clone(),
                signature_algorithms: signature.signature_algorithms.clone(),
                elliptic_curves: signature.elliptic_curves,
                ja4,
                ja4_original,
            };
            
            // Remove flow after successful parse
            tcp_flows.remove(&flow_key);
            
            Ok(Some(TlsClientOutput {
                source: crate::output::IpPort::new(src_ip, src_port),
                destination: crate::output::IpPort::new(dst_ip, dst_port),
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

/// Process IPv6 packet with TCP reassembly for fragmented ClientHello
pub fn process_ipv6_with_reassembly(
    ipv6: &pnet::packet::ipv6::Ipv6Packet,
    tcp_flows: &mut HashMap<FlowKey, TlsClientHelloReader>,
) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    if ipv6.get_next_header() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return Ok(None);
    }
    
    let tcp = match TcpPacket::new(ipv6.payload()) {
        Some(tcp) => tcp,
        None => return Ok(None),
    };
    
    let src_ip = IpAddr::V6(ipv6.get_source());
    let dst_ip = IpAddr::V6(ipv6.get_destination());
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    
    // Only process packets from client (high port -> 443)
    let is_client = dst_port == 443 || dst_port == 8443 || (src_port > 1024 && dst_port <= 1024);
    if !is_client {
        return Ok(None);
    }
    
    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    
    let payload = tcp.payload();
    if payload.is_empty() {
        return Ok(None);
    }
    
    // Check if we already have an active flow for this connection
    let has_active_flow = tcp_flows.contains_key(&flow_key);
    
    // Check if it's TLS traffic (only if we don't have an active flow)
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
    let reader = tcp_flows.entry(flow_key).or_default();
    
    match reader.add_bytes(payload) {
        Ok(Some(signature)) => {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            
            let tls_client = crate::ObservableTlsClient {
                version: signature.version,
                sni: signature.sni.clone(),
                alpn: signature.alpn.clone(),
                cipher_suites: signature.cipher_suites.clone(),
                extensions: signature.extensions.clone(),
                signature_algorithms: signature.signature_algorithms.clone(),
                elliptic_curves: signature.elliptic_curves,
                ja4,
                ja4_original,
            };
            
            // Remove flow after successful parse
            tcp_flows.remove(&flow_key);
            
            Ok(Some(TlsClientOutput {
                source: crate::output::IpPort::new(src_ip, src_port),
                destination: crate::output::IpPort::new(dst_ip, dst_port),
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
