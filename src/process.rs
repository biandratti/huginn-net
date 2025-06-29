use crate::error::PassiveTcpError;
use crate::http_process::{FlowKey, ObservableHttpPackage, TcpFlow};
use crate::observable_signals::ObservableTcp;
use crate::observable_signals::ObservableUptime;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::observable_signals::{ObservableMtu, ObservableTlsClient};
use crate::tcp_process::ObservableTCPPackage;
use crate::tls_process::ObservableTlsPackage;
use crate::uptime::{Connection, SynData};
use crate::{http_process, tcp_process, tls_process, AnalysisConfig};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    vlan::VlanPacket,
    Packet,
};
use std::net::IpAddr;
use ttl_cache::TtlCache;

#[derive(Clone)]
pub struct IpPort {
    pub ip: IpAddr,
    pub port: u16,
}

pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tcp_request: Option<ObservableTcp>,
    pub tcp_response: Option<ObservableTcp>,
    pub mtu: Option<ObservableMtu>,
    pub uptime: Option<ObservableUptime>,
    pub http_request: Option<ObservableHttpRequest>,
    pub http_response: Option<ObservableHttpResponse>,
    pub tls_client: Option<ObservableTlsClient>,
}

impl ObservablePackage {
    pub fn extract(
        packet: &[u8],
        tcp_cache: &mut TtlCache<Connection, SynData>,
        http_cache: &mut TtlCache<FlowKey, TcpFlow>,
        config: &AnalysisConfig,
    ) -> Result<Self, PassiveTcpError> {
        EthernetPacket::new(packet)
            .ok_or_else(|| {
                PassiveTcpError::UnexpectedPackage("ethernet packet too short".to_string())
            })
            .and_then(|packet| {
                visit_ethernet(
                    packet.get_ethertype(),
                    tcp_cache,
                    http_cache,
                    packet.payload(),
                    config,
                )
            })
    }
}

fn visit_ethernet(
    ether_type: EtherType,
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    payload: &[u8],
    config: &AnalysisConfig,
) -> Result<ObservablePackage, PassiveTcpError> {
    match ether_type {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("vlan packet too short".to_string()))
            .and_then(|packet| visit_vlan(tcp_cache, http_cache, packet, config)),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("ipv4 packet too short".to_string()))
            .and_then(|packet| process_ipv4(tcp_cache, http_cache, packet, config)),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("ipv6 packet too short".to_string()))
            .and_then(|packet| process_ipv6(tcp_cache, http_cache, packet, config)),

        ty => Err(PassiveTcpError::UnsupportedEthernetType(ty)),
    }
}

fn visit_vlan(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: VlanPacket,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, PassiveTcpError> {
    visit_ethernet(
        packet.get_ethertype(),
        tcp_cache,
        http_cache,
        packet.payload(),
        config,
    )
}

trait IpPacketProcessor: Packet {
    fn is_tcp(&self) -> bool;
    fn get_protocol_error(&self) -> String;
    fn process_http_with_data(
        data: &[u8],
        http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    ) -> Result<ObservableHttpPackage, PassiveTcpError>;
    fn process_tcp_with_data(
        data: &[u8],
        tcp_cache: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, PassiveTcpError>;
    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, PassiveTcpError>;
}

impl IpPacketProcessor for Ipv4Packet<'_> {
    fn is_tcp(&self) -> bool {
        self.get_next_level_protocol() == IpNextHeaderProtocols::Tcp
    }

    fn get_protocol_error(&self) -> String {
        format!(
            "unsupported IPv4 packet with non-TCP payload: {}",
            self.get_next_level_protocol()
        )
    }

    fn process_http_with_data(
        data: &[u8],
        http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    ) -> Result<ObservableHttpPackage, PassiveTcpError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            http_process::process_http_ipv4(&packet, http_cache)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv4 packet data".to_string(),
            ))
        }
    }

    fn process_tcp_with_data(
        data: &[u8],
        tcp_cache: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, PassiveTcpError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            tcp_process::process_tcp_ipv4(&packet, tcp_cache)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv4 packet data".to_string(),
            ))
        }
    }

    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, PassiveTcpError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            tls_process::process_tls_ipv4(&packet)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv4 packet data".to_string(),
            ))
        }
    }
}

impl IpPacketProcessor for Ipv6Packet<'_> {
    fn is_tcp(&self) -> bool {
        self.get_next_header() == IpNextHeaderProtocols::Tcp
    }

    fn get_protocol_error(&self) -> String {
        format!(
            "IPv6 packet with non-TCP payload: {}",
            self.get_next_header()
        )
    }

    fn process_http_with_data(
        data: &[u8],
        http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    ) -> Result<ObservableHttpPackage, PassiveTcpError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            http_process::process_http_ipv6(&packet, http_cache)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }

    fn process_tcp_with_data(
        data: &[u8],
        tcp_cache: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, PassiveTcpError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            tcp_process::process_tcp_ipv6(&packet, tcp_cache)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }

    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, PassiveTcpError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            tls_process::process_tls_ipv6(&packet)
        } else {
            Err(PassiveTcpError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }
}

fn process_ip<P: IpPacketProcessor>(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: P,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, PassiveTcpError> {
    if !packet.is_tcp() {
        return Err(PassiveTcpError::UnsupportedProtocol(
            packet.get_protocol_error(),
        ));
    }

    let packet_data = packet.packet().to_vec();

    crossbeam::scope(|s| {
        let http_handle = if config.http_enabled {
            Some(s.spawn(|_| P::process_http_with_data(&packet_data, http_cache)))
        } else {
            None
        };

        let tcp_handle = if config.tcp_enabled {
            Some(s.spawn(|_| P::process_tcp_with_data(&packet_data, tcp_cache)))
        } else {
            None
        };

        let tls_handle = if config.tls_enabled {
            Some(s.spawn(|_| P::process_tls_with_data(&packet_data)))
        } else {
            None
        };

        let http_response = http_handle.map(|h| h.join().unwrap()).unwrap_or_else(|| {
            Ok(ObservableHttpPackage {
                http_request: None,
                http_response: None,
            })
        });

        let tcp_response = tcp_handle.map(|h| h.join().unwrap()).unwrap_or_else(|| {
            Err(PassiveTcpError::UnsupportedProtocol(
                "TCP analysis disabled".to_string(),
            ))
        });

        let tls_response = tls_handle
            .map(|h| h.join().unwrap())
            .unwrap_or_else(|| Ok(ObservableTlsPackage { tls_client: None }));

        handle_http_tcp_tlc(http_response, tcp_response, tls_response)
    })
    .unwrap()
}

pub fn process_ipv4(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: Ipv4Packet,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, PassiveTcpError> {
    process_ip(tcp_cache, http_cache, packet, config)
}

pub fn process_ipv6(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: Ipv6Packet,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, PassiveTcpError> {
    process_ip(tcp_cache, http_cache, packet, config)
}

fn handle_http_tcp_tlc(
    http_response: Result<ObservableHttpPackage, PassiveTcpError>,
    tcp_response: Result<ObservableTCPPackage, PassiveTcpError>,
    tls_response: Result<ObservableTlsPackage, PassiveTcpError>,
) -> Result<ObservablePackage, PassiveTcpError> {
    match (http_response, tcp_response, tls_response) {
        (Ok(http_package), Ok(tcp_package), Ok(tls_package)) => Ok(ObservablePackage {
            source: tcp_package.source,
            destination: tcp_package.destination,
            tcp_request: tcp_package.tcp_request,
            tcp_response: tcp_package.tcp_response,
            mtu: tcp_package.mtu,
            uptime: tcp_package.uptime,
            http_request: http_package.http_request,
            http_response: http_package.http_response,
            tls_client: tls_package.tls_client,
        }),
        (Err(http_err), _, _) => Err(http_err),
        (_, Err(tcp_err), _) => Err(tcp_err),
        (_, _, Err(tls_err)) => Err(tls_err),
    }
}
