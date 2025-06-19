use crate::error::PassiveTcpError;
use crate::http_process::{FlowKey, ObservableHttpPackage, TcpFlow};
use crate::observable_signals::ObservableMtu;
use crate::observable_signals::ObservableTcp;
use crate::observable_signals::ObservableUptime;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::tcp_process::ObservableTCPPackage;
use crate::uptime::{Connection, SynData};
use crate::{http_process, tcp_process};
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
}

impl ObservablePackage {
    pub fn extract(
        packet: &[u8],
        tcp_cache: &mut TtlCache<Connection, SynData>,
        http_cache: &mut TtlCache<FlowKey, TcpFlow>,
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
                )
            })
    }
}

fn visit_ethernet(
    ether_type: EtherType,
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    payload: &[u8],
) -> Result<ObservablePackage, PassiveTcpError> {
    match ether_type {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("vlan packet too short".to_string()))
            .and_then(|packet| visit_vlan(tcp_cache, http_cache, packet)),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("ipv4 packet too short".to_string()))
            .and_then(|packet| process_ipv4(tcp_cache, http_cache, packet)),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| PassiveTcpError::UnexpectedPackage("ipv6 packet too short".to_string()))
            .and_then(|packet| process_ipv6(tcp_cache, http_cache, packet)),

        ty => Err(PassiveTcpError::UnsupportedEthernetType(ty)),
    }
}

fn visit_vlan(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: VlanPacket,
) -> Result<ObservablePackage, PassiveTcpError> {
    visit_ethernet(
        packet.get_ethertype(),
        tcp_cache,
        http_cache,
        packet.payload(),
    )
}

pub fn process_ipv4(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: Ipv4Packet,
) -> Result<ObservablePackage, PassiveTcpError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(PassiveTcpError::UnsupportedProtocol(format!(
            "unsupported IPv4 packet with non-TCP payload: {}",
            packet.get_next_level_protocol()
        )));
    }

    let packet_data = packet.packet().to_vec();

    crossbeam::scope(|s| {
        let http_handle = s.spawn(|_| {
            let packet = Ipv4Packet::new(&packet_data).unwrap();
            http_process::process_http_ipv4(&packet, http_cache)
        });

        let tcp_handle = s.spawn(|_| {
            let packet = Ipv4Packet::new(&packet_data).unwrap();
            tcp_process::process_tcp_ipv4(&packet, tcp_cache)
        });

        let http_response = http_handle.join().unwrap();
        let tcp_response = tcp_handle.join().unwrap();

        handle_http_tcp_responses(http_response, tcp_response)
    })
    .unwrap()
}

pub fn process_ipv6(
    tcp_cache: &mut TtlCache<Connection, SynData>,
    http_cache: &mut TtlCache<FlowKey, TcpFlow>,
    packet: Ipv6Packet,
) -> Result<ObservablePackage, PassiveTcpError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(PassiveTcpError::UnsupportedProtocol(format!(
            "IPv6 packet with non-TCP payload: {}",
            packet.get_next_header()
        )));
    }

    let packet_data = packet.packet().to_vec();

    crossbeam::scope(|s| {
        let http_handle = s.spawn(|_| {
            let packet = Ipv6Packet::new(&packet_data).unwrap();
            http_process::process_http_ipv6(&packet, http_cache)
        });

        let tcp_handle = s.spawn(|_| {
            let packet = Ipv6Packet::new(&packet_data).unwrap();
            tcp_process::process_tcp_ipv6(&packet, tcp_cache)
        });

        let http_response = http_handle.join().unwrap();
        let tcp_response = tcp_handle.join().unwrap();

        handle_http_tcp_responses(http_response, tcp_response)
    })
    .unwrap()
}

fn handle_http_tcp_responses(
    http_response: Result<ObservableHttpPackage, PassiveTcpError>,
    tcp_response: Result<ObservableTCPPackage, PassiveTcpError>,
) -> Result<ObservablePackage, PassiveTcpError> {
    match (http_response, tcp_response) {
        (Ok(http_package), Ok(tcp_package)) => Ok(ObservablePackage {
            source: tcp_package.source,
            destination: tcp_package.destination,
            tcp_request: tcp_package.tcp_request,
            tcp_response: tcp_package.tcp_response,
            mtu: tcp_package.mtu,
            uptime: tcp_package.uptime,
            http_request: http_package.http_request,
            http_response: http_package.http_response,
        }),
        (Err(http_err), _) => Err(http_err),
        (_, Err(tcp_err)) => Err(tcp_err),
    }
}
