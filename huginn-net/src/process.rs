use crate::error::HuginnNetError;
use crate::AnalysisConfig;
use huginn_net_http::http_process::{FlowKey, HttpProcessors, ObservableHttpPackage, TcpFlow};
use huginn_net_http::observable::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_tcp::observable::{ObservableMtu, ObservableTcp, ObservableUptime};
use huginn_net_tcp::tcp_process::ObservableTCPPackage;
use huginn_net_tcp::uptime::{Connection, SynData};
use huginn_net_tls::{ObservableTlsClient, ObservableTlsPackage};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
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
        connection_tracker: &mut TtlCache<Connection, SynData>,
        http_flows: &mut TtlCache<FlowKey, TcpFlow>,
        http_processors: &HttpProcessors,
        config: &AnalysisConfig,
    ) -> Result<Self, HuginnNetError> {
        EthernetPacket::new(packet)
            .ok_or_else(|| {
                HuginnNetError::UnexpectedPackage("ethernet packet too short".to_string())
            })
            .and_then(|packet| {
                visit_ethernet(
                    packet.get_ethertype(),
                    connection_tracker,
                    http_flows,
                    http_processors,
                    packet.payload(),
                    config,
                )
            })
    }
}

fn visit_ethernet(
    ether_type: EtherType,
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    payload: &[u8],
    config: &AnalysisConfig,
) -> Result<ObservablePackage, HuginnNetError> {
    match ether_type {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| HuginnNetError::UnexpectedPackage("vlan packet too short".to_string()))
            .and_then(|packet| {
                visit_vlan(
                    connection_tracker,
                    http_flows,
                    http_processors,
                    packet,
                    config,
                )
            }),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| HuginnNetError::UnexpectedPackage("ipv4 packet too short".to_string()))
            .and_then(|packet| {
                process_ipv4(
                    connection_tracker,
                    http_flows,
                    http_processors,
                    packet,
                    config,
                )
            }),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| HuginnNetError::UnexpectedPackage("ipv6 packet too short".to_string()))
            .and_then(|packet| {
                process_ipv6(
                    connection_tracker,
                    http_flows,
                    http_processors,
                    packet,
                    config,
                )
            }),

        ty => Err(HuginnNetError::UnsupportedEthernetType(ty)),
    }
}

fn visit_vlan(
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    packet: VlanPacket,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, HuginnNetError> {
    visit_ethernet(
        packet.get_ethertype(),
        connection_tracker,
        http_flows,
        http_processors,
        packet.payload(),
        config,
    )
}

trait IpPacketProcessor: Packet {
    fn is_tcp(&self) -> bool;
    fn get_protocol_error(&self) -> String;
    fn get_addresses(&self) -> (IpAddr, IpAddr);
    fn process_http_with_data(
        data: &[u8],
        http_flows: &mut TtlCache<FlowKey, TcpFlow>,
        http_processors: &HttpProcessors,
    ) -> Result<ObservableHttpPackage, HuginnNetError>;
    fn process_tcp_with_data(
        data: &[u8],
        connection_tracker: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, HuginnNetError>;
    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, HuginnNetError>;
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

    fn get_addresses(&self) -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(self.get_source()),
            IpAddr::V4(self.get_destination()),
        )
    }

    fn process_http_with_data(
        data: &[u8],
        http_flows: &mut TtlCache<FlowKey, TcpFlow>,
        http_processors: &HttpProcessors,
    ) -> Result<ObservableHttpPackage, HuginnNetError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            huginn_net_http::http_process::process_http_ipv4(&packet, http_flows, http_processors)
                .map_err(|e| match e {
                    huginn_net_http::error::HuginnNetHttpError::Parse(msg) => {
                        HuginnNetError::Parse(msg)
                    }
                    huginn_net_http::error::HuginnNetHttpError::UnsupportedProtocol(msg) => {
                        HuginnNetError::UnsupportedProtocol(msg)
                    }
                })
        } else {
            Err(HuginnNetError::UnexpectedPackage(
                "Invalid IPv4 packet data".to_string(),
            ))
        }
    }

    fn process_tcp_with_data(
        data: &[u8],
        connection_tracker: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, HuginnNetError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            huginn_net_tcp::tcp_process::process_tcp_ipv4(&packet, connection_tracker).map_err(
                |e| match e {
                    huginn_net_tcp::error::HuginnNetTcpError::Parse(msg) => {
                        HuginnNetError::Parse(msg)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::UnsupportedProtocol(msg) => {
                        HuginnNetError::UnsupportedProtocol(msg)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::InvalidTcpFlags(flags) => {
                        HuginnNetError::InvalidTcpFlags(flags)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::UnexpectedPackage(msg) => {
                        HuginnNetError::UnexpectedPackage(msg)
                    }
                },
            )
        } else {
            Err(HuginnNetError::UnexpectedPackage(
                "Invalid IPv4 packet data".to_string(),
            ))
        }
    }

    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, HuginnNetError> {
        if let Some(packet) = Ipv4Packet::new(data) {
            huginn_net_tls::process_tls_ipv4(&packet).map_err(|e| match e {
                huginn_net_tls::error::TlsError::Parse(msg) => HuginnNetError::Parse(msg),
                huginn_net_tls::error::TlsError::UnsupportedProtocol(msg) => {
                    HuginnNetError::UnsupportedProtocol(msg)
                }
                huginn_net_tls::error::TlsError::Unknown => {
                    HuginnNetError::Parse("Unknown TLS error".to_string())
                }
            })
        } else {
            Err(HuginnNetError::UnexpectedPackage(
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

    fn get_addresses(&self) -> (IpAddr, IpAddr) {
        (
            IpAddr::V6(self.get_source()),
            IpAddr::V6(self.get_destination()),
        )
    }

    fn process_http_with_data(
        data: &[u8],
        http_flows: &mut TtlCache<FlowKey, TcpFlow>,
        http_processors: &HttpProcessors,
    ) -> Result<ObservableHttpPackage, HuginnNetError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            huginn_net_http::http_process::process_http_ipv6(&packet, http_flows, http_processors)
                .map_err(|e| match e {
                    huginn_net_http::error::HuginnNetHttpError::Parse(msg) => {
                        HuginnNetError::Parse(msg)
                    }
                    huginn_net_http::error::HuginnNetHttpError::UnsupportedProtocol(msg) => {
                        HuginnNetError::UnsupportedProtocol(msg)
                    }
                })
        } else {
            Err(HuginnNetError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }

    fn process_tcp_with_data(
        data: &[u8],
        connection_tracker: &mut TtlCache<Connection, SynData>,
    ) -> Result<ObservableTCPPackage, HuginnNetError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            huginn_net_tcp::tcp_process::process_tcp_ipv6(&packet, connection_tracker).map_err(
                |e| match e {
                    huginn_net_tcp::error::HuginnNetTcpError::Parse(msg) => {
                        HuginnNetError::Parse(msg)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::UnsupportedProtocol(msg) => {
                        HuginnNetError::UnsupportedProtocol(msg)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::InvalidTcpFlags(flags) => {
                        HuginnNetError::InvalidTcpFlags(flags)
                    }
                    huginn_net_tcp::error::HuginnNetTcpError::UnexpectedPackage(msg) => {
                        HuginnNetError::UnexpectedPackage(msg)
                    }
                },
            )
        } else {
            Err(HuginnNetError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }

    fn process_tls_with_data(data: &[u8]) -> Result<ObservableTlsPackage, HuginnNetError> {
        if let Some(packet) = Ipv6Packet::new(data) {
            huginn_net_tls::process_tls_ipv6(&packet).map_err(|e| match e {
                huginn_net_tls::error::TlsError::Parse(msg) => HuginnNetError::Parse(msg),
                huginn_net_tls::error::TlsError::UnsupportedProtocol(msg) => {
                    HuginnNetError::UnsupportedProtocol(msg)
                }
                huginn_net_tls::error::TlsError::Unknown => {
                    HuginnNetError::Parse("Unknown TLS error".to_string())
                }
            })
        } else {
            Err(HuginnNetError::UnexpectedPackage(
                "Invalid IPv6 packet data".to_string(),
            ))
        }
    }
}

fn execute_analysis<P: IpPacketProcessor>(
    packet_data: &[u8],
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    config: &AnalysisConfig,
    source: IpPort,
    destination: IpPort,
) -> Result<ObservablePackage, HuginnNetError> {
    let http_response = if config.http_enabled {
        P::process_http_with_data(packet_data, http_flows, http_processors)?
    } else {
        ObservableHttpPackage {
            http_request: None,
            http_response: None,
        }
    };

    let tcp_response: ObservableTCPPackage = if config.tcp_enabled {
        P::process_tcp_with_data(packet_data, connection_tracker)?
    } else {
        ObservableTCPPackage {
            tcp_request: None,
            tcp_response: None,
            mtu: None,
            uptime: None,
        }
    };

    let tls_response = if config.tls_enabled {
        P::process_tls_with_data(packet_data)?
    } else {
        ObservableTlsPackage { tls_client: None }
    };

    handle_http_tcp_tlc(
        Ok(http_response),
        Ok(tcp_response),
        Ok(tls_response),
        source,
        destination,
    )
}

fn process_ip<P: IpPacketProcessor>(
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    packet: P,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, HuginnNetError> {
    if !packet.is_tcp() {
        return Err(HuginnNetError::UnsupportedProtocol(
            packet.get_protocol_error(),
        ));
    }

    let (source_ip, destination_ip) = packet.get_addresses();
    let tcp_ports = TcpPacket::new(packet.payload())
        .ok_or_else(|| HuginnNetError::UnexpectedPackage("Invalid TCP packet".to_string()))?;

    let source = IpPort {
        ip: source_ip,
        port: tcp_ports.get_source(),
    };
    let destination = IpPort {
        ip: destination_ip,
        port: tcp_ports.get_destination(),
    };

    let packet_data = packet.packet();

    execute_analysis::<P>(
        packet_data,
        connection_tracker,
        http_flows,
        http_processors,
        config,
        source,
        destination,
    )
}

pub fn process_ipv4(
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    packet: Ipv4Packet,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, HuginnNetError> {
    process_ip(
        connection_tracker,
        http_flows,
        http_processors,
        packet,
        config,
    )
}

pub fn process_ipv6(
    connection_tracker: &mut TtlCache<Connection, SynData>,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    packet: Ipv6Packet,
    config: &AnalysisConfig,
) -> Result<ObservablePackage, HuginnNetError> {
    process_ip(
        connection_tracker,
        http_flows,
        http_processors,
        packet,
        config,
    )
}

fn handle_http_tcp_tlc(
    http_response: Result<ObservableHttpPackage, HuginnNetError>,
    tcp_response: Result<ObservableTCPPackage, HuginnNetError>,
    tls_response: Result<ObservableTlsPackage, HuginnNetError>,
    source: IpPort,
    destination: IpPort,
) -> Result<ObservablePackage, HuginnNetError> {
    match (http_response, tcp_response, tls_response) {
        (Ok(http_package), Ok(tcp_package), Ok(tls_package)) => Ok(ObservablePackage {
            source,
            destination,
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
