use crate::error::HuginnNetTlsError;
use crate::output::{IpPort, TlsClientOutput};
use crate::ObservableTlsClient;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

#[derive(Clone)]
pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tls_client: Option<ObservableTlsClient>,
}

pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
) -> std::result::Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    let observable_package = create_observable_package_ipv4(ipv4)?;

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
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetTlsError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let tls_package = crate::tls_process::process_tls_ipv4(ipv4)?;

    Ok(ObservablePackage { source, destination, tls_client: tls_package.tls_client })
}

pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
) -> std::result::Result<Option<TlsClientOutput>, HuginnNetTlsError> {
    let observable_package = create_observable_package_ipv6(ipv6)?;

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
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetTlsError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let tls_package = crate::tls_process::process_tls_ipv6(ipv6)?;

    Ok(ObservablePackage { source, destination, tls_client: tls_package.tls_client })
}
