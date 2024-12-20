use std::net::IpAddr;
use std::time::Instant;
use crate::http;
use failure::Error;
use pnet::packet::ipv4::Ipv4Packet;
use ttl_cache::TtlCache;

pub type FlowKey = (IpAddr, IpAddr, u16, u16); // (Client IP, Server IP, Client Port, Server Port)

#[derive(Debug)]
pub struct TcpFlow {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    client_seq: u32,
    server_seq: u32,
    client_data: Vec<u8>, // Aggregated HTTP request payload
    server_data: Vec<u8>, // Aggregated HTTP response payload
    last_seen: Instant,   // Timestamp for flow expiration
}

pub fn process_http_ipv4(_packet: &Ipv4Packet, cache: &mut TtlCache<FlowKey, TcpFlow>) -> Result<ObservableHttpPackage, Error> {
    Ok(ObservableHttpPackage { http_request: None })
}

pub struct ObservableHttpPackage {
    http_request: Option<ObservableHttpRequest>,
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
