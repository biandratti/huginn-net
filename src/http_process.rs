use crate::http;
use crate::http::{Header, Version};
use failure::{bail, Error};
use httparse::{Request, EMPTY_HEADER};
use log::debug;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use ttl_cache::TtlCache;

/// FlowKey: (Client IP, Server IP, Client Port, Server Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

#[derive(Clone)]
struct TcpData {
    sequence: u32,
    data: Vec<u8>,
}

pub struct TcpFlow {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    client_data: Vec<TcpData>,
    server_data: Vec<TcpData>,
    last_seen: Instant, // Timestamp for flow expiration
}
impl TcpFlow {
    fn apply(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> TcpFlow {
        TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            //client_seq: tcp.get_sequence(),
            //server_seq: 0,
            client_data: Vec::new(),
            server_data: Vec::new(),
            last_seen: Instant::now(),
        }
    }
    /// Traversing all the data in sequence in the correct order to build the full data
    ///
    /// # Parameters
    /// - `is_client`: If the data comes from the client.
    fn get_full_data(&self, is_client: bool) -> Vec<u8> {
        let data = if is_client {
            &self.client_data
        } else {
            &self.server_data
        };

        let mut sorted_data = data.clone();

        sorted_data.sort_by_key(|tcp_data| tcp_data.sequence);

        let mut full_data = Vec::new();
        for tcp_data in sorted_data {
            full_data.extend_from_slice(&tcp_data.data);
        }
        full_data
    }
}

pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        bail!("unsupported IPv4 protocol")
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
        )
    } else {
        Ok(ObservableHttpPackage {
            http_request: None,
            http_response: None,
        })
    }
}

pub fn process_http_ipv6(
    packet: &Ipv6Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        bail!("unsupported IPv6 protocol")
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
        )
    } else {
        Ok(ObservableHttpPackage {
            http_request: None,
            http_response: None,
        })
    }
}

fn process_tcp_packet(
    cache: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Result<ObservableHttpPackage, Error> {
    let src_port: u16 = tcp.get_source();
    let dst_port: u16 = tcp.get_destination();
    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    let mut http_request: Option<ObservableHttpRequest> = None;
    let mut http_response: Option<ObservableHttpResponse> = None;

    if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        let flow: TcpFlow = TcpFlow::apply(src_ip, src_port, dst_ip, dst_port);
        cache.insert(flow_key, flow, Duration::new(60, 0));
    }

    // TODO: WIP
    if let Some(flow) = cache.get_mut(&flow_key) {
        flow.last_seen = Instant::now(); // TODO: WIP

        if !tcp.payload().is_empty() {
            if src_ip == flow.client_ip && src_port == flow.client_port {
                let tcp_data: TcpData = TcpData {
                    sequence: tcp.get_sequence(),
                    data: Vec::from(tcp.payload()),
                };
                flow.client_data.push(tcp_data);
                if let Ok(http_request_parsed) = parse_http_request(&flow.get_full_data(true)) {
                    http_request = http_request_parsed;
                }
            } else if src_ip == flow.server_ip && src_port == flow.server_port {
                let tcp_data: TcpData = TcpData {
                    sequence: tcp.get_sequence(),
                    data: Vec::from(tcp.payload()),
                };
                flow.server_data.push(tcp_data);
                if let Ok(http_response_parsed) = parse_http_response(&flow.get_full_data(false)) {
                    http_response = http_response_parsed;
                }
            }
        }

        if tcp.get_flags() & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
            != 0
        {
            debug!("Connection closed or reset");
            cache.remove(&flow_key);
        }
    }

    Ok(ObservableHttpPackage {
        http_request,
        http_response,
    })
}

fn parse_http_request(data: &[u8]) -> Result<Option<ObservableHttpRequest>, Error> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);

    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            let headers: Vec<Header> = req
                .headers
                .iter()
                .map(|h| Header::new(h.name).with_value(String::from_utf8_lossy(h.value)))
                .collect();

            let headers_in_order: Vec<Header> = build_headers_in_order(&headers);
            let headers_absent: Vec<Header> = build_headers_absent_in_order(&headers);
            let user_agent: Option<String> = extract_user_agent(&headers);
            let lang: Option<String> = extract_accept_language(&headers);
            let http_version: Version = extract_http_version(req);

            Ok(Some(ObservableHttpRequest {
                lang,
                user_agent: user_agent.clone(),
                signature: http::Signature {
                    version: http_version,
                    horder: headers_in_order,
                    habsent: headers_absent,
                    expsw: extract_traffic_classification(user_agent),
                },
            }))
        }
        Ok(httparse::Status::Partial) => {
            debug!("Incomplete HTTP request data. Data: {:?}", data);
            Ok(None)
        }
        Err(e) => {
            debug!(
                "Failed to parse HTTP request with Data: {:?}. Error: {}",
                data, e
            );
            Err(failure::err_msg(format!(
                "Failed to parse HTTP request: {}",
                e
            )))
        }
    }
}

fn parse_http_response(_data: &[u8]) -> Result<Option<ObservableHttpResponse>, Error> {
    // TODO: WIP
    Ok(None)
}

fn build_headers_in_order(headers: &[Header]) -> Vec<Header> {
    // TODO: WIP
    headers.to_vec()
}

fn build_headers_absent_in_order(headers: &[Header]) -> Vec<Header> {
    // List of expected headers
    let expected_headers = [
        "User-Agent",
        "Server",
        "Accept-Language",
        "Via",
        "X-Forwarded-For",
        "Date",
    ];
    let mut headers_absent = Vec::new();
    for header_name in expected_headers.iter() {
        let header_present = headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(header_name));
        if !header_present {
            headers_absent.push(Header::new(header_name));
        }
    }
    headers_absent
}

fn extract_user_agent(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("User-Agent"))
        .and_then(|header| header.value.clone())
}

fn extract_accept_language(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("Accept-Language"))
        .and_then(|header| header.value.clone())
}

fn extract_traffic_classification(user_agent: Option<String>) -> String {
    user_agent.unwrap_or_else(|| "???".to_string())
}

fn extract_http_version(request: Request) -> Version {
    match request.version {
        Some(0) => Version::V10,
        Some(1) => Version::V11,
        _ => Version::Any,
    }
}

pub struct ObservableHttpPackage {
    pub http_request: Option<ObservableHttpRequest>,
    pub http_response: Option<ObservableHttpResponse>,
}

#[derive(Debug)]
pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
pub struct ObservableHttpResponse {
    pub signature: http::Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let valid_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent\r\nAccept-Language: en-US\r\n\r\n";
        match parse_http_request(valid_request) {
            Ok(Some(request)) => {
                assert_eq!(request.lang, Some("en-US".to_string()));
                assert_eq!(request.user_agent, Some("test-agent".to_string()));
                println!("Parsed HTTP Request: {:?}", request);
            }
            Ok(None) => panic!("Incomplete HTTP request"),
            Err(e) => panic!("Failed to parse HTTP request: {}", e),
        }
    }
}
