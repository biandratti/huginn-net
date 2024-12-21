use crate::http;
use crate::http::{Header, Version};
use failure::Error;
use httparse::{Request, EMPTY_HEADER};
use log::{debug, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use ttl_cache::TtlCache;

pub type FlowKey = (IpAddr, IpAddr, u16, u16); // (Client IP, Server IP, Client Port, Server Port)

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

pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp) = TcpPacket::new(packet.payload()) {
            return process_tcp_packet(
                cache,
                tcp,
                IpAddr::V4(packet.get_source()),
                IpAddr::V4(packet.get_destination()),
            );
        }
    }
    Ok(ObservableHttpPackage { http_request: None })
}

pub fn process_http_ipv6(
    packet: &Ipv6Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_header() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp) = TcpPacket::new(packet.payload()) {
            return process_tcp_packet(
                cache,
                tcp,
                IpAddr::V6(packet.get_source()),
                IpAddr::V6(packet.get_destination()),
            );
        }
    }
    Ok(ObservableHttpPackage { http_request: None })
}

fn process_tcp_packet(
    cache: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Result<ObservableHttpPackage, Error> {
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let flow_key = (src_ip, dst_ip, src_port, dst_port);
    let mut http_request: Option<ObservableHttpRequest> = None;

    if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        let flow = TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            client_seq: tcp.get_sequence(),
            server_seq: 0,
            client_data: Vec::new(),
            server_data: Vec::new(),
            last_seen: Instant::now(),
        };
        cache.insert(flow_key, flow, Duration::new(60, 0));
        return Ok(ObservableHttpPackage { http_request: None });
    }

    if let Some(flow) = cache.get_mut(&flow_key) {
        flow.last_seen = Instant::now();

        if !tcp.payload().is_empty() {
            // Append the new data to the flow data
            if src_ip == flow.client_ip && src_port == flow.client_port {
                flow.client_data.extend_from_slice(tcp.payload());
                if let Ok(http_request_parsed) = parse_http_request(&flow.client_data) {
                    info!("HTTP Request:\n{:?}", http_request_parsed);
                    http_request = http_request_parsed;
                }
            } else {
                // Try to parse the HTTP response when enough data is accumulated
                /*flow.server_data.extend_from_slice(tcp.payload());
                if let Ok(response) = parse_http_response(&flow.server_data) {
                    info!("HTTP Response:\n{:?}", response);
                }*/
            }
        }

        if tcp.get_flags() & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
            != 0
        {
            debug!("Connection closed or reset");
            cache.remove(&flow_key);
        }
    }

    Ok(ObservableHttpPackage { http_request })
}

fn parse_http_request(data: &[u8]) -> Result<Option<ObservableHttpRequest>, Error> {
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);

    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            let headers: Vec<_> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();

            let expected_headers = vec![
                "User-Agent",
                "Server",
                "Accept-Language",
                "Via",
                "X-Forwarded-For",
                "Date",
            ];

            let horder: Vec<Header> = headers
                .iter()
                .map(|(k, _)| Header::new(k.clone()))
                .collect();

            let habsent: Vec<Header> = expected_headers
                .iter()
                .filter(|h| !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(h)))
                .map(|h| Header::new(h.to_string()))
                .collect();

            let user_agent: Option<String> = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("User-Agent"))
                .map(|(_, v)| v.clone());
            let lang: Option<String> = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Accept-Language"))
                .map(|(_, v)| v.clone());

            //info!("Successfully parsed HTTP Request. Headers: {:?}", headers);

            Ok(Some(ObservableHttpRequest {
                lang,
                user_agent: user_agent.clone(),
                signature: http::Signature {
                    version: extract_http_version(req),
                    horder,
                    habsent,
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

fn extract_traffic_classification(user_agent: Option<String>) -> String {
    match user_agent {
        None => "???".to_string(),
        Some(us_ag) => us_ag,
    }
}

fn extract_http_version(request: Request) -> Version {
    match request.version {
        Some(1) => Version::V10,
        Some(2) => Version::V11,
        //Some(3) => Version::V2,
        _ => Version::Any,
    }
}

pub struct ObservableHttpPackage {
    http_request: Option<ObservableHttpRequest>,
}

#[derive(Debug)]
pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
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
