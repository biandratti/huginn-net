use crate::error::HuginnNetError;
use crate::http_common::HttpProcessor;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::{http1_process, http2_process};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;
use ttl_cache::TtlCache;

/// FlowKey: (Client IP, Server IP, Client Port, Server Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

/// Container for HTTP processors to avoid creating new instances on each call
pub struct HttpProcessors {
    pub http2_processor: http2_process::Http2Processor,
    pub http1_processor: http1_process::Http1Processor,
}

impl HttpProcessors {
    pub fn new() -> Self {
        Self {
            http2_processor: http2_process::Http2Processor::new(),
            http1_processor: http1_process::Http1Processor::new(),
        }
    }
}

impl Default for HttpProcessors {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ObservableHttpPackage {
    pub http_request: Option<ObservableHttpRequest>,
    pub http_response: Option<ObservableHttpResponse>,
}

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
    client_http_parsed: bool,
    server_http_parsed: bool,
}

/// Quick check if HTTP data is complete for parsing (supports HTTP/1.x and HTTP/2)
fn has_complete_http_data(data: &[u8], processors: &HttpProcessors) -> bool {
    // Strategy: Don't make early decisions about protocol due to TCP fragmentation
    // Wait until we have enough data to make a reliable determination

    if data.len() < 4 {
        // Not enough data yet, wait for more TCP packets
        return false;
    }

    // HTTP/2 first since it's more specific
    processors.http2_processor.has_complete_data(data)
        || processors.http1_processor.has_complete_data(data)
}

impl TcpFlow {
    fn init(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        tcp_data: TcpData,
    ) -> TcpFlow {
        TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            client_data: vec![tcp_data],
            server_data: Vec::new(),
            client_http_parsed: false,
            server_http_parsed: false,
        }
    }
    /// Traversing all the data in sequence in the correct order to build the full data
    ///
    /// # Parameters
    /// - `is_client`: If the data comes from the client.
    fn get_full_data(&self, is_client: bool) -> Vec<u8> {
        let data: &Vec<TcpData> = if is_client {
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
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv4".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            processors,
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
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv6".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            processors,
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
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    let src_port: u16 = tcp.get_source();
    let dst_port: u16 = tcp.get_destination();
    let mut observable_http_package = ObservableHttpPackage {
        http_request: None,
        http_response: None,
    };

    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    let (tcp_flow, is_client) = {
        if let Some(flow) = cache.get_mut(&flow_key) {
            (Some(flow), true)
        } else {
            let reversed_key: FlowKey = (dst_ip, src_ip, dst_port, src_port);
            if let Some(flow) = cache.get_mut(&reversed_key) {
                (Some(flow), false)
            } else {
                (None, false)
            }
        }
    };

    if let Some(flow) = tcp_flow {
        if !tcp.payload().is_empty() {
            let tcp_data = TcpData {
                sequence: tcp.get_sequence(),
                data: Vec::from(tcp.payload()),
            };

            if is_client && src_ip == flow.client_ip && src_port == flow.client_port {
                // Only add data and parse if not already parsed
                if !flow.client_http_parsed {
                    flow.client_data.push(tcp_data);
                    let full_data = flow.get_full_data(is_client);

                    // Quick check before expensive parsing (supports HTTP/1.x and HTTP/2)
                    if has_complete_http_data(&full_data, processors) {
                        match parse_http_request(&full_data, processors) {
                            Ok(Some(http_request_parsed)) => {
                                observable_http_package.http_request = Some(http_request_parsed);
                                flow.client_http_parsed = true;
                            }
                            Ok(None) => {}
                            Err(_e) => {}
                        }
                    }
                } else {
                    debug!("CLIENT: HTTP already parsed, discarding additional data");
                }
            } else if src_ip == flow.server_ip && src_port == flow.server_port {
                // Only add data and parse if not already parsed
                if !flow.server_http_parsed {
                    flow.server_data.push(tcp_data);
                    let full_data = flow.get_full_data(is_client);

                    // Quick check before expensive parsing (supports HTTP/1.x and HTTP/2)
                    if has_complete_http_data(&full_data, processors) {
                        match parse_http_response(&full_data, processors) {
                            Ok(Some(http_response_parsed)) => {
                                observable_http_package.http_response = Some(http_response_parsed);
                                flow.server_http_parsed = true;
                            }
                            Ok(None) => {}
                            Err(_e) => {}
                        }
                    } else {
                        debug!("SERVER: Data not complete yet, waiting for more");
                    }
                } else {
                    debug!("SERVER: HTTP already parsed, discarding additional data");
                }
            }

            // Remove from cache if both request and response are parsed
            if flow.client_http_parsed && flow.server_http_parsed {
                debug!("Both HTTP request and response parsed, removing from cache early");
                cache.remove(&flow_key);
                return Ok(observable_http_package);
            }

            // Clean up on connection close
            if tcp.get_flags()
                & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
                != 0
            {
                debug!("Connection closed or reset");
                cache.remove(&flow_key);
            }
        }
    } else if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        let tcp_data: TcpData = TcpData {
            sequence: tcp.get_sequence(),
            data: Vec::from(tcp.payload()),
        };
        let flow: TcpFlow = TcpFlow::init(src_ip, src_port, dst_ip, dst_port, tcp_data);
        cache.insert(flow_key, flow, Duration::new(60, 0));
    }

    Ok(observable_http_package)
}

fn parse_http_request(
    data: &[u8],
    processors: &HttpProcessors,
) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
    // Use provided processor instances in order (HTTP/2 first, then HTTP/1.x)
    if processors.http2_processor.can_process_request(data) {
        debug!(
            "Using {} processor for request",
            processors.http2_processor.name()
        );
        return processors.http2_processor.process_request(data);
    }

    if processors.http1_processor.can_process_request(data) {
        debug!(
            "Using {} processor for request",
            processors.http1_processor.name()
        );
        return processors.http1_processor.process_request(data);
    }

    Err(HuginnNetError::Parse(
        "No HTTP processor could handle request data".to_string(),
    ))
}

fn parse_http_response(
    data: &[u8],
    processors: &HttpProcessors,
) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
    // Use provided processor instances in order (HTTP/2 first, then HTTP/1.x)
    if processors.http2_processor.can_process_response(data) {
        debug!(
            "Using {} processor for response",
            processors.http2_processor.name()
        );
        return processors.http2_processor.process_response(data);
    }

    if processors.http1_processor.can_process_response(data) {
        debug!(
            "Using {} processor for response",
            processors.http1_processor.name()
        );
        return processors.http1_processor.process_response(data);
    }

    Err(HuginnNetError::Parse(
        "No HTTP processor could handle response data".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http;
    use crate::http1_process;

    #[test]
    fn test_parse_http1_request() {
        let valid_request = b"GET / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n\
        Accept-Language: en-US,en;q=0.9,es;q=0.8\r\n\
        Cache-Control: max-age=0\r\n\
        Connection: keep-alive\r\n\
        If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT\r\n\
        If-None-Match: \"3147526947\"\r\n\
        Upgrade-Insecure-Requests: 1\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
        \r\n";
        match http1_process::Http1Processor::new().process_request(valid_request) {
            Ok(Some(request)) => {
                assert_eq!(request.lang, Some("English".to_string()));
                assert_eq!(request.user_agent, Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()));
                assert_eq!(request.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Host"),
                    http::Header::new("Accept").with_value("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                    http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
                    http::Header::new("Cache-Control").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                    http::Header::new("If-Modified-Since").optional(),
                    http::Header::new("If-None-Match").optional(),
                    http::Header::new("Upgrade-Insecure-Requests").with_value("1"),
                    http::Header::new("User-Agent"),
                ];
                assert_eq!(request.horder, expected_horder);

                let expected_habsent = vec![
                    http::Header::new("Accept-Encoding"),
                    http::Header::new("Accept-Charset"),
                    http::Header::new("Keep-Alive"),
                ];
                assert_eq!(request.habsent, expected_habsent);

                assert_eq!(request.expsw, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
            }
            Ok(None) => panic!("Incomplete HTTP request"),
            Err(e) => panic!("Failed to parse HTTP request: {e}"),
        }
    }

    #[test]
    fn test_parse_http1_response() {
        let valid_response = b"HTTP/1.1 200 OK\r\n\
        Server: Apache\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        Content-Length: 112\r\n\
        Connection: keep-alive\r\n\
        \r\n\
        <html><body><h1>It works!</h1></body></html>";

        match http1_process::Http1Processor::new().process_response(valid_response) {
            Ok(Some(response)) => {
                assert_eq!(response.expsw, "Apache");
                assert_eq!(response.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Server"),
                    http::Header::new("Content-Type"),
                    http::Header::new("Content-Length").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                ];
                assert_eq!(response.horder, expected_horder);

                let expected_absent = vec![
                    http::Header::new("Keep-Alive"),
                    http::Header::new("Accept-Ranges"),
                    http::Header::new("Date"),
                ];
                assert_eq!(response.habsent, expected_absent);
            }
            Ok(None) => panic!("Incomplete HTTP response"),
            Err(e) => panic!("Failed to parse HTTP response: {e}"),
        }
    }

    #[test]
    fn test_get_diagnostic_for_empty_sw() {
        let diagnosis: http::HttpDiagnosis = crate::http_common::get_diagnostic(None, None, None);
        assert_eq!(diagnosis, http::HttpDiagnosis::Anonymous);
    }
}
