use crate::error::HuginnNetHttpError;
use crate::http::common::HttpProcessor;
use crate::http::observable::{ObservableHttpRequest, ObservableHttpResponse};
use crate::http1::process as http1_process;
use crate::http2::process as http2_process;
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

use crate::http::common::HttpParser;

/// Valid first bytes for an HTTP request payload.
///
/// Union of first letters of:
/// - HTTP/1.x methods (RFC 7231): `GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, CONNECT, PATCH`
/// - WebDAV (RFC 4918): `PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK`
/// - WebDAV Versioning (RFC 3253): `REPORT`
/// - HTTP/2 connection preface (RFC 7540): `"PRI * HTTP/2.0..."` (starts with `P`)
///
/// Same fast-reject strategy used by nDPI's `http_fs = "CDGHLMOPRU"` table in
/// `src/lib/protocols/http.c` (we additionally include `T` for `TRACE`).
const HTTP_REQUEST_FIRST_BYTES: &[u8] = b"CDGHLMOPRTU";

/// Maximum legal frame length for an HTTP/2 frame using the default `SETTINGS_MAX_FRAME_SIZE`
/// (RFC 7540 §6.5.2). Used to discriminate HTTP/2 frames from random binary noise.
const HTTP2_MAX_FRAME_LEN: u32 = 16384;

/// Minimum payload size we attempt to parse. Below this we treat the data as
/// incomplete and wait for more TCP segments — avoids paying the trait-dispatch
/// cost on fragments that obviously can't contain an HTTP request or response.
const MIN_HTTP_PAYLOAD_LEN: usize = 4;

/// Cheap pre-filter: does this payload plausibly start an HTTP request (or HTTP/2
/// connection preface)? Rejects binary protocols (TLS, SSH, etc.) on flows tracked
/// by `huginn-net-http` before reaching the trait-dispatched parser path.
///
/// Also rejects fragments smaller than `MIN_HTTP_PAYLOAD_LEN`, so callers don't
/// need to do their own length guard — the function is self-validating.
fn looks_like_http_request(data: &[u8]) -> bool {
    if data.len() < MIN_HTTP_PAYLOAD_LEN {
        return false;
    }
    HTTP_REQUEST_FIRST_BYTES.contains(&data[0])
}

/// Cheap pre-filter: does this payload plausibly start an HTTP response?
/// - HTTP/1.x responses always start with the literal `"HTTP"` (then `/1.0` or `/1.1`).
/// - HTTP/2 responses are sequences of frames with no magic prefix, so we accept any
///   payload whose first 9 bytes look like a valid frame header (reasonable length and
///   a known frame type byte). Same structural test used by
///   `crate::http2::process::looks_like_http2_response`.
fn looks_like_http_response(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP") {
        return true;
    }
    if data.len() < 9 {
        return false;
    }
    let frame_length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
    if frame_length > HTTP2_MAX_FRAME_LEN {
        return false;
    }
    matches!(data[3], 0..=10)
}

/// HTTP parser that automatically detects and processes different HTTP versions
pub struct HttpProcessors {
    parsers: Vec<Box<dyn HttpParser>>,
}

impl HttpProcessors {
    pub fn new() -> Self {
        Self {
            parsers: vec![Box::new(Http1ParserAdapter::new()), Box::new(Http2ParserAdapter::new())],
        }
    }

    /// Parse HTTP request data using the appropriate parser
    #[inline]
    pub fn parse_request(&self, data: &[u8]) -> Option<ObservableHttpRequest> {
        // Fast-reject: skip the trait-dispatched parser loop for payloads that
        // obviously can't start an HTTP request or HTTP/2 preface.
        if !looks_like_http_request(data) {
            return None;
        }
        for parser in &self.parsers {
            if parser.can_parse(data) {
                if let Some(result) = parser.parse_request(data) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Parse HTTP response data using the appropriate parser
    #[inline]
    pub fn parse_response(&self, data: &[u8]) -> Option<ObservableHttpResponse> {
        // Fast-reject: skip the parser loop for payloads that don't look like an
        // HTTP/1.x response line or a valid HTTP/2 frame header.
        if !looks_like_http_response(data) {
            return None;
        }
        for parser in &self.parsers {
            if parser.can_parse(data) {
                if let Some(result) = parser.parse_response(data) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Get all supported HTTP versions
    pub fn supported_versions(&self) -> Vec<crate::http::Version> {
        self.parsers.iter().map(|p| p.supported_version()).collect()
    }
}

/// Adapter that bridges HTTP/1.x processor to the unified HttpParser interface
struct Http1ParserAdapter {
    processor: http1_process::Http1Processor,
}

impl Http1ParserAdapter {
    fn new() -> Self {
        Self { processor: http1_process::Http1Processor::new() }
    }
}

impl HttpParser for Http1ParserAdapter {
    fn supported_version(&self) -> crate::http::Version {
        crate::http::Version::V11
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        self.processor.can_process_request(data) || self.processor.can_process_response(data)
    }

    fn name(&self) -> &'static str {
        "HTTP/1.x"
    }

    fn parse_request(&self, data: &[u8]) -> Option<ObservableHttpRequest> {
        self.processor.process_request(data).ok().flatten()
    }

    fn parse_response(&self, data: &[u8]) -> Option<ObservableHttpResponse> {
        self.processor.process_response(data).ok().flatten()
    }
}

/// Adapter that bridges HTTP/2 processor to the unified HttpParser interface
struct Http2ParserAdapter {
    processor: http2_process::Http2Processor,
}

impl Http2ParserAdapter {
    fn new() -> Self {
        Self { processor: http2_process::Http2Processor::new() }
    }
}

impl HttpParser for Http2ParserAdapter {
    fn supported_version(&self) -> crate::http::Version {
        crate::http::Version::V20
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        self.processor.can_process_request(data) || self.processor.can_process_response(data)
    }

    fn name(&self) -> &'static str {
        "HTTP/2"
    }

    fn parse_request(&self, data: &[u8]) -> Option<ObservableHttpRequest> {
        self.processor.process_request(data).ok().flatten()
    }

    fn parse_response(&self, data: &[u8]) -> Option<ObservableHttpResponse> {
        self.processor.process_response(data).ok().flatten()
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

#[inline]
pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetHttpError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetHttpError::UnsupportedProtocol("IPv4".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            http_flows,
            tcp,
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            processors,
        )
    } else {
        Ok(ObservableHttpPackage { http_request: None, http_response: None })
    }
}

#[inline]
pub fn process_http_ipv6(
    packet: &Ipv6Packet,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetHttpError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetHttpError::UnsupportedProtocol("IPv6".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            http_flows,
            tcp,
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            processors,
        )
    } else {
        Ok(ObservableHttpPackage { http_request: None, http_response: None })
    }
}

fn process_tcp_packet(
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    processors: &HttpProcessors,
) -> Result<ObservableHttpPackage, HuginnNetHttpError> {
    let src_port: u16 = tcp.get_source();
    let dst_port: u16 = tcp.get_destination();
    let mut observable_http_package =
        ObservableHttpPackage { http_request: None, http_response: None };

    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    let (tcp_flow, is_client) = {
        if let Some(flow) = http_flows.get_mut(&flow_key) {
            (Some(flow), true)
        } else {
            let reversed_key: FlowKey = (dst_ip, src_ip, dst_port, src_port);
            if let Some(flow) = http_flows.get_mut(&reversed_key) {
                (Some(flow), false)
            } else {
                (None, false)
            }
        }
    };

    if let Some(flow) = tcp_flow {
        if !tcp.payload().is_empty() {
            let tcp_data = TcpData { sequence: tcp.get_sequence(), data: Vec::from(tcp.payload()) };

            if is_client && src_ip == flow.client_ip && src_port == flow.client_port {
                // Only add data and parse if not already parsed
                if !flow.client_http_parsed {
                    flow.client_data.push(tcp_data);
                    let full_data = flow.get_full_data(is_client);
                    match parse_http_request(&full_data, processors) {
                        Ok(Some(http_request_parsed)) => {
                            observable_http_package.http_request = Some(http_request_parsed);
                            flow.client_http_parsed = true;
                        }
                        Ok(None) => {}
                        Err(_e) => {}
                    }
                } else {
                    debug!("CLIENT: HTTP already parsed, discarding additional data");
                }
            } else if src_ip == flow.server_ip && src_port == flow.server_port {
                // Only add data and parse if not already parsed
                if !flow.server_http_parsed {
                    flow.server_data.push(tcp_data);
                    let full_data = flow.get_full_data(is_client);
                    match parse_http_response(&full_data, processors) {
                        Ok(Some(http_response_parsed)) => {
                            observable_http_package.http_response = Some(http_response_parsed);
                            flow.server_http_parsed = true;
                        }
                        Ok(None) => {
                            debug!("SERVER: Data not complete yet, waiting for more");
                        }
                        Err(_e) => {}
                    }
                } else {
                    debug!("SERVER: HTTP already parsed, discarding additional data");
                }
            }

            // Remove from http_flows if both request and response are parsed
            if flow.client_http_parsed && flow.server_http_parsed {
                debug!("Both HTTP request and response parsed, removing from http_flows early");
                http_flows.remove(&flow_key);
                return Ok(observable_http_package);
            }

            // Clean up on connection close
            if tcp.get_flags()
                & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
                != 0
            {
                debug!("Connection closed or reset");
                http_flows.remove(&flow_key);
            }
        }
    } else if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        let tcp_data: TcpData =
            TcpData { sequence: tcp.get_sequence(), data: Vec::from(tcp.payload()) };
        let flow: TcpFlow = TcpFlow::init(src_ip, src_port, dst_ip, dst_port, tcp_data);
        http_flows.insert(flow_key, flow, Duration::new(60, 0));
    }

    Ok(observable_http_package)
}

fn parse_http_request(
    data: &[u8],
    processors: &HttpProcessors,
) -> Result<Option<ObservableHttpRequest>, HuginnNetHttpError> {
    match processors.parse_request(data) {
        Some(request) => {
            debug!("Successfully parsed HTTP request using polymorphic parser");
            Ok(Some(request))
        }
        None => {
            debug!("No HTTP parser could handle request data");
            Ok(None)
        }
    }
}

fn parse_http_response(
    data: &[u8],
    processors: &HttpProcessors,
) -> Result<Option<ObservableHttpResponse>, HuginnNetHttpError> {
    match processors.parse_response(data) {
        Some(response) => {
            debug!("Successfully parsed HTTP response using polymorphic parser");
            Ok(Some(response))
        }
        None => {
            debug!("No HTTP parser could handle response data");
            Ok(None)
        }
    }
}
