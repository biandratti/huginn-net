use crate::error::HuginnNetError;
use crate::http_common::HttpProcessor;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::tls_decryption::{CipherSuite, TlsConnectionState, TlsDecryptor};
use crate::{http1_process, http2_process};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::Duration;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsRecordType};
use tracing::debug;
use ttl_cache::TtlCache;

/// FlowKey: (Client IP, Server IP, Client Port, Server Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

/// HTTPS processor that handles TLS decryption and HTTP processing
pub struct HttpsProcessor {
    tls_decryptor: Option<TlsDecryptor>,
    http_processors: HttpProcessors,
}

impl HttpsProcessor {
    /// Create new HTTPS processor
    pub fn new(tls_decryptor: Option<TlsDecryptor>) -> Self {
        Self {
            tls_decryptor,
            http_processors: HttpProcessors::new(),
        }
    }

    /// Process HTTPS data by decrypting and then parsing HTTP
    pub fn process_https_data(
        &mut self,
        flow_key: &FlowKey,
        encrypted_data: &[u8],
        is_client_data: bool,
    ) -> Result<Option<(ObservableHttpRequest, ObservableHttpResponse)>, HuginnNetError> {
        let decryptor = match &mut self.tls_decryptor {
            Some(d) => d,
            None => {
                return Err(HuginnNetError::Parse(
                    "No TLS decryptor available".to_string(),
                ))
            }
        };

        // Create connection ID from flow key
        let connection_id = format!(
            "{}:{}->{}:{}",
            flow_key.0, flow_key.2, flow_key.1, flow_key.3
        );

        // Decrypt the data
        let decrypted_data =
            decryptor.decrypt_record(&connection_id, encrypted_data, is_client_data)?;

        // Parse the decrypted HTTP data
        let request = if is_client_data {
            self.http_processors.parse_request(&decrypted_data)
        } else {
            None
        };

        let response = if !is_client_data {
            self.http_processors.parse_response(&decrypted_data)
        } else {
            None
        };

        Ok(match (request, response) {
            (Some(req), None) => Some((
                req,
                ObservableHttpResponse {
                    version: crate::http::Version::V11,
                    horder: Vec::new(),
                    habsent: Vec::new(),
                    expsw: String::new(),
                    headers: Vec::new(),
                    status_code: None,
                },
            )),
            (None, Some(resp)) => Some((
                ObservableHttpRequest {
                    lang: None,
                    user_agent: None,
                    version: crate::http::Version::V11,
                    horder: Vec::new(),
                    habsent: Vec::new(),
                    expsw: String::new(),
                    headers: Vec::new(),
                    cookies: Vec::new(),
                    referer: None,
                    method: None,
                    uri: None,
                },
                resp,
            )),
            (Some(req), Some(resp)) => Some((req, resp)),
            (None, None) => None,
        })
    }

    /// Setup TLS connection for decryption
    pub fn setup_tls_connection(
        &mut self,
        flow_key: &FlowKey,
        connection_state: TlsConnectionState,
    ) -> Result<(), HuginnNetError> {
        if let Some(decryptor) = &mut self.tls_decryptor {
            let connection_id = format!(
                "{}:{}->{}:{}",
                flow_key.0, flow_key.2, flow_key.1, flow_key.3
            );
            decryptor.add_connection(connection_id, connection_state);
            debug!("Setup TLS connection for decryption: {:?}", flow_key);
        }
        Ok(())
    }
}

use crate::http_common::HttpParser;

/// HTTP parser that automatically detects and processes different HTTP versions
pub struct HttpProcessors {
    parsers: Vec<Box<dyn HttpParser>>,
}

impl HttpProcessors {
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(Http1ParserAdapter::new()),
                Box::new(Http2ParserAdapter::new()),
            ],
        }
    }

    /// Parse HTTP request data using the appropriate parser
    pub fn parse_request(&self, data: &[u8]) -> Option<ObservableHttpRequest> {
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
    pub fn parse_response(&self, data: &[u8]) -> Option<ObservableHttpResponse> {
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
        Self {
            processor: http1_process::Http1Processor::new(),
        }
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
        Self {
            processor: http2_process::Http2Processor::new(),
        }
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
    timestamp: std::time::Instant,
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
    // TLS/HTTPS support
    is_tls: bool,
    tls_handshake_complete: bool,
    client_random: Option<Vec<u8>>,
    server_random: Option<Vec<u8>>,
    cipher_suite: Option<CipherSuite>,
    tls_version: Option<u16>,
}

/// Quick check if HTTP data is complete for parsing (supports HTTP/1.x and HTTP/2)
fn has_complete_http_data(data: &[u8], processors: &HttpProcessors) -> bool {
    // Strategy: Don't make early decisions about protocol due to TCP fragmentation
    // Wait until we have enough data to make a reliable determination

    if data.len() < 4 {
        // Not enough data yet, wait for more TCP packets
        return false;
    }

    // Try to parse with any available parser - if successful, data is complete
    processors.parse_request(data).is_some() || processors.parse_response(data).is_some()
}

impl TcpFlow {
    fn init(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        tcp_data: TcpData,
    ) -> TcpFlow {
        // Detect if this might be TLS based on destination port
        let is_tls = dst_port == 443 || src_port == 443;

        TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            client_data: vec![tcp_data],
            server_data: Vec::new(),
            client_http_parsed: false,
            server_http_parsed: false,
            // TLS/HTTPS fields
            is_tls,
            tls_handshake_complete: false,
            client_random: None,
            server_random: None,
            cipher_suite: None,
            tls_version: None,
        }
    }
    /// Traversing all the data in arrival order to preserve original packet sequence
    /// This preserves HTTP header order as seen on the wire, which is critical for
    /// accurate fingerprinting when packets pass through proxies or load balancers.
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

        sorted_data.sort_by_key(|tcp_data| tcp_data.timestamp);

        let mut full_data = Vec::new();
        for tcp_data in sorted_data {
            full_data.extend_from_slice(&tcp_data.data);
        }
        full_data
    }

    /// Check if this flow is TLS/HTTPS
    fn is_tls_flow(&self) -> bool {
        self.is_tls
    }

    /// Process TLS handshake data to extract connection parameters
    fn process_tls_handshake(
        &mut self,
        data: &[u8],
        is_client_data: bool,
    ) -> Result<(), HuginnNetError> {
        if !self.is_tls {
            return Ok(());
        }

        // Parse TLS records from the data
        let mut remaining = data;
        while !remaining.is_empty() {
            match parse_tls_plaintext(remaining) {
                Ok((rest, tls_record)) => {
                    remaining = rest;

                    // Process handshake messages
                    if tls_record.hdr.record_type == TlsRecordType::Handshake {
                        for message in &tls_record.msg {
                            if let TlsMessage::Handshake(handshake_msg) = message {
                                self.extract_handshake_info(handshake_msg, is_client_data)?;
                            }
                        }
                    }
                }
                Err(_) => {
                    // Not valid TLS data or incomplete, break
                    break;
                }
            }
        }

        Ok(())
    }

    /// Extract handshake information from TLS messages
    fn extract_handshake_info(
        &mut self,
        handshake_msg: &TlsMessageHandshake,
        is_client_data: bool,
    ) -> Result<(), HuginnNetError> {
        match handshake_msg {
            TlsMessageHandshake::ClientHello(client_hello) => {
                if is_client_data {
                    // Extract client random
                    self.client_random = Some(client_hello.random.to_vec());
                    debug!("Extracted client random from ClientHello");
                }
            }
            TlsMessageHandshake::ServerHello(server_hello) => {
                if !is_client_data {
                    // Extract server random and cipher suite
                    self.server_random = Some(server_hello.random.to_vec());

                    // Convert cipher suite
                    if let Some(cipher) = CipherSuite::from_u16(server_hello.cipher.0) {
                        debug!("Extracted cipher suite: {:?}", cipher);
                        self.cipher_suite = Some(cipher);
                    }

                    // Extract TLS version
                    self.tls_version = Some(server_hello.version.0);

                    // Check if handshake is complete enough for decryption
                    if self.client_random.is_some()
                        && self.server_random.is_some()
                        && self.cipher_suite.is_some()
                    {
                        self.tls_handshake_complete = true;
                        debug!("TLS handshake parameters complete");
                    }
                }
            }
            _ => {
                // Other handshake messages (certificates, key exchange, etc.)
                // For now, we don't need to process these for decryption
            }
        }

        Ok(())
    }

    /// Get TLS connection state for decryption
    #[allow(dead_code)]
    fn get_tls_connection_state(&self) -> Option<TlsConnectionState> {
        if !self.tls_handshake_complete {
            return None;
        }

        let client_random = self.client_random.as_ref()?.clone();
        let server_random = self.server_random.as_ref()?.clone();
        let cipher_suite = self.cipher_suite.as_ref()?.clone();
        let tls_version = self.tls_version?;

        Some(TlsConnectionState::new(
            client_random,
            server_random,
            cipher_suite,
            tls_version,
        ))
    }

    /// Check if TLS handshake is complete
    fn is_tls_handshake_complete(&self) -> bool {
        self.tls_handshake_complete
    }
}

pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    processors: &HttpProcessors,
    config: &crate::AnalysisConfig,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv4".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            http_flows,
            tcp,
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            processors,
            config,
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
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    processors: &HttpProcessors,
    config: &crate::AnalysisConfig,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv6".to_string()));
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            http_flows,
            tcp,
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            processors,
            config,
        )
    } else {
        Ok(ObservableHttpPackage {
            http_request: None,
            http_response: None,
        })
    }
}

fn process_tcp_packet(
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    processors: &HttpProcessors,
    config: &crate::AnalysisConfig,
) -> Result<ObservableHttpPackage, HuginnNetError> {
    let src_port: u16 = tcp.get_source();
    let dst_port: u16 = tcp.get_destination();
    let mut observable_http_package = ObservableHttpPackage {
        http_request: None,
        http_response: None,
    };

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
            let tcp_data = TcpData {
                timestamp: std::time::Instant::now(),
                data: Vec::from(tcp.payload()),
            };

            if is_client && src_ip == flow.client_ip && src_port == flow.client_port {
                // Only add data and parse if not already parsed
                if !flow.client_http_parsed {
                    flow.client_data.push(tcp_data.clone());

                    // Handle TLS/HTTPS processing
                    if flow.is_tls_flow() && config.https_enabled {
                        // Process TLS handshake if not complete
                        if !flow.is_tls_handshake_complete() {
                            if let Err(e) = flow.process_tls_handshake(&tcp_data.data, true) {
                                debug!("Failed to process TLS handshake: {}", e);
                            }
                        }

                        // If handshake is complete, try to decrypt and parse HTTP
                        if flow.is_tls_handshake_complete() {
                            // For HTTPS, we need the full encrypted data
                            let _full_data = flow.get_full_data(is_client);

                            // Try to decrypt and parse as HTTP (this is a simplified approach)
                            // In a real implementation, we'd need to identify TLS application data records
                            debug!("HTTPS: Handshake complete, ready for decryption");
                            // TODO: Implement actual HTTPS decryption here
                        }
                    } else {
                        // Regular HTTP processing
                        let full_data = flow.get_full_data(is_client);

                        // Quick check before expensive parsing (supports HTTP/1.x and HTTP/2)
                        if has_complete_http_data(&full_data, processors) {
                            match parse_http_request(&full_data, processors) {
                                Ok(Some(http_request_parsed)) => {
                                    observable_http_package.http_request =
                                        Some(http_request_parsed);
                                    flow.client_http_parsed = true;
                                }
                                Ok(None) => {}
                                Err(_e) => {}
                            }
                        }
                    }
                } else {
                    debug!("CLIENT: HTTP already parsed, discarding additional data");
                }
            } else if src_ip == flow.server_ip && src_port == flow.server_port {
                // Only add data and parse if not already parsed
                if !flow.server_http_parsed {
                    flow.server_data.push(tcp_data.clone());

                    // Handle TLS/HTTPS processing
                    if flow.is_tls_flow() && config.https_enabled {
                        // Process TLS handshake if not complete
                        if !flow.is_tls_handshake_complete() {
                            if let Err(e) = flow.process_tls_handshake(&tcp_data.data, false) {
                                debug!("Failed to process TLS handshake: {}", e);
                            }
                        }

                        // If handshake is complete, try to decrypt and parse HTTP
                        if flow.is_tls_handshake_complete() {
                            // For HTTPS, we need the full encrypted data
                            let _full_data = flow.get_full_data(is_client);

                            // Try to decrypt and parse as HTTP (this is a simplified approach)
                            debug!("HTTPS: Server handshake complete, ready for decryption");
                            // TODO: Implement actual HTTPS decryption here
                        }
                    } else {
                        // Regular HTTP processing
                        let full_data = flow.get_full_data(is_client);

                        // Quick check before expensive parsing (supports HTTP/1.x and HTTP/2)
                        if has_complete_http_data(&full_data, processors) {
                            match parse_http_response(&full_data, processors) {
                                Ok(Some(http_response_parsed)) => {
                                    observable_http_package.http_response =
                                        Some(http_response_parsed);
                                    flow.server_http_parsed = true;
                                }
                                Ok(None) => {}
                                Err(_e) => {}
                            }
                        } else {
                            debug!("SERVER: Data not complete yet, waiting for more");
                        }
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
        let tcp_data: TcpData = TcpData {
            timestamp: std::time::Instant::now(),
            data: Vec::from(tcp.payload()),
        };
        let flow: TcpFlow = TcpFlow::init(src_ip, src_port, dst_ip, dst_port, tcp_data);
        http_flows.insert(flow_key, flow, Duration::new(60, 0));
    }

    Ok(observable_http_package)
}

fn parse_http_request(
    data: &[u8],
    processors: &HttpProcessors,
) -> Result<Option<ObservableHttpRequest>, HuginnNetError> {
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
) -> Result<Option<ObservableHttpResponse>, HuginnNetError> {
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
