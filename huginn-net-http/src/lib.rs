#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::http;

pub mod http1_parser;
pub mod http1_process;
pub mod http2_parser;
pub mod http2_process;
pub mod http_common;
pub mod http_languages;
pub mod http_process;
pub mod packet_parser;

pub mod display;
pub mod error;
pub mod observable;
pub mod output;
pub mod process;
pub mod signature_matcher;

// Re-exports
pub use error::*;
pub use http_process::*;
pub use observable::*;
pub use output::*;
pub use process::*;
pub use signature_matcher::*;

use crate::packet_parser::{parse_packet, IpPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

/// An HTTP-focused passive fingerprinting analyzer.
///
/// The `HuginnNetHttp` struct handles HTTP packet analysis for browser fingerprinting,
/// web server detection, and HTTP protocol analysis using p0f-style methodologies.
pub struct HuginnNetHttp<'a> {
    pub matcher: Option<SignatureMatcher<'a>>,
    http_flows: TtlCache<FlowKey, TcpFlow>,
    http_processors: HttpProcessors,
}

impl<'a> HuginnNetHttp<'a> {
    /// Creates a new instance of `HuginnNetHttp`.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for HTTP matching
    /// - `max_connections`: Maximum number of HTTP flows to track
    ///
    /// # Returns
    /// A new `HuginnNetHttp` instance ready for HTTP analysis.
    pub fn new(
        database: Option<&'a db::Database>,
        max_connections: usize,
    ) -> Result<Self, HuginnNetHttpError> {
        let matcher = database.map(SignatureMatcher::new);

        Ok(Self {
            matcher,
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
        })
    }

    fn process_with<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => match self.process_packet(&packet) {
                    Ok(result) => {
                        if sender.send(result).is_err() {
                            error!("Receiver dropped, stopping packet processing");
                            break;
                        }
                    }
                    Err(http_error) => {
                        debug!("Error processing packet: {}", http_error);
                    }
                },
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Analyzes network traffic from a live network interface for HTTP packets.
    ///
    /// # Parameters
    /// - `interface_name`: The name of the network interface to capture from.
    /// - `sender`: A channel sender to send analysis results.
    /// - `cancel_signal`: Optional atomic boolean to signal cancellation.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    pub fn analyze_network(
        &mut self,
        interface_name: &str,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetHttpError::Parse(format!(
                    "Could not find network interface: {interface_name}"
                ))
            })?;

        debug!("Using network interface: {}", interface.name);

        let config = Config {
            promiscuous: true,
            ..Config::default()
        };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(HuginnNetHttpError::Parse(
                    "Unhandled channel type".to_string(),
                ))
            }
            Err(e) => {
                return Err(HuginnNetHttpError::Parse(format!(
                    "Unable to create channel: {e}"
                )))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => Some(Err(HuginnNetHttpError::Parse(format!(
                    "Error receiving packet: {e}"
                )))),
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes HTTP packets from a PCAP file.
    ///
    /// # Parameters
    /// - `pcap_path`: Path to the PCAP file to analyze.
    /// - `sender`: A channel sender to send analysis results.
    /// - `cancel_signal`: Optional atomic boolean to signal cancellation.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    pub fn analyze_pcap(
        &mut self,
        pcap_path: &str,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError> {
        let file = File::open(pcap_path)
            .map_err(|e| HuginnNetHttpError::Parse(format!("Failed to open PCAP file: {e}")))?;
        let mut pcap_reader = PcapReader::new(file)
            .map_err(|e| HuginnNetHttpError::Parse(format!("Failed to create PCAP reader: {e}")))?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => Some(Err(HuginnNetHttpError::Parse(format!(
                    "Error reading PCAP packet: {e}"
                )))),
                None => None,
            },
            sender,
            cancel_signal,
        )
    }

    /// Processes a single packet and extracts HTTP information if present.
    ///
    /// # Parameters
    /// - `packet`: The raw packet data.
    ///
    /// # Returns
    /// A `Result` containing an `HttpAnalysisResult` or an error.
    fn process_packet(&mut self, packet: &[u8]) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::ipv6::Ipv6Packet;

        match parse_packet(packet) {
            IpPacket::Ipv4(ip_data) => {
                if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                    process::process_ipv4_packet(
                        &ipv4,
                        &mut self.http_flows,
                        &self.http_processors,
                        self.matcher.as_ref(),
                    )
                } else {
                    Ok(HttpAnalysisResult {
                        http_request: None,
                        http_response: None,
                    })
                }
            }
            IpPacket::Ipv6(ip_data) => {
                if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                    process::process_ipv6_packet(
                        &ipv6,
                        &mut self.http_flows,
                        &self.http_processors,
                        self.matcher.as_ref(),
                    )
                } else {
                    Ok(HttpAnalysisResult {
                        http_request: None,
                        http_response: None,
                    })
                }
            }
            IpPacket::None => Ok(HttpAnalysisResult {
                http_request: None,
                http_response: None,
            }),
        }
    }
}
