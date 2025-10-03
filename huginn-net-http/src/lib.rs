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

use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::debug;
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
    ) -> Result<Self, HuginnNetError> {
        let matcher = database.map(SignatureMatcher::new);

        Ok(Self {
            matcher,
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
        })
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
    ) -> Result<(), HuginnNetError> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetError::Parse(format!("Interface {interface_name} not found"))
            })?;

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx), // tx is unused, but required by pnet
            Ok(_) => {
                return Err(HuginnNetError::Parse(
                    "Unsupported channel type".to_string(),
                ))
            }
            Err(e) => {
                return Err(HuginnNetError::Parse(format!(
                    "Failed to create channel: {e}"
                )))
            }
        };

        loop {
            if let Some(ref signal) = cancel_signal {
                if signal.load(Ordering::Relaxed) {
                    break;
                }
            }

            match rx.next() {
                Ok(packet) => {
                    // Process packet and handle errors gracefully
                    match self.process_packet(packet) {
                        Ok(result) => {
                            if sender.send(result).is_err() {
                                break;
                            }
                        }
                        Err(huginn_error) => {
                            debug!("Error processing packet: {}", huginn_error);
                        }
                    }
                }
                Err(e) => {
                    return Err(HuginnNetError::Parse(format!(
                        "Error receiving packet: {e}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Processes a single packet and extracts HTTP information if present.
    ///
    /// # Parameters
    /// - `packet`: The raw packet data.
    ///
    /// # Returns
    /// A `Result` containing an `HttpAnalysisResult` or an error.
    fn process_packet(&mut self, packet: &[u8]) -> Result<HttpAnalysisResult, HuginnNetError> {
        let ethernet = EthernetPacket::new(packet)
            .ok_or_else(|| HuginnNetError::Parse("Invalid Ethernet packet".to_string()))?;

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
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
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
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
            _ => Ok(HttpAnalysisResult {
                http_request: None,
                http_response: None,
            }),
        }
    }
}
