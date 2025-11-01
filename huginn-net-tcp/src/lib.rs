#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::tcp;

pub mod ip_options;
pub mod mtu;
pub mod packet_parser;
pub mod tcp_process;
pub mod ttl;
pub mod uptime;
pub mod window_size;

pub mod display;
pub mod error;
pub mod observable;
pub mod output;
pub mod process;
pub mod signature_matcher;

// Re-exports
pub use error::*;
pub use observable::*;
pub use output::*;
pub use process::*;
pub use signature_matcher::*;
pub use tcp_process::*;
pub use uptime::{
    calculate_uptime_improved, Connection, ConnectionKey, FrequencyState, TcpTimestamp,
    UptimeTracker,
};

use crate::packet_parser::{parse_packet, IpPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

/// A TCP-focused passive fingerprinting analyzer.
///
/// The `HuginnNetTcp` struct handles TCP packet analysis for OS fingerprinting,
/// MTU detection, and uptime calculation using p0f-style methodologies.
pub struct HuginnNetTcp<'a> {
    pub matcher: Option<SignatureMatcher<'a>>,
    max_connections: usize,
}

impl<'a> HuginnNetTcp<'a> {
    /// Creates a new instance of `HuginnNetTcp`.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for OS matching
    /// - `max_connections`: Maximum number of connections to track in the connection tracker
    ///
    /// # Returns
    /// A new `HuginnNetTcp` instance ready for TCP analysis.
    pub fn new(
        database: Option<&'a db::Database>,
        max_connections: usize,
    ) -> Result<Self, HuginnNetTcpError> {
        let matcher = database.map(SignatureMatcher::new);

        Ok(Self { matcher, max_connections })
    }

    fn process_with<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTcpError>>,
    {
        // Connection tracker for TCP analysis
        let mut connection_tracker = TtlCache::new(self.max_connections);

        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => match self.process_packet(&packet, &mut connection_tracker) {
                    Ok(result) => {
                        if sender.send(result).is_err() {
                            error!("Receiver dropped, stopping packet processing");
                            break;
                        }
                    }
                    Err(tcp_error) => {
                        debug!("Error processing packet: {}", tcp_error);
                    }
                },
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Analyzes network traffic from a live network interface for TCP packets.
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
        sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetTcpError::Parse(format!(
                    "Could not find network interface: {interface_name}"
                ))
            })?;

        debug!("Using network interface: {}", interface.name);

        let config = Config { promiscuous: true, ..Config::default() };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(HuginnNetTcpError::Parse("Unhandled channel type".to_string())),
            Err(e) => {
                return Err(HuginnNetTcpError::Parse(format!("Unable to create channel: {e}")))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => {
                    Some(Err(HuginnNetTcpError::Parse(format!("Error receiving packet: {e}"))))
                }
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes TCP packets from a PCAP file.
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
        sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError> {
        let file = File::open(pcap_path)
            .map_err(|e| HuginnNetTcpError::Parse(format!("Failed to open PCAP file: {e}")))?;
        let mut pcap_reader = PcapReader::new(file)
            .map_err(|e| HuginnNetTcpError::Parse(format!("Failed to create PCAP reader: {e}")))?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => {
                    Some(Err(HuginnNetTcpError::Parse(format!("Error reading PCAP packet: {e}"))))
                }
                None => None,
            },
            sender,
            cancel_signal,
        )
    }

    /// Processes a single packet and extracts TCP information if present.
    ///
    /// # Parameters
    /// - `packet`: The raw packet data.
    /// - `connection_tracker`: Mutable reference to connection tracker.
    ///
    /// # Returns
    /// A `Result` containing a `TcpAnalysisResult` or an error.
    fn process_packet(
        &self,
        packet: &[u8],
        connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    ) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
        match parse_packet(packet) {
            IpPacket::Ipv4(ip_data) => {
                if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                    process_ipv4_packet(&ipv4, connection_tracker, self.matcher.as_ref())
                } else {
                    Ok(TcpAnalysisResult {
                        syn: None,
                        syn_ack: None,
                        mtu: None,
                        client_uptime: None,
                        server_uptime: None,
                    })
                }
            }
            IpPacket::Ipv6(ip_data) => {
                if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                    process_ipv6_packet(&ipv6, connection_tracker, self.matcher.as_ref())
                } else {
                    Ok(TcpAnalysisResult {
                        syn: None,
                        syn_ack: None,
                        mtu: None,
                        client_uptime: None,
                        server_uptime: None,
                    })
                }
            }
            IpPacket::None => Ok(TcpAnalysisResult {
                syn: None,
                syn_ack: None,
                mtu: None,
                client_uptime: None,
                server_uptime: None,
            }),
        }
    }
}
