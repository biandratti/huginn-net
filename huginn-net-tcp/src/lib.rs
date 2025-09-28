#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::tcp;

pub mod ip_options;
pub mod mtu;
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
pub use uptime::{Connection, SynData};

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

/// A TCP-focused passive fingerprinting analyzer.
///
/// The `HuginnNetTcp` struct handles TCP packet analysis for OS fingerprinting,
/// MTU detection, and uptime calculation using p0f-style methodologies.
pub struct HuginnNetTcp<'a> {
    pub matcher: Option<SignatureMatcher<'a>>,
}

impl<'a> HuginnNetTcp<'a> {
    /// Creates a new instance of `HuginnNetTcp`.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for OS matching
    ///
    /// # Returns
    /// A new `HuginnNetTcp` instance ready for TCP analysis.
    pub fn new(database: Option<&'a db::Database>) -> Result<Self, HuginnNetError> {
        let matcher = database.map(SignatureMatcher::new);

        Ok(Self { matcher })
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

        // Connection tracker for TCP analysis
        let mut connection_tracker = TtlCache::new(1000);

        loop {
            if let Some(ref signal) = cancel_signal {
                if signal.load(Ordering::Relaxed) {
                    break;
                }
            }

            match rx.next() {
                Ok(packet) => {
                    // Process packet and handle errors gracefully
                    match self.process_packet(packet, &mut connection_tracker) {
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
        connection_tracker: &mut TtlCache<Connection, SynData>,
    ) -> Result<TcpAnalysisResult, HuginnNetError> {
        let ethernet = EthernetPacket::new(packet)
            .ok_or_else(|| HuginnNetError::Parse("Invalid Ethernet packet".to_string()))?;

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    process::process_ipv4_packet(&ipv4, connection_tracker, self.matcher.as_ref())
                } else {
                    Ok(TcpAnalysisResult {
                        syn: None,
                        syn_ack: None,
                        mtu: None,
                        uptime: None,
                    })
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    process::process_ipv6_packet(&ipv6, connection_tracker, self.matcher.as_ref())
                } else {
                    Ok(TcpAnalysisResult {
                        syn: None,
                        syn_ack: None,
                        mtu: None,
                        uptime: None,
                    })
                }
            }
            _ => Ok(TcpAnalysisResult {
                syn: None,
                syn_ack: None,
                mtu: None,
                uptime: None,
            }),
        }
    }
}

/// Represents the output from TCP analysis.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP packets.
#[derive(Debug)]
pub struct TcpAnalysisResult {
    /// Information derived from SYN packets.
    pub syn: Option<SynTCPOutput>,

    /// Information derived from SYN-ACK packets.
    pub syn_ack: Option<SynAckTCPOutput>,

    /// Information about the Maximum Transmission Unit (MTU).
    pub mtu: Option<MTUOutput>,

    /// Information about the system uptime.
    pub uptime: Option<UptimeOutput>,
}
