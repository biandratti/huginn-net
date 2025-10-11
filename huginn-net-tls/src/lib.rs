pub mod datalink_parser;
pub mod error;
pub mod observable;
pub mod output;
pub mod process;
pub mod tls;
pub mod tls_process;

// Re-exports
pub use error::*;
pub use observable::*;
pub use output::*;
pub use process::*;
pub use tls::*;
pub use tls_process::*;

use crate::datalink_parser::{parse_packet, ParsedPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};

/// A TLS-focused passive fingerprinting analyzer using JA4 methodology.
///
/// The `HuginnNetTls` struct handles TLS packet analysis and JA4 fingerprinting
/// following the official FoxIO specification.
pub struct HuginnNetTls;

impl Default for HuginnNetTls {
    fn default() -> Self {
        Self
    }
}

impl HuginnNetTls {
    /// Creates a new instance of `HuginnNetTls`.
    ///
    /// # Returns
    /// A new `HuginnNetTls` instance ready for TLS analysis.
    pub fn new() -> Self {
        Self
    }

    fn process_with<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTlsError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTlsError>>,
    {
        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    match self.process_packet(&packet) {
                        Ok(Some(result)) => {
                            if sender.send(result).is_err() {
                                error!("Receiver dropped, stopping packet processing");
                                break;
                            }
                        }
                        Ok(None) => {
                            // No TLS found, continue processing
                        }
                        Err(tls_error) => {
                            debug!("Error processing packet: {}", tls_error);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Captures and analyzes packets on the specified network interface.
    ///
    /// Sends `TlsClientOutput` through the provided channel.
    ///
    /// # Parameters
    /// - `interface_name`: The name of the network interface to analyze.
    /// - `sender`: A `Sender` to send `TlsClientOutput` objects back to the caller.
    /// - `cancel_signal`: Optional `Arc<AtomicBool>` to signal graceful shutdown.
    ///
    /// # Errors
    /// - If the network interface cannot be found or a channel cannot be created.
    pub fn analyze_network(
        &mut self,
        interface_name: &str,
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTlsError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetTlsError::Parse(format!(
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
                return Err(HuginnNetTlsError::Parse(
                    "Unhandled channel type".to_string(),
                ))
            }
            Err(e) => {
                return Err(HuginnNetTlsError::Parse(format!(
                    "Unable to create channel: {e}"
                )))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => Some(Err(HuginnNetTlsError::Parse(format!(
                    "Error receiving packet: {e}"
                )))),
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes packets from a PCAP file.
    ///
    /// # Parameters
    /// - `pcap_path`: The path to the PCAP file to analyze.
    /// - `sender`: A `Sender` to send `TlsClientOutput` objects back to the caller.
    /// - `cancel_signal`: Optional `Arc<AtomicBool>` to signal graceful shutdown.
    ///
    /// # Errors
    /// - If the PCAP file cannot be opened or read.
    pub fn analyze_pcap(
        &mut self,
        pcap_path: &str,
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTlsError> {
        let file = File::open(pcap_path)
            .map_err(|e| HuginnNetTlsError::Parse(format!("Failed to open PCAP file: {e}")))?;
        let mut pcap_reader = PcapReader::new(file)
            .map_err(|e| HuginnNetTlsError::Parse(format!("Failed to create PCAP reader: {e}")))?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => Some(Err(HuginnNetTlsError::Parse(format!(
                    "Error reading PCAP packet: {e}"
                )))),
                None => None,
            },
            sender,
            cancel_signal,
        )
    }

    /// Processes a single packet and extracts TLS information if present.
    ///
    /// # Parameters
    /// - `packet`: The raw packet data.
    ///
    /// # Returns
    /// A `Result` containing an optional `TlsClientOutput` or an error.
    fn process_packet(
        &mut self,
        packet: &[u8],
    ) -> std::result::Result<Option<TlsClientOutput>, HuginnNetTlsError> {
        match parse_packet(packet) {
            ParsedPacket::Ipv4(ip_data) => {
                if let Some(ipv4) = pnet::packet::ipv4::Ipv4Packet::new(ip_data) {
                    process_ipv4_packet(&ipv4)
                } else {
                    Ok(None)
                }
            }
            ParsedPacket::Ipv6(ip_data) => {
                if let Some(ipv6) = pnet::packet::ipv6::Ipv6Packet::new(ip_data) {
                    process_ipv6_packet(&ipv6)
                } else {
                    Ok(None)
                }
            }
            ParsedPacket::None => Ok(None),
        }
    }
}
