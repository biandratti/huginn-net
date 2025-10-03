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

use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::debug;

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

    /// Analyzes network traffic from a live network interface for TLS packets.
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
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> std::result::Result<(), TlsError> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| TlsError::Parse(format!("Interface {interface_name} not found")))?;

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(TlsError::Parse("Unsupported channel type".to_string())),
            Err(e) => return Err(TlsError::Parse(format!("Failed to create channel: {e}"))),
        };

        loop {
            if let Some(ref signal) = cancel_signal {
                if signal.load(Ordering::Relaxed) {
                    break;
                }
            }

            match rx.next() {
                Ok(packet) => {
                    match self.process_packet(packet) {
                        Ok(Some(result)) => {
                            if sender.send(result).is_err() {
                                break; // Receiver dropped
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
                    return Err(TlsError::Parse(format!("Error receiving packet: {e}")));
                }
            }
        }

        Ok(())
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
    ) -> std::result::Result<Option<TlsClientOutput>, TlsError> {
        let ethernet = EthernetPacket::new(packet)
            .ok_or_else(|| TlsError::Parse("Invalid Ethernet packet".to_string()))?;

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    process_ipv4_packet(&ipv4)
                } else {
                    Ok(None)
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    process_ipv6_packet(&ipv6)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
}
