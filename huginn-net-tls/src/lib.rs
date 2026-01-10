pub mod error;
pub mod filter;
pub mod observable;
pub mod output;
pub mod packet_hash;
pub mod packet_parser;
pub mod parallel;
pub mod process;
pub mod raw_filter;
pub mod tls;
pub mod tls_client_hello_reader;
pub mod tls_process;

// Re-exports
pub use error::*;
pub use filter::*;
pub use observable::*;
pub use output::*;
pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use process::*;
pub use tls::*;
pub use tls_client_hello_reader::TlsClientHelloReader;
pub use tls_process::{
    parse_tls_client_hello, parse_tls_client_hello_ja4, process_tls_ipv4, process_tls_ipv6,
};

use crate::packet_parser::{parse_packet, IpPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

/// Configuration for parallel processing
///
/// Controls the behavior of worker threads in parallel mode.
#[derive(Debug, Clone)]
struct ParallelConfig {
    /// Number of worker threads to spawn
    num_workers: usize,
    /// Size of packet queue per worker (affects memory usage and backpressure)
    queue_size: usize,
    /// Maximum packets to process in one batch before checking for new work
    /// Higher = better throughput, lower = better latency (typical: 16-64)
    batch_size: usize,
    /// Worker receive timeout in milliseconds
    /// Lower = faster shutdown, higher = better throughput (typical: 5-50)
    timeout_ms: u64,
}

/// FlowKey: (Source IP, Destination IP, Source Port, Destination Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

/// A TLS-focused passive fingerprinting analyzer using JA4 methodology.
///
/// The `HuginnNetTls` struct handles TLS packet analysis and JA4 fingerprinting
/// following the official FoxIO specification.
pub struct HuginnNetTls {
    tcp_flows: TtlCache<FlowKey, TlsClientHelloReader>,
    parallel_config: Option<ParallelConfig>,
    worker_pool: Option<Arc<WorkerPool>>,
    filter_config: Option<FilterConfig>,
    max_connections: usize,
}

impl HuginnNetTls {
    /// Creates a new instance of `HuginnNetTls` in sequential mode (single-threaded).
    ///
    /// # Returns
    /// A new `HuginnNetTls` instance ready for TLS analysis.
    pub fn new() -> Self {
        Self::with_max_connections(10000)
    }
}

impl Default for HuginnNetTls {
    fn default() -> Self {
        Self::new()
    }
}

impl HuginnNetTls {
    /// Creates a new instance with a specified maximum number of connections.
    ///
    /// # Parameters
    /// - `max_connections`: Maximum number of TCP flows to track
    ///
    /// # Returns
    /// A new `HuginnNetTls` instance ready for TLS analysis.
    pub fn with_max_connections(max_connections: usize) -> Self {
        Self {
            tcp_flows: TtlCache::new(max_connections),
            parallel_config: None,
            worker_pool: None,
            filter_config: None,
            max_connections,
        }
    }

    /// Configure packet filtering (builder pattern)
    pub fn with_filter(mut self, config: FilterConfig) -> Self {
        self.filter_config = Some(config);
        self
    }

    /// Creates a new instance with full parallel configuration.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads (recommended: 2-4 on 8-core systems)
    /// - `queue_size`: Size of packet queue per worker (typical: 100-200)
    /// - `batch_size`: Maximum packets to process in one batch (typical: 16-64, recommended: 32)
    /// - `timeout_ms`: Worker receive timeout in milliseconds (typical: 5-50, recommended: 10)
    ///
    /// # Configuration Guide
    ///
    /// ## batch_size
    /// - **Low (8-16)**: Lower latency, more responsive, higher overhead
    /// - **Medium (32)**: Balanced throughput and latency *(recommended)*
    /// - **High (64-128)**: Maximum throughput, higher latency
    ///
    /// ## timeout_ms
    /// - **Low (5-10ms)**: Fast shutdown, slightly lower throughput *(recommended: 10)*
    /// - **Medium (20-50ms)**: Better throughput, slower shutdown
    /// - **High (100ms+)**: Maximum throughput, slow shutdown
    ///
    /// # Example
    /// ```rust,no_run
    /// use huginn_net_tls::HuginnNetTls;
    ///
    /// // Balanced configuration (recommended)
    /// let tls = HuginnNetTls::with_config(4, 100, 32, 10);
    ///
    /// // Low latency
    /// let low_latency = HuginnNetTls::with_config(2, 100, 8, 5);
    ///
    /// // High throughput
    /// let high_throughput = HuginnNetTls::with_config(4, 200, 64, 20);
    /// ```
    ///
    /// # Returns
    /// A new `HuginnNetTls` instance with parallel configuration.
    pub fn with_config(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
    ) -> Self {
        Self::with_config_and_max_connections(
            num_workers,
            queue_size,
            batch_size,
            timeout_ms,
            10000,
        )
    }

    /// Creates a new instance with full parallel configuration and max connections.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads
    /// - `queue_size`: Size of packet queue per worker
    /// - `batch_size`: Maximum packets to process in one batch
    /// - `timeout_ms`: Worker receive timeout in milliseconds
    /// - `max_connections`: Maximum number of TCP flows to track
    ///
    /// # Returns
    /// A new `HuginnNetTls` instance with parallel configuration.
    pub fn with_config_and_max_connections(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
        max_connections: usize,
    ) -> Self {
        Self {
            tcp_flows: TtlCache::new(max_connections),
            parallel_config: Some(ParallelConfig {
                num_workers,
                queue_size,
                batch_size,
                timeout_ms,
            }),
            worker_pool: None,
            filter_config: None,
            max_connections,
        }
    }

    /// Get worker pool statistics (only available in parallel mode, after analyze_* is called)
    ///
    /// # Returns
    /// `Some(PoolStats)` if parallel mode is active, `None` otherwise
    pub fn stats(&self) -> Option<PoolStats> {
        self.worker_pool.as_ref().map(|pool| pool.stats())
    }

    /// Get a reference to the worker pool (only available in parallel mode, after analyze_* is called)
    ///
    /// # Returns
    /// `Some(Arc<WorkerPool>)` if parallel mode is active, `None` otherwise
    pub fn worker_pool(&self) -> Option<Arc<WorkerPool>> {
        self.worker_pool.clone()
    }

    /// Initialize the worker pool (only for parallel mode, called automatically by analyze_*)
    ///
    /// This can be called explicitly to get the pool reference before starting analysis
    ///
    /// # Errors
    /// - If the worker pool creation fails.
    ///
    pub fn init_pool(&mut self, sender: Sender<TlsClientOutput>) -> Result<(), HuginnNetTlsError> {
        if let Some(config) = &self.parallel_config {
            if self.worker_pool.is_none() {
                let worker_pool = Arc::new(WorkerPool::new(
                    config.num_workers,
                    config.queue_size,
                    config.batch_size,
                    config.timeout_ms,
                    sender,
                    self.max_connections,
                    self.filter_config.clone(),
                )?);
                self.worker_pool = Some(worker_pool);
            }
        }
        Ok(())
    }

    fn process_with<F>(
        &mut self,
        packet_fn: F,
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTlsError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTlsError>>,
    {
        if self.parallel_config.is_some() {
            self.process_parallel(packet_fn, sender, cancel_signal)
        } else {
            self.process_sequential(packet_fn, sender, cancel_signal)
        }
    }

    fn process_parallel<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<TlsClientOutput>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTlsError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTlsError>>,
    {
        let config = self
            .parallel_config
            .as_ref()
            .ok_or_else(|| HuginnNetTlsError::Parse("Parallel config not found".to_string()))?;

        if self.worker_pool.is_none() {
            let worker_pool = Arc::new(WorkerPool::new(
                config.num_workers,
                config.queue_size,
                config.batch_size,
                config.timeout_ms,
                sender,
                self.max_connections,
                self.filter_config.clone(),
            )?);
            self.worker_pool = Some(worker_pool);
        }

        let worker_pool = self
            .worker_pool
            .as_ref()
            .ok_or_else(|| HuginnNetTlsError::Parse("Worker pool not initialized".to_string()))?
            .clone();

        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    let _ = worker_pool.dispatch(packet);
                }
                Err(e) => {
                    error!("Failed to read packet: {e}");
                }
            }
        }

        Ok(())
    }

    fn process_sequential<F>(
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
                Ok(packet) => match self.process_packet(&packet) {
                    Ok(Some(result)) => {
                        if sender.send(result).is_err() {
                            error!("Receiver dropped, stopping packet processing");
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!("No TLS found, continuing packet processing");
                    }
                    Err(tls_error) => {
                        debug!("Error processing packet: {tls_error}");
                    }
                },
                Err(e) => {
                    error!("Failed to read packet: {e}");
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

        let config = Config { promiscuous: true, ..Config::default() };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(HuginnNetTlsError::Parse("Unhandled channel type".to_string())),
            Err(e) => {
                return Err(HuginnNetTlsError::Parse(format!("Unable to create channel: {e}")))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => {
                    Some(Err(HuginnNetTlsError::Parse(format!("Error receiving packet: {e}"))))
                }
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
                Some(Err(e)) => {
                    Some(Err(HuginnNetTlsError::Parse(format!("Error reading PCAP packet: {e}"))))
                }
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
    ) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
        if let Some(ref filter) = self.filter_config {
            if !raw_filter::apply(packet, filter) {
                debug!("Filtered out packet before parsing");
                return Ok(None);
            }
        }

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => crate::process::process_ipv4_packet(&ipv4, &mut self.tcp_flows),
            IpPacket::Ipv6(ipv6) => crate::process::process_ipv6_packet(&ipv6, &mut self.tcp_flows),
            IpPacket::None => Ok(None),
        }
    }
}
