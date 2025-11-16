#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::tcp;

pub mod ip_options;
pub mod mtu;
pub mod packet_hash;
pub mod packet_parser;
pub mod parallel;
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
pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
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
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

/// Configuration for parallel processing.
#[derive(Debug, Clone, Copy)]
pub struct ParallelConfig {
    pub num_workers: usize,
    pub queue_size: usize,
    pub batch_size: usize,
    pub timeout_ms: u64,
}

/// A TCP-focused passive fingerprinting analyzer.
///
/// The `HuginnNetTcp` struct handles TCP packet analysis for OS fingerprinting,
/// MTU detection, and uptime calculation using p0f-style methodologies.
///
/// Supports both sequential (single-threaded) and parallel (multi-threaded) processing modes.
pub struct HuginnNetTcp {
    matcher: Option<Arc<db::Database>>,
    max_connections: usize,
    parallel_config: Option<ParallelConfig>,
    worker_pool: Option<Arc<WorkerPool>>,
}

impl HuginnNetTcp {
    /// Creates a new instance of `HuginnNetTcp` in sequential mode.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for OS matching
    /// - `max_connections`: Maximum number of connections to track in the connection tracker
    ///
    /// # Returns
    /// A new `HuginnNetTcp` instance ready for sequential TCP analysis.
    pub fn new(
        database: Option<Arc<db::Database>>,
        max_connections: usize,
    ) -> Result<Self, HuginnNetTcpError> {
        Ok(Self { matcher: database, max_connections, parallel_config: None, worker_pool: None })
    }

    /// Creates a new instance of `HuginnNetTcp` configured for parallel processing.
    ///
    /// Uses hash-based worker assignment to ensure packets from the same source IP
    /// always go to the same worker, maintaining state consistency.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for OS matching
    /// - `max_connections`: Maximum number of connections to track per worker (typical: 1000)
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
    /// use huginn_net_tcp::HuginnNetTcp;
    /// use huginn_net_db::Database;
    /// use std::sync::Arc;
    ///
    /// let db = Arc::new(Database::load_default().expect("Failed to load database"));
    ///
    /// // Balanced configuration (recommended)
    /// let tcp = HuginnNetTcp::with_config(Some(db.clone()), 1000, 4, 100, 32, 10);
    ///
    /// // Low latency
    /// let low_latency = HuginnNetTcp::with_config(Some(db.clone()), 1000, 2, 100, 8, 5);
    ///
    /// // High throughput
    /// let high_throughput = HuginnNetTcp::with_config(Some(db), 1000, 4, 200, 64, 20);
    /// ```
    ///
    /// # Returns
    /// A new `HuginnNetTcp` instance configured for parallel processing.
    pub fn with_config(
        database: Option<Arc<db::Database>>,
        max_connections: usize,
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
    ) -> Result<Self, HuginnNetTcpError> {
        Ok(Self {
            matcher: database,
            max_connections,
            parallel_config: Some(ParallelConfig {
                num_workers,
                queue_size,
                batch_size,
                timeout_ms,
            }),
            worker_pool: None,
        })
    }

    /// Initializes the worker pool for parallel processing.
    ///
    /// Must be called before `analyze_network` or `analyze_pcap` when using parallel mode.
    ///
    /// # Parameters
    /// - `sender`: Channel to send TCP analysis results
    ///
    /// # Errors
    /// Returns error if called without parallel config or if worker pool creation fails.
    pub fn init_pool(
        &mut self,
        sender: Sender<TcpAnalysisResult>,
    ) -> Result<(), HuginnNetTcpError> {
        let config = self
            .parallel_config
            .ok_or(HuginnNetTcpError::Misconfiguration(
                "Parallel mode not configured. Use with_config() to enable parallel processing"
                    .to_string(),
            ))?;

        // Clone Arc for sharing across threads (cheap, just increments ref count)
        let database_arc = self.matcher.as_ref().map(Arc::clone);

        let worker_pool = WorkerPool::new(
            config.num_workers,
            config.queue_size,
            config.batch_size,
            config.timeout_ms,
            sender,
            database_arc,
            self.max_connections,
        )?;

        self.worker_pool = Some(Arc::new(worker_pool));
        Ok(())
    }

    /// Returns a reference to the worker pool.
    ///
    /// # Returns
    /// An `Option` containing an `Arc` to the `WorkerPool` if parallel mode is enabled.
    pub fn worker_pool(&self) -> Option<Arc<WorkerPool>> {
        self.worker_pool.as_ref().map(Arc::clone)
    }

    /// Returns current pool statistics (parallel mode only).
    ///
    /// # Returns
    /// `Some(PoolStats)` if in parallel mode, `None` otherwise.
    pub fn stats(&self) -> Option<PoolStats> {
        self.worker_pool.as_ref().map(|pool| pool.stats())
    }

    fn process_with<F>(
        &mut self,
        packet_fn: F,
        sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTcpError>>,
    {
        if self.parallel_config.is_some() {
            self.process_parallel(packet_fn, sender, cancel_signal)
        } else {
            self.process_sequential(packet_fn, sender, cancel_signal)
        }
    }

    fn process_sequential<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTcpError>>,
    {
        // Connection tracker for TCP analysis (sequential mode)
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
                        debug!("Error processing packet: {tcp_error}");
                    }
                },
                Err(e) => {
                    error!("Failed to read packet: {e}");
                }
            }
        }
        Ok(())
    }

    fn process_parallel<F>(
        &mut self,
        mut packet_fn: F,
        _sender: Sender<TcpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetTcpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetTcpError>>,
    {
        let worker_pool = self
            .worker_pool
            .as_ref()
            .ok_or(HuginnNetTcpError::Misconfiguration(
                "Worker pool not initialized. Call init_pool() before processing".to_string(),
            ))?;

        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    // Dispatch to worker pool using hash-based assignment
                    worker_pool.dispatch(packet);
                }
                Err(e) => {
                    error!("Failed to read packet: {e}");
                }
            }
        }

        // Signal workers to finish
        worker_pool.shutdown();
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
        let matcher = self
            .matcher
            .as_ref()
            .map(|db| SignatureMatcher::new(db.as_ref()));

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => {
                process_ipv4_packet(&ipv4, connection_tracker, matcher.as_ref())
            }
            IpPacket::Ipv6(ipv6) => {
                process_ipv6_packet(&ipv6, connection_tracker, matcher.as_ref())
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
