#![forbid(unsafe_code)]

//! TCP fingerprinting primitives.
//!
//! This crate is intentionally **independent of any signature database**.
//! It exposes:
//! - [`tcp`] pure data types describing a TCP fingerprint.
//! - [`TcpObservation`] what was observed on the wire.
//! - [`TcpMatcher`] the trait any database/matcher implements
//!   to provide OS/MTU matches.
//! - [`HuginnNetTcp`] the high-level capture/processing entry point that
//!   plugs an arbitrary matcher in.
//!
//! In the default workspace setup, `huginn-net-db` provides
//! `TcpSignatureMatcher`, which loads p0f-style signatures and implements
//! [`TcpMatcher`].

pub mod filter;
pub mod ip_options;
pub mod matcher_api;
pub mod mtu;
pub mod packet_hash;
pub mod packet_parser;
pub mod parallel;
pub mod raw_filter;
pub mod syn_options;
pub mod tcp;
pub mod tcp_process;
pub mod ttl;
pub mod uptime;
pub mod window_size;

pub mod display;
pub mod error;
pub mod observable;
pub mod output;
pub mod process;

// Re-exports
pub use error::*;
pub use filter::*;
pub use observable::*;
pub use output::*;
pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use process::*;
pub use tcp_process::*;
pub use uptime::{
    calculate_uptime_improved, Connection, ConnectionKey, FrequencyState, TcpTimestamp,
    UptimeTracker,
};

use crate::matcher_api::TcpMatcher;
use crate::packet_parser::{parse_packet, IpPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

#[derive(Debug, Clone, Copy)]
struct ParallelConfig {
    num_workers: usize,
    queue_size: usize,
    batch_size: usize,
    timeout_ms: u64,
}

pub type SharedTcpMatcher = Arc<dyn TcpMatcher + Send + Sync>;

/// A TCP-focused passive fingerprinting analyzer.
///
/// `HuginnNetTcp` handles TCP packet analysis for OS fingerprinting,
/// MTU detection, and uptime calculation using p0f-style methodologies.
///
/// Supports both sequential (single-threaded) and parallel (multi-threaded)
/// processing modes.
pub struct HuginnNetTcp {
    matcher: Option<SharedTcpMatcher>,
    max_connections: usize,
    parallel_config: Option<ParallelConfig>,
    worker_pool: Option<Arc<WorkerPool>>,
    filter_config: Option<FilterConfig>,
}

impl HuginnNetTcp {
    /// Creates a new instance of `HuginnNetTcp` in sequential mode without a
    /// matcher.
    ///
    /// Use [`HuginnNetTcp::with_matcher`] to plug in a fingerprint matcher
    /// (e.g. `huginn_net_db::TcpSignatureMatcher`). Without a matcher, the
    /// analyzer still extracts raw TCP signatures, MTU, and uptime, but all
    /// `*QualityMatched` results are reported as `Disabled`.
    ///
    /// # Parameters
    /// - `max_connections`: Maximum number of connections to track in the
    ///   connection tracker.
    ///
    /// # Returns
    /// A new `HuginnNetTcp` instance ready for sequential TCP analysis.
    pub fn new(max_connections: usize) -> Self {
        Self {
            matcher: None,
            max_connections,
            parallel_config: None,
            worker_pool: None,
            filter_config: None,
        }
    }

    /// Enable parallel processing (builder pattern).
    ///
    /// Uses hash-based worker assignment to ensure packets from the same source IP
    /// always go to the same worker, maintaining state consistency.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads (recommended: 2-4 on 8-core systems)
    /// - `queue_size`: Size of packet queue per worker (typical: 100-200)
    /// - `batch_size`: Maximum packets to process in one batch (typical: 16-64, recommended: 32)
    /// - `timeout_ms`: Worker receive timeout in milliseconds (typical: 5-50, recommended: 10)
    pub fn with_parallel(
        mut self,
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
    ) -> Self {
        self.parallel_config =
            Some(ParallelConfig { num_workers, queue_size, batch_size, timeout_ms });
        self
    }

    /// Plug in a TCP fingerprint matcher (builder pattern).
    ///
    /// The matcher is shared between this analyzer and any worker pool it
    /// spawns; pass an `Arc<dyn TcpMatcher + Send + Sync>` (alias
    /// [`SharedTcpMatcher`]).
    ///
    /// In the default workspace setup, `huginn-net-db` provides
    /// `TcpSignatureMatcher` (borrowed) and `SharedTcpSignatureMatcher`
    /// (owned `Arc<Database>`); the latter is what you typically pass here.
    pub fn with_matcher(mut self, matcher: SharedTcpMatcher) -> Self {
        self.matcher = Some(matcher);
        self
    }

    /// Configure packet filtering (builder pattern).
    pub fn with_filter(mut self, config: FilterConfig) -> Self {
        self.filter_config = Some(config);
        self
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
                "Parallel mode not configured. Use with_parallel() to enable parallel processing"
                    .to_string(),
            ))?;

        let matcher_arc = self.matcher.as_ref().map(Arc::clone);

        let worker_pool = WorkerPool::new(
            config.num_workers,
            config.queue_size,
            config.batch_size,
            config.timeout_ms,
            sender,
            matcher_arc,
            self.max_connections,
            self.filter_config.clone(),
        )?;

        self.worker_pool = Some(Arc::new(worker_pool));
        Ok(())
    }

    /// Returns a reference to the worker pool.
    pub fn worker_pool(&self) -> Option<Arc<WorkerPool>> {
        self.worker_pool.as_ref().map(Arc::clone)
    }

    /// Returns current pool statistics (parallel mode only).
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
                    worker_pool.dispatch(packet);
                }
                Err(e) => {
                    error!("Failed to read packet: {e}");
                }
            }
        }

        worker_pool.shutdown();
        Ok(())
    }

    /// Analyzes network traffic from a live network interface for TCP packets.
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
    fn process_packet(
        &self,
        packet: &[u8],
        connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    ) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
        if let Some(ref filter) = self.filter_config {
            if !raw_filter::apply(packet, filter) {
                debug!("Filtered out packet before parsing");
                return Ok(TcpAnalysisResult {
                    syn: None,
                    syn_ack: None,
                    mtu: None,
                    client_uptime: None,
                    server_uptime: None,
                });
            }
        }

        let matcher_ref: Option<&dyn TcpMatcher> =
            self.matcher.as_deref().map(|m| m as &dyn TcpMatcher);

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => process_ipv4_packet(&ipv4, connection_tracker, matcher_ref),
            IpPacket::Ipv6(ipv6) => process_ipv6_packet(&ipv6, connection_tracker, matcher_ref),
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
