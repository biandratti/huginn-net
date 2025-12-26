#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::http;

pub mod akamai;
pub mod akamai_extractor;
pub mod filter;
pub mod http1_parser;
pub mod http1_process;
pub mod http2_parser;
pub mod http2_process;
pub mod http_common;
pub mod http_languages;
pub mod http_process;
pub mod packet_parser;
pub mod raw_filter;

pub mod packet_hash;

pub mod display;
pub mod error;
pub mod observable;
pub mod output;
pub mod parallel;
pub mod process;
pub mod signature_matcher;

// Re-exports
pub use akamai::{AkamaiFingerprint, Http2Priority, PseudoHeader, SettingId, SettingParameter};
pub use akamai_extractor::{calculate_frames_bytes_consumed, extract_akamai_fingerprint};
pub use error::*;
pub use filter::*;
pub use http1_process::{
    build_absent_headers_from_new_parser, convert_headers_to_http_format, parse_http1_request,
    Http1Processor,
};
pub use http2_parser::{Http2Frame, Http2FrameType, Http2Parser, HTTP2_CONNECTION_PREFACE};
pub use http2_process::{parse_http2_request, Http2Processor};
pub use http_common::HttpProcessor;
pub use http_process::*;
pub use observable::*;
pub use output::*;
pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use process::*;
pub use signature_matcher::*;

use crate::packet_parser::{parse_packet, IpPacket};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

/// Configuration for TLS certificate-based analysis
///
/// Used for scenarios where TLS traffic needs to be decrypted (e.g., passthrough proxy)
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM format)
    pub cert_path: PathBuf,
    /// Path to TLS private key file (PEM format)
    pub key_path: PathBuf,
}

/// Configuration for parallel processing
///
/// Controls the behavior of worker threads in parallel mode.
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of worker threads to spawn
    pub num_workers: usize,
    /// Size of packet queue per worker (affects memory usage and backpressure)
    pub queue_size: usize,
    /// Maximum packets to process in one batch before checking for new work
    /// Higher = better throughput, lower = better latency (typical: 8-32)
    pub batch_size: usize,
    /// Worker receive timeout in milliseconds
    /// Lower = faster shutdown, higher = better throughput (typical: 5-20)
    pub timeout_ms: u64,
}

/// An HTTP-focused passive fingerprinting analyzer.
///
/// The `HuginnNetHttp` struct handles HTTP packet analysis for browser fingerprinting,
/// web server detection, and HTTP protocol analysis using p0f-style methodologies.
pub struct HuginnNetHttp {
    http_flows: TtlCache<FlowKey, TcpFlow>,
    http_processors: HttpProcessors,
    parallel_config: Option<ParallelConfig>,
    worker_pool: Option<Arc<WorkerPool>>,
    database: Option<Arc<db::Database>>,
    #[allow(dead_code)] // TODO: Will be used for TLS decryption in Akamai fingerprinting
    tls_config: Option<TlsConfig>,
    max_connections: usize,
    filter_config: Option<FilterConfig>,
}

impl HuginnNetHttp {
    /// Creates a new instance of `HuginnNetHttp` in sequential mode.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for HTTP matching
    /// - `max_connections`: Maximum number of HTTP flows to track
    ///
    /// # Returns
    /// A new `HuginnNetHttp` instance ready for HTTP analysis.
    pub fn new(
        database: Option<Arc<db::Database>>,
        max_connections: usize,
    ) -> Result<Self, HuginnNetHttpError> {
        Ok(Self {
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
            parallel_config: None,
            worker_pool: None,
            database,
            tls_config: None,
            max_connections,
            filter_config: None,
        })
    }

    /// Creates a new instance of `HuginnNetHttp` with TLS certificate support.
    ///
    /// Use this constructor when analyzing TLS-encrypted traffic (e.g., passthrough proxy scenarios)
    /// where you need to decrypt HTTPS to extract HTTP/2 frames for Akamai fingerprinting.
    ///
    /// # Parameters
    /// - `cert_path`: Path to TLS certificate file (PEM format)
    /// - `key_path`: Path to TLS private key file (PEM format)
    /// - `max_connections`: Maximum number of HTTP flows to track (default: 10000)
    ///
    /// # Returns
    /// A new `HuginnNetHttp` instance with TLS decryption capabilities.
    ///
    /// # Example
    /// ```no_run
    /// use huginn_net_http::HuginnNetHttp;
    /// use std::path::PathBuf;
    ///
    /// // Create analyzer with certificates (for TLS passthrough scenarios)
    /// let analyzer = HuginnNetHttp::with_tls_certificates(
    ///     PathBuf::from("/etc/ssl/certs/server.crt"),
    ///     PathBuf::from("/etc/ssl/private/server.key"),
    ///     10000,
    /// )?;
    /// # Ok::<(), huginn_net_http::HuginnNetHttpError>(())
    /// ```
    pub fn with_tls_certificates(
        cert_path: PathBuf,
        key_path: PathBuf,
        max_connections: usize,
    ) -> Result<Self, HuginnNetHttpError> {
        Ok(Self {
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
            parallel_config: None,
            worker_pool: None,
            database: None, // No p0f database needed for Akamai fingerprinting
            tls_config: Some(TlsConfig { cert_path, key_path }),
            max_connections,
            filter_config: None,
        })
    }

    /// Creates a new instance of `HuginnNetHttp` with full parallel configuration.
    ///
    /// # Parameters
    /// - `database`: Optional signature database for HTTP matching
    /// - `max_connections`: Maximum number of HTTP flows to track per worker (typical: 1000-10000)
    /// - `num_workers`: Number of worker threads (recommended: 2 for HTTP due to flow tracking)
    /// - `queue_size`: Size of each worker's packet queue (typical: 100-200)
    /// - `batch_size`: Maximum packets to process in one batch (typical: 8-32, recommended: 16)
    /// - `timeout_ms`: Worker receive timeout in milliseconds (typical: 5-20, recommended: 10)
    ///
    /// # Configuration Guide
    ///
    /// ## batch_size
    /// - **Low (8)**: Lower latency, more responsive, higher overhead
    /// - **Medium (16)**: Balanced throughput and latency *(recommended)*
    /// - **High (32-64)**: Maximum throughput, higher latency
    ///
    /// ## timeout_ms
    /// - **Low (5-10ms)**: Fast shutdown, slightly lower throughput *(recommended: 10)*
    /// - **Medium (15-20ms)**: Better throughput, slower shutdown
    /// - **High (50ms+)**: Maximum throughput, slow shutdown
    ///
    /// # Example
    /// ```rust,no_run
    /// use huginn_net_http::HuginnNetHttp;
    ///
    /// // Balanced configuration (recommended for HTTP)
    /// let http = HuginnNetHttp::with_config(None, 1000, 2, 100, 16, 10);
    ///
    /// // Low latency
    /// let low_latency = HuginnNetHttp::with_config(None, 1000, 2, 100, 8, 5);
    ///
    /// // High throughput
    /// let high_throughput = HuginnNetHttp::with_config(None, 5000, 2, 200, 32, 15);
    /// ```
    ///
    /// # Returns
    /// A new `HuginnNetHttp` instance configured for parallel processing.
    pub fn with_config(
        database: Option<Arc<db::Database>>,
        max_connections: usize,
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
    ) -> Result<Self, HuginnNetHttpError> {
        Ok(Self {
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
            parallel_config: Some(ParallelConfig {
                num_workers,
                queue_size,
                batch_size,
                timeout_ms,
            }),
            worker_pool: None,
            database,
            tls_config: None,
            max_connections,
            filter_config: None,
        })
    }

    /// Configure packet filtering (builder pattern)
    pub fn with_filter(mut self, config: FilterConfig) -> Self {
        self.filter_config = Some(config);
        self
    }

    /// Initializes the worker pool for parallel processing.
    ///
    /// Must be called after `with_config` and before calling `analyze_network` or `analyze_pcap`.
    ///
    /// # Parameters
    /// - `result_tx`: Channel sender for analysis results
    ///
    /// # Returns
    /// `Ok(())` if pool initialized successfully, error otherwise.
    pub fn init_pool(
        &mut self,
        result_tx: Sender<HttpAnalysisResult>,
    ) -> Result<(), HuginnNetHttpError> {
        if let Some(config) = &self.parallel_config {
            let pool = WorkerPool::new(
                config.num_workers,
                config.queue_size,
                config.batch_size,
                config.timeout_ms,
                result_tx,
                self.database.clone(),
                self.max_connections,
                self.filter_config.clone(),
            )?;
            self.worker_pool = Some(pool);
            Ok(())
        } else {
            Err(HuginnNetHttpError::Misconfiguration(
                "Parallel config not set. Use with_config() instead of new()".to_string(),
            ))
        }
    }

    /// Returns a reference to the worker pool if initialized.
    pub fn worker_pool(&self) -> Option<&Arc<WorkerPool>> {
        self.worker_pool.as_ref()
    }

    /// Returns current worker pool statistics if parallel mode is active.
    pub fn stats(&self) -> Option<PoolStats> {
        self.worker_pool.as_ref().map(|pool| pool.stats())
    }

    fn process_with<F>(
        &mut self,
        packet_fn: F,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        if self.worker_pool.is_some() {
            self.process_parallel(packet_fn, cancel_signal)
        } else {
            self.process_sequential(packet_fn, sender, cancel_signal)
        }
    }

    fn process_sequential<F>(
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

    fn process_parallel<F>(
        &mut self,
        mut packet_fn: F,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        let pool = self.worker_pool.as_ref().ok_or_else(|| {
            HuginnNetHttpError::Misconfiguration("Worker pool not initialized".to_string())
        })?;

        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    let _ = pool.dispatch(packet);
                }
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

        let config = Config { promiscuous: true, ..Config::default() };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(HuginnNetHttpError::Parse("Unhandled channel type".to_string())),
            Err(e) => {
                return Err(HuginnNetHttpError::Parse(format!("Unable to create channel: {e}")))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => {
                    Some(Err(HuginnNetHttpError::Parse(format!("Error receiving packet: {e}"))))
                }
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
                Some(Err(e)) => {
                    Some(Err(HuginnNetHttpError::Parse(format!("Error reading PCAP packet: {e}"))))
                }
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
        if let Some(ref filter) = self.filter_config {
            if !raw_filter::apply(packet, filter) {
                debug!("Filtered out packet before parsing");
                return Ok(HttpAnalysisResult { http_request: None, http_response: None });
            }
        }

        let matcher = self
            .database
            .as_ref()
            .map(|db| SignatureMatcher::new(db.as_ref()));

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => process::process_ipv4_packet(
                &ipv4,
                &mut self.http_flows,
                &self.http_processors,
                matcher.as_ref(),
            ),
            IpPacket::Ipv6(ipv6) => process::process_ipv6_packet(
                &ipv6,
                &mut self.http_flows,
                &self.http_processors,
                matcher.as_ref(),
            ),
            IpPacket::None => Ok(HttpAnalysisResult { http_request: None, http_response: None }),
        }
    }
}
