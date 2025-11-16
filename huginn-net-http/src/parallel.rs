//! Parallel processing support for HTTP analysis using worker pool architecture.
//!
//! This module provides multi-threaded packet processing with hash-based worker assignment
//! to maintain HTTP flow consistency (request/response tracking). Unlike TCP which hashes
//! only the source IP, HTTP hashes the complete flow (src_ip, dst_ip, src_port, dst_port)
//! to ensure requests and responses from the same connection are processed by the same worker.

use crate::error::HuginnNetHttpError;
use crate::http_process::{FlowKey, HttpProcessors, TcpFlow};
use crate::packet_hash;
use crate::{HttpAnalysisResult, SignatureMatcher};
use crossbeam_channel::{bounded, Sender};
use huginn_net_db as db;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::debug;
use ttl_cache::TtlCache;

/// Worker configuration parameters
struct WorkerConfig {
    batch_size: usize,
    timeout_ms: u64,
    max_connections: usize,
}

/// Worker pool for parallel HTTP packet processing.
pub struct WorkerPool {
    packet_senders: Arc<Vec<Sender<Vec<u8>>>>,
    result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<HttpAnalysisResult>>>>,
    shutdown_flag: Arc<AtomicBool>,
    dispatched_count: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
    worker_dropped: Vec<Arc<AtomicU64>>,
    num_workers: usize,
    pub batch_size: usize,
    pub timeout_ms: u64,
}

/// Statistics for a single worker thread.
#[derive(Debug, Clone)]
pub struct WorkerStats {
    pub id: usize,
    pub queue_size: usize,
    pub dropped: u64,
}

/// Pool-level statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_dispatched: u64,
    pub total_dropped: u64,
    pub workers: Vec<WorkerStats>,
}

/// Result of dispatching a packet to a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Packet successfully queued for processing
    Queued,
    /// Worker queue full, packet dropped
    Dropped,
}

impl WorkerPool {
    /// Creates a new worker pool for HTTP analysis.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads
    /// - `queue_size`: Size of each worker's packet queue
    /// - `batch_size`: Maximum packets to process in one batch
    /// - `timeout_ms`: Worker receive timeout in milliseconds
    /// - `result_sender`: Channel to send analysis results
    /// - `database`: Optional signature database for matching
    /// - `max_connections`: Maximum HTTP flows to track per worker
    ///
    /// # Returns
    /// A new `WorkerPool` or an error if creation fails.
    pub fn new(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
        result_sender: std::sync::mpsc::Sender<HttpAnalysisResult>,
        database: Option<Arc<db::Database>>,
        max_connections: usize,
    ) -> Result<Arc<Self>, HuginnNetHttpError> {
        if num_workers == 0 {
            return Err(HuginnNetHttpError::Misconfiguration(
                "Worker count must be at least 1".to_string(),
            ));
        }

        let mut packet_senders = Vec::with_capacity(num_workers);
        let mut worker_dropped = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_sender_clone = result_sender.clone();
            let db_clone = database.clone();
            let dropped = Arc::new(AtomicU64::new(0));
            worker_dropped.push(Arc::clone(&dropped));
            let shutdown_flag_clone = Arc::clone(&shutdown_flag);

            thread::Builder::new()
                .name(format!("http-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        rx,
                        result_sender_clone,
                        db_clone,
                        dropped,
                        shutdown_flag_clone,
                        WorkerConfig { batch_size, timeout_ms, max_connections },
                    )
                })
                .map_err(|e| {
                    HuginnNetHttpError::Misconfiguration(format!(
                        "Failed to spawn worker thread {worker_id}: {e}"
                    ))
                })?;
        }

        Ok(Arc::new(Self {
            packet_senders: Arc::new(packet_senders),
            result_sender: Arc::new(Mutex::new(Some(result_sender))),
            shutdown_flag,
            dispatched_count: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
            worker_dropped,
            num_workers,
            batch_size,
            timeout_ms,
        }))
    }

    /// Worker thread main loop with batching support.
    fn worker_loop(
        worker_id: usize,
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        result_sender: std::sync::mpsc::Sender<HttpAnalysisResult>,
        database: Option<Arc<db::Database>>,
        dropped: Arc<AtomicU64>,
        shutdown_flag: Arc<AtomicBool>,
        config: WorkerConfig,
    ) {
        use crossbeam_channel::RecvTimeoutError;
        use std::time::Duration;

        debug!("HTTP worker {} started", worker_id);

        let matcher = database
            .as_ref()
            .map(|db| SignatureMatcher::new(db.as_ref()));
        let mut http_flows = TtlCache::new(config.max_connections);
        let http_processors = HttpProcessors::new();
        let timeout = Duration::from_millis(config.timeout_ms);
        let mut batch = Vec::with_capacity(config.batch_size);

        loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                debug!("HTTP worker {} received shutdown signal", worker_id);
                break;
            }

            // Receive first packet with timeout (blocking)
            match rx.recv_timeout(timeout) {
                Ok(packet) => {
                    batch.push(packet);

                    // Try to fill the batch with additional packets (non-blocking)
                    while batch.len() < config.batch_size {
                        match rx.try_recv() {
                            Ok(packet) => batch.push(packet),
                            Err(_) => break,
                        }
                    }

                    // Process all packets in the batch
                    for packet in batch.drain(..) {
                        match Self::process_packet(
                            &packet,
                            &mut http_flows,
                            &http_processors,
                            matcher.as_ref(),
                        ) {
                            Ok(result) => {
                                if result_sender.send(result).is_err() {
                                    debug!("HTTP worker {} result channel closed", worker_id);
                                    return;
                                }
                            }
                            Err(_) => {
                                // Packet processing error, increment dropped count
                                dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        debug!("HTTP worker {} received shutdown signal", worker_id);
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    debug!("HTTP worker {} channel disconnected", worker_id);
                    break;
                }
            }
        }

        debug!("HTTP worker {} stopped", worker_id);
    }

    /// Processes a single packet within a worker thread.
    fn process_packet(
        packet: &[u8],
        http_flows: &mut TtlCache<FlowKey, TcpFlow>,
        http_processors: &HttpProcessors,
        matcher: Option<&SignatureMatcher>,
    ) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
        use crate::packet_parser::{parse_packet, IpPacket};
        use crate::process;

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => {
                process::process_ipv4_packet(&ipv4, http_flows, http_processors, matcher)
            }
            IpPacket::Ipv6(ipv6) => {
                process::process_ipv6_packet(&ipv6, http_flows, http_processors, matcher)
            }
            IpPacket::None => Ok(HttpAnalysisResult { http_request: None, http_response: None }),
        }
    }

    pub fn dispatch(&self, packet: Vec<u8>) -> DispatchResult {
        // Don't accept new packets if shutting down
        if self.shutdown_flag.load(Ordering::Relaxed) {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            return DispatchResult::Dropped;
        }

        let worker_id = packet_hash::hash_flow(&packet, self.num_workers);

        self.dispatched_count.fetch_add(1, Ordering::Relaxed);

        if let Some(sender) = self.packet_senders.get(worker_id) {
            match sender.try_send(packet) {
                Ok(()) => DispatchResult::Queued,
                Err(_) => {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    self.worker_dropped[worker_id].fetch_add(1, Ordering::Relaxed);
                    DispatchResult::Dropped
                }
            }
        } else {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            DispatchResult::Dropped
        }
    }

    pub fn stats(&self) -> PoolStats {
        let workers = self
            .packet_senders
            .iter()
            .enumerate()
            .map(|(id, sender)| WorkerStats {
                id,
                queue_size: sender.len(),
                dropped: self.worker_dropped[id].load(Ordering::Relaxed),
            })
            .collect();

        PoolStats {
            total_dispatched: self.dispatched_count.load(Ordering::Relaxed),
            total_dropped: self.dropped_count.load(Ordering::Relaxed),
            workers,
        }
    }

    /// Initiates graceful shutdown of the worker pool.
    pub fn shutdown(&self) {
        // Set shutdown flag to stop workers on next timeout
        self.shutdown_flag.store(true, Ordering::Relaxed);

        // Drop result sender to signal workers
        if let Ok(mut sender) = self.result_sender.lock() {
            *sender = None;
        }
    }
}

impl fmt::Display for PoolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HTTP Worker Pool Statistics:")?;
        writeln!(f, "  Total dispatched: {}", self.total_dispatched)?;
        writeln!(f, "  Total dropped: {}", self.total_dropped)?;
        writeln!(f, "  Workers: {}", self.workers.len())?;
        for worker in &self.workers {
            writeln!(f, "    {worker}")?;
        }
        Ok(())
    }
}

impl fmt::Display for WorkerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Worker {}: queue_size={}, dropped={}",
            self.id, self.queue_size, self.dropped
        )
    }
}
