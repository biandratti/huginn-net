use crate::error::HuginnNetTcpError;
use crate::output::TcpAnalysisResult;
use crate::packet_hash;
use crate::packet_parser::{parse_packet, IpPacket};
use crate::process::{process_ipv4_packet, process_ipv6_packet};
use crate::signature_matcher::SignatureMatcher;
use crossbeam_channel::{bounded, RecvTimeoutError, Sender, TryRecvError, TrySendError};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::debug;
use ttl_cache::TtlCache;

/// Worker configuration parameters
struct WorkerConfig {
    batch_size: usize,
    timeout_ms: u64,
    max_connections: usize,
}

/// Result of packet dispatch to worker queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Packet successfully queued for processing
    Queued,
    /// Packet dropped (queue full or pool shutdown)
    Dropped,
}

/// Statistics for a single worker.
#[derive(Debug, Clone)]
pub struct WorkerStats {
    /// Worker ID
    pub id: usize,
    /// Current queue size
    pub queue_size: usize,
    /// Number of packets dropped by this worker
    pub dropped: u64,
}

impl std::fmt::Display for WorkerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Worker {}: queue_size={}, dropped={}",
            self.id, self.queue_size, self.dropped
        )
    }
}

/// Statistics for the entire worker pool.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total packets dispatched
    pub total_dispatched: u64,
    /// Total packets dropped
    pub total_dropped: u64,
    /// Per-worker statistics
    pub workers: Vec<WorkerStats>,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "TCP Pool Stats - packets dispatched: {}, packets dropped: {}",
            self.total_dispatched, self.total_dropped
        )?;
        for worker in &self.workers {
            writeln!(f, "  {worker}")?;
        }
        Ok(())
    }
}

/// Worker pool for parallel TCP processing with hash-based dispatch.
pub struct WorkerPool {
    _workers: Vec<thread::JoinHandle<()>>,
    packet_senders: Arc<Vec<Sender<Vec<u8>>>>,
    result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<TcpAnalysisResult>>>>,
    shutdown_flag: Arc<AtomicBool>,
    pub num_workers: NonZeroUsize,
    pub batch_size: usize,
    pub timeout_ms: u64,
    dispatched_count: AtomicU64,
    dropped_count: AtomicU64,
    worker_dropped: Vec<AtomicU64>,
}

impl WorkerPool {
    /// Creates a new worker pool for parallel TCP processing.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads
    /// - `queue_size`: Size of each worker's packet queue
    /// - `batch_size`: Maximum packets to process in one batch
    /// - `timeout_ms`: Worker receive timeout in milliseconds
    /// - `result_sender`: Channel to send TCP analysis results
    /// - `database`: Optional database for OS fingerprinting (wrapped in Arc for thread sharing)
    /// - `max_connections`: Maximum connections to track per worker
    ///
    /// # Errors
    /// Returns error if `num_workers` is 0 or thread creation fails.
    pub fn new(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
        result_sender: std::sync::mpsc::Sender<TcpAnalysisResult>,
        database: Option<Arc<crate::db::Database>>,
        max_connections: usize,
    ) -> Result<Self, HuginnNetTcpError> {
        let num_workers = NonZeroUsize::new(num_workers).ok_or(
            HuginnNetTcpError::Misconfiguration("Worker count must be greater than 0".to_string()),
        )?;

        let mut workers = Vec::new();
        let mut packet_senders = Vec::new();
        let mut worker_dropped = Vec::new();

        let result_sender = Arc::new(Mutex::new(Some(result_sender)));
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers.get() {
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_sender_clone = Arc::clone(&result_sender);
            let dropped_counter = Arc::new(AtomicU64::new(0));
            worker_dropped.push(Arc::clone(&dropped_counter));

            let worker_database = database.as_ref().map(Arc::clone);
            let shutdown_flag_clone = Arc::clone(&shutdown_flag);

            let handle = thread::Builder::new()
                .name(format!("tcp-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        rx,
                        result_sender_clone,
                        worker_database,
                        shutdown_flag_clone,
                        WorkerConfig { batch_size, timeout_ms, max_connections },
                    );
                })
                .map_err(|e| {
                    HuginnNetTcpError::Misconfiguration(format!(
                        "Failed to spawn worker thread: {e}"
                    ))
                })?;

            workers.push(handle);
        }

        let worker_dropped_plain: Vec<AtomicU64> = worker_dropped
            .iter()
            .map(|arc| AtomicU64::new(arc.load(Ordering::Relaxed)))
            .collect();

        Ok(Self {
            _workers: workers,
            packet_senders: Arc::new(packet_senders),
            result_sender,
            shutdown_flag,
            num_workers,
            batch_size,
            timeout_ms,
            dispatched_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            worker_dropped: worker_dropped_plain,
        })
    }

    fn worker_loop(
        worker_id: usize,
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<TcpAnalysisResult>>>>,
        database: Option<Arc<crate::db::Database>>,
        shutdown_flag: Arc<AtomicBool>,
        config: WorkerConfig,
    ) {
        debug!("TCP worker {} started", worker_id);

        // Each worker creates its own matcher from the shared database
        let matcher = database
            .as_ref()
            .map(|db| SignatureMatcher::new(db.as_ref()));

        // Each worker maintains its own connection tracker (state isolation)
        let mut connection_tracker = TtlCache::new(config.max_connections);
        let timeout = Duration::from_millis(config.timeout_ms);
        let mut batch = Vec::with_capacity(config.batch_size);

        loop {
            // Check shutdown flag
            if shutdown_flag.load(Ordering::Relaxed) {
                debug!("TCP worker {} received shutdown signal", worker_id);
                break;
            }

            // Blocking recv for first packet (waits if queue is empty)
            let first_packet = match rx.recv_timeout(timeout) {
                Ok(packet) => packet,
                Err(RecvTimeoutError::Timeout) => {
                    // Check shutdown flag on timeout
                    if shutdown_flag.load(Ordering::Relaxed) {
                        debug!("TCP worker {} received shutdown signal", worker_id);
                        break;
                    }
                    batch.clear();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    debug!("TCP worker {} channel disconnected", worker_id);
                    break;
                }
            };

            batch.push(first_packet);

            // Try to fill batch with more packets (non-blocking)
            while batch.len() < config.batch_size {
                match rx.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }

            // Process entire batch
            for packet in batch.drain(..) {
                let result = match parse_packet(&packet) {
                    IpPacket::Ipv4(ipv4) => {
                        process_ipv4_packet(&ipv4, &mut connection_tracker, matcher.as_ref())
                    }
                    IpPacket::Ipv6(ipv6) => {
                        process_ipv6_packet(&ipv6, &mut connection_tracker, matcher.as_ref())
                    }
                    IpPacket::None => Ok(TcpAnalysisResult {
                        syn: None,
                        syn_ack: None,
                        mtu: None,
                        client_uptime: None,
                        server_uptime: None,
                    }),
                };

                match result {
                    Ok(analysis_result) => {
                        if let Ok(guard) = result_sender.lock() {
                            if let Some(ref sender) = *guard {
                                if sender.send(analysis_result).is_err() {
                                    debug!("TCP worker {} result channel closed", worker_id);
                                    return;
                                }
                            } else {
                                debug!("TCP worker {} pool shutting down", worker_id);
                                return;
                            }
                        }
                    }
                    Err(_e) => {
                        debug!("TCP worker {} error processing packet: {_e}", worker_id);
                    }
                }
            }
        }

        debug!("TCP worker {} stopped", worker_id);
    }

    /// Dispatches a packet to the appropriate worker based on source IP hash.
    ///
    /// Uses hash-based assignment to ensure packets from the same source IP
    /// always go to the same worker, maintaining state consistency.
    pub fn dispatch(&self, packet: Vec<u8>) -> DispatchResult {
        // Check if pool is shutting down
        if self.shutdown_flag.load(Ordering::Relaxed) {
            return DispatchResult::Dropped;
        }

        // Extract source IP for hashing
        let source_ip_hash = packet_hash::hash_source_ip(&packet);

        // NonZeroUsize guarantees num_workers.get() > 0
        let worker_id = source_ip_hash
            .checked_rem(self.num_workers.get())
            .unwrap_or(0);

        match self.packet_senders[worker_id].try_send(packet) {
            Ok(()) => {
                self.dispatched_count.fetch_add(1, Ordering::Relaxed);
                DispatchResult::Queued
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                self.worker_dropped[worker_id].fetch_add(1, Ordering::Relaxed);
                DispatchResult::Dropped
            }
        }
    }

    pub fn stats(&self) -> PoolStats {
        let workers = (0..self.num_workers.get())
            .map(|id| WorkerStats {
                id,
                queue_size: self.packet_senders[id].len(),
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
        self.shutdown_flag.store(true, Ordering::Relaxed);

        // Drop result sender to signal workers
        if let Ok(mut sender) = self.result_sender.lock() {
            *sender = None;
        }
    }
}
