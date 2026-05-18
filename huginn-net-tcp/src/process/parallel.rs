use super::{process_ipv4_packet, process_ipv6_packet, ConnectionTracker};
use crate::error::HuginnNetTcpError;
use crate::filter::raw as raw_filter;
use crate::filter::FilterConfig;
use crate::matcher_api::TcpMatcher;
use crate::output::TcpAnalysisResult;
use crate::parser::hash as packet_hash;
use crate::parser::packet::{parse_packet, IpPacket};
use crossbeam_channel::{bounded, Sender, TrySendError};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

type SharedMatcher = Arc<dyn TcpMatcher + Send + Sync>;

/// Worker configuration parameters.
#[derive(Debug, Clone, Copy)]
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
    dispatched_count: AtomicU64,
    dropped_count: AtomicU64,
    worker_dropped: Vec<AtomicU64>,
    pub batch_size: usize,
    pub timeout_ms: u64,
}

impl WorkerPool {
    /// Creates a new worker pool for parallel TCP processing.
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads
    /// - `queue_size`: Size of each worker's packet queue
    /// - `batch_size`: Number of packets to process before yielding
    /// - `timeout_ms`: Timeout in milliseconds for blocking receive
    /// - `result_sender`: Channel to send TCP analysis results
    /// - `matcher`: Optional matcher implementing [`TcpMatcher`] for OS/MTU
    ///   matching (wrapped in `Arc` for thread sharing).
    /// - `max_connections`: Maximum connections to track per worker
    /// - `filter_config`: Optional filter configuration for packet filtering
    ///
    /// # Errors
    /// Returns error if `num_workers` is 0 or thread creation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
        result_sender: std::sync::mpsc::Sender<TcpAnalysisResult>,
        matcher: Option<SharedMatcher>,
        max_connections: usize,
        filter_config: Option<FilterConfig>,
    ) -> Result<Self, HuginnNetTcpError> {
        let num_workers = NonZeroUsize::new(num_workers).ok_or(
            HuginnNetTcpError::Misconfiguration("Worker count must be greater than 0".to_string()),
        )?;

        let mut workers = Vec::new();
        let mut packet_senders = Vec::new();
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers.get() {
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_sender_clone = result_sender.clone();
            let shutdown_flag_clone = Arc::clone(&shutdown_flag);

            let worker_matcher = matcher.as_ref().map(Arc::clone);
            let worker_filter = filter_config.clone();

            let handle = thread::Builder::new()
                .name(format!("tcp-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        rx,
                        result_sender_clone,
                        worker_matcher,
                        shutdown_flag_clone,
                        WorkerConfig { batch_size, timeout_ms, max_connections },
                        worker_filter,
                    );
                })
                .map_err(|e| {
                    HuginnNetTcpError::Misconfiguration(format!(
                        "Failed to spawn worker thread: {e}"
                    ))
                })?;

            workers.push(handle);
        }

        let worker_dropped: Vec<AtomicU64> =
            (0..num_workers.get()).map(|_| AtomicU64::new(0)).collect();

        Ok(Self {
            _workers: workers,
            packet_senders: Arc::new(packet_senders),
            result_sender: Arc::new(Mutex::new(Some(result_sender))),
            shutdown_flag,
            num_workers,
            dispatched_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            worker_dropped,
            batch_size,
            timeout_ms,
        })
    }

    fn worker_loop(
        worker_id: usize,
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        result_sender: std::sync::mpsc::Sender<TcpAnalysisResult>,
        matcher: Option<SharedMatcher>,
        shutdown_flag: Arc<AtomicBool>,
        config: WorkerConfig,
        filter_config: Option<FilterConfig>,
    ) {
        use crossbeam_channel::RecvTimeoutError;
        use std::time::Duration;

        tracing::debug!("TCP worker {worker_id} starting");

        let matcher_ref: Option<&dyn TcpMatcher> = matcher.as_deref().map(|m| m as &dyn TcpMatcher);

        // Each worker maintains its own connection tracker (state isolation)
        let mut connection_tracker = ConnectionTracker::new(config.max_connections);

        let timeout = Duration::from_millis(config.timeout_ms);

        loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                tracing::debug!("TCP worker {worker_id} received shutdown signal");
                break;
            }

            // Blocking receive for first packet in batch
            let first_packet = match rx.recv_timeout(timeout) {
                Ok(packet) => packet,
                Err(RecvTimeoutError::Timeout) => {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        tracing::debug!(
                            "TCP worker {worker_id} received shutdown signal during timeout"
                        );
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    tracing::debug!("TCP worker {worker_id}: channel disconnected");
                    break;
                }
            };

            // Process first packet
            if !Self::process_packet(
                &first_packet,
                &mut connection_tracker,
                matcher_ref,
                &result_sender,
                filter_config.as_ref(),
            ) {
                tracing::debug!("TCP worker {worker_id}: result channel closed");
                break;
            }

            // Try to collect more packets for batch processing (non-blocking)
            for _ in 1..config.batch_size {
                match rx.try_recv() {
                    Ok(packet) => {
                        if !Self::process_packet(
                            &packet,
                            &mut connection_tracker,
                            matcher_ref,
                            &result_sender,
                            filter_config.as_ref(),
                        ) {
                            tracing::debug!("TCP worker {worker_id}: result channel closed");
                            return;
                        }
                    }
                    Err(_) => break, // No more packets available, continue to next batch
                }
            }
        }

        tracing::debug!("TCP worker {worker_id} exiting");
    }

    /// Processes a single packet and sends the result.
    /// Returns `false` if the result channel is closed (signal to exit).
    fn process_packet(
        packet: &[u8],
        connection_tracker: &mut ConnectionTracker,
        matcher: Option<&dyn TcpMatcher>,
        result_sender: &std::sync::mpsc::Sender<TcpAnalysisResult>,
        filter: Option<&FilterConfig>,
    ) -> bool {
        if let Some(filter_cfg) = filter {
            if !raw_filter::apply(packet, filter_cfg) {
                tracing::debug!("Filtered out packet before parsing");
                return true;
            }
        }

        let result = match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => process_ipv4_packet(&ipv4, connection_tracker, matcher),
            IpPacket::Ipv6(ipv6) => process_ipv6_packet(&ipv6, connection_tracker, matcher),
            IpPacket::None => Ok(TcpAnalysisResult {
                syn: None,
                syn_ack: None,
                mtu: None,
                #[cfg(feature = "uptime")]
                client_uptime: None,
                #[cfg(feature = "uptime")]
                server_uptime: None,
            }),
        };

        match result {
            Ok(analysis_result) => result_sender.send(analysis_result).is_ok(),
            Err(_e) => {
                tracing::debug!("Error processing packet: {_e}");
                true // Continue processing despite error
            }
        }
    }

    /// Returns the worker index that would receive `packet` (same routing as
    /// [`Self::dispatch`]).
    ///
    /// This is deterministic for a given packet and pool size; callers can use
    /// it in tests without relying on queue timing.
    pub fn worker_index_for_packet(&self, packet: &[u8]) -> usize {
        let source_ip_hash = packet_hash::hash_source_ip(packet);
        source_ip_hash
            .checked_rem(self.num_workers.get())
            .unwrap_or(0)
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

        let worker_id = self.worker_index_for_packet(&packet);

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
        let mut workers = Vec::new();

        for (id, sender) in self.packet_senders.iter().enumerate() {
            workers.push(WorkerStats {
                id,
                queue_size: sender.len(),
                dropped: self.worker_dropped[id].load(Ordering::Relaxed),
            });
        }

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
