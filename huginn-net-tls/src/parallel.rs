use crate::output::TlsClientOutput;
use crate::packet_parser::{parse_packet, IpPacket};
use crate::process::{process_ipv4_packet, process_ipv6_packet};
use crate::HuginnNetTlsError;
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::debug;

/// Result of dispatching a packet to a worker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Packet successfully queued
    Queued,
    /// Packet dropped (queue full)
    Dropped,
}

/// Statistics for a single worker
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerStats {
    /// Worker ID
    pub id: usize,
    /// Current queue size (approximate)
    pub queue_size: usize,
    /// Total packets dropped by this worker
    pub dropped: u64,
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

/// Simple statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total packets dispatched to workers (accumulated since start)
    pub total_dispatched: u64,
    /// Total packets dropped because queues were full (accumulated since start)
    pub total_dropped: u64,
    /// Per-worker statistics (current state)
    pub workers: Vec<WorkerStats>,
}

impl fmt::Display for PoolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "TLS Pool Stats - packets dispatched: {}, packets dropped: {}",
            self.total_dispatched, self.total_dropped
        )?;
        for worker in &self.workers {
            writeln!(f, "  {worker}")?;
        }
        Ok(())
    }
}

/// Worker pool for parallel TLS processing
pub struct WorkerPool {
    _workers: Vec<thread::JoinHandle<()>>,
    packet_senders: Arc<Vec<Sender<Vec<u8>>>>,
    result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<TlsClientOutput>>>>,
    shutdown_flag: Arc<AtomicBool>,
    pub num_workers: NonZeroUsize,
    pub batch_size: usize,
    pub timeout_ms: u64,
    next_worker: AtomicUsize,
    queued_count: AtomicU64,
    dropped_count: AtomicU64,
    worker_dropped: Vec<AtomicU64>,
}

impl WorkerPool {
    /// Create a new worker pool
    ///
    /// # Errors
    ///
    /// Returns an error if unable to spawn worker threads or if num_workers is 0
    pub fn new(
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
        result_sender: std::sync::mpsc::Sender<TlsClientOutput>,
    ) -> Result<Self, HuginnNetTlsError> {
        let num_workers = NonZeroUsize::new(num_workers).ok_or_else(|| {
            HuginnNetTlsError::Misconfiguration("Worker count must be greater than 0".to_string())
        })?;

        debug!(
            "Creating TLS worker pool: {} workers, queue size: {}, batch size: {}, timeout: {}ms",
            num_workers, queue_size, batch_size, timeout_ms
        );

        let num_workers_val = num_workers.get();
        let mut workers = Vec::with_capacity(num_workers_val);
        let mut packet_senders = Vec::with_capacity(num_workers_val);
        let mut worker_dropped = Vec::with_capacity(num_workers_val);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers_val {
            worker_dropped.push(AtomicU64::new(0));
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_sender_clone = result_sender.clone();
            let shutdown_flag_clone = Arc::clone(&shutdown_flag);

            let handle = thread::Builder::new()
                .name(format!("tls-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        rx,
                        result_sender_clone,
                        shutdown_flag_clone,
                        batch_size,
                        timeout_ms,
                    );
                })
                .map_err(|e| {
                    HuginnNetTlsError::Misconfiguration(format!(
                        "Failed to spawn worker thread: {e}"
                    ))
                })?;

            workers.push(handle);
        }

        Ok(Self {
            _workers: workers,
            packet_senders: Arc::new(packet_senders),
            result_sender: Arc::new(Mutex::new(Some(result_sender))),
            shutdown_flag,
            num_workers,
            batch_size,
            timeout_ms,
            next_worker: AtomicUsize::new(0),
            queued_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            worker_dropped,
        })
    }

    /// Shutdown the worker pool by closing all channels
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        if let Ok(mut sender) = self.result_sender.lock() {
            *sender = None;
        }
    }

    /// Dispatch packet to a worker (round-robin)
    pub fn dispatch(&self, packet: Vec<u8>) -> DispatchResult {
        let counter = self.next_worker.fetch_add(1, Ordering::Relaxed);
        let worker_id = counter.checked_rem(self.num_workers.get()).unwrap_or(0);
        match self.packet_senders[worker_id].try_send(packet) {
            Ok(()) => {
                self.queued_count.fetch_add(1, Ordering::Relaxed);
                DispatchResult::Queued
            }
            Err(TrySendError::Full(_)) => {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                self.worker_dropped[worker_id].fetch_add(1, Ordering::Relaxed);
                DispatchResult::Dropped
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                self.worker_dropped[worker_id].fetch_add(1, Ordering::Relaxed);
                DispatchResult::Dropped
            }
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> PoolStats {
        let workers = (0..self.num_workers.get())
            .map(|worker_id| WorkerStats {
                id: worker_id,
                queue_size: self
                    .packet_senders
                    .get(worker_id)
                    .map(|s| s.len())
                    .unwrap_or(0),
                dropped: self.worker_dropped[worker_id].load(Ordering::Relaxed),
            })
            .collect();

        PoolStats {
            total_dispatched: self.queued_count.load(Ordering::Relaxed),
            total_dropped: self.dropped_count.load(Ordering::Relaxed),
            workers,
        }
    }

    fn worker_loop(
        worker_id: usize,
        rx: Receiver<Vec<u8>>,
        result_sender: std::sync::mpsc::Sender<TlsClientOutput>,
        shutdown_flag: Arc<AtomicBool>,
        batch_size: usize,
        timeout_ms: u64,
    ) {
        debug!("TLS worker {} started", worker_id);

        let mut batch = Vec::with_capacity(batch_size);

        loop {
            // Check shutdown flag
            if shutdown_flag.load(Ordering::Relaxed) {
                debug!("TLS worker {} received shutdown signal", worker_id);
                break;
            }

            // Blocking recv for first packet (waits if queue is empty)
            let first_packet = match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
                Ok(packet) => packet,
                Err(RecvTimeoutError::Timeout) => {
                    batch.clear();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    debug!("TLS worker {} channel disconnected", worker_id);
                    break;
                }
            };

            batch.push(first_packet);

            // Try to fill batch with more packets (non-blocking)
            while batch.len() < batch_size {
                match rx.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }

            // Process entire batch
            for packet in batch.drain(..) {
                match Self::process_packet(&packet) {
                    Ok(Some(result)) => {
                        if result_sender.send(result).is_err() {
                            debug!("TLS worker {} result channel closed", worker_id);
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            }
        }

        debug!("TLS worker {} stopped", worker_id);
    }

    fn process_packet(packet: &[u8]) -> Result<Option<TlsClientOutput>, HuginnNetTlsError> {
        match parse_packet(packet) {
            IpPacket::Ipv4(ip_data) => {
                if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                    process_ipv4_packet(&ipv4)
                } else {
                    Ok(None)
                }
            }
            IpPacket::Ipv6(ip_data) => {
                if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                    process_ipv6_packet(&ipv6)
                } else {
                    Ok(None)
                }
            }
            IpPacket::None => Ok(None),
        }
    }
}
