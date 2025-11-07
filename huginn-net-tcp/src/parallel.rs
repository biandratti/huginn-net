//! Parallel processing module for TCP fingerprinting with hash-based worker assignment.
//!
//! This module provides a worker pool for parallel TCP packet processing. Unlike TLS,
//! TCP fingerprinting maintains per-connection state (cache, uptime tracking, etc.),
//! so packets are dispatched to workers based on source IP hash to ensure state consistency.

use crate::error::HuginnNetTcpError;
use crate::output::TcpAnalysisResult;
use crate::packet_parser::{parse_packet, IpPacket};
use crate::process::{process_ipv4_packet, process_ipv6_packet};
use crate::signature_matcher::SignatureMatcher;
use crossbeam_channel::{bounded, Sender, TrySendError};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use ttl_cache::TtlCache;

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
    packet_senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
    result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<TcpAnalysisResult>>>>,
    pub num_workers: NonZeroUsize,
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
    /// - `result_sender`: Channel to send TCP analysis results
    /// - `database`: Optional database for OS fingerprinting (wrapped in Arc for thread sharing)
    /// - `max_connections`: Maximum connections to track per worker
    ///
    /// # Errors
    /// Returns error if `num_workers` is 0 or thread creation fails.
    pub fn new(
        num_workers: usize,
        queue_size: usize,
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

        for worker_id in 0..num_workers.get() {
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_sender_clone = Arc::clone(&result_sender);
            let dropped_counter = Arc::new(AtomicU64::new(0));
            worker_dropped.push(Arc::clone(&dropped_counter));

            // Clone Arc<Database> for each worker (cheap, just increments ref count)
            let worker_database = database.as_ref().map(Arc::clone);

            let handle = thread::Builder::new()
                .name(format!("tcp-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(
                        worker_id,
                        rx,
                        result_sender_clone,
                        worker_database,
                        max_connections,
                    );
                })
                .map_err(|e| {
                    HuginnNetTcpError::Misconfiguration(format!(
                        "Failed to spawn worker thread: {e}"
                    ))
                })?;

            workers.push(handle);
        }

        // Convert Arc<AtomicU64> to plain AtomicU64 by reading values
        let worker_dropped_plain: Vec<AtomicU64> = worker_dropped
            .iter()
            .map(|arc| AtomicU64::new(arc.load(Ordering::Relaxed)))
            .collect();

        Ok(Self {
            _workers: workers,
            packet_senders: Arc::new(Mutex::new(packet_senders)),
            result_sender,
            num_workers,
            dispatched_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            worker_dropped: worker_dropped_plain,
        })
    }

    /// Worker loop that processes TCP packets with local state.
    fn worker_loop(
        worker_id: usize,
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        result_sender: Arc<Mutex<Option<std::sync::mpsc::Sender<TcpAnalysisResult>>>>,
        database: Option<Arc<crate::db::Database>>,
        max_connections: usize,
    ) {
        // Each worker creates its own matcher from the shared database
        let matcher = database.as_ref().map(|db| SignatureMatcher::new(db.as_ref()));

        // Each worker maintains its own connection tracker (state isolation)
        let mut connection_tracker = TtlCache::new(max_connections);

        while let Ok(packet) = rx.recv() {
            // Process packet based on IP version
            let result = match parse_packet(&packet) {
                IpPacket::Ipv4(ip_data) => {
                    if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                        process_ipv4_packet(&ipv4, &mut connection_tracker, matcher.as_ref())
                    } else {
                        Ok(TcpAnalysisResult {
                            syn: None,
                            syn_ack: None,
                            mtu: None,
                            client_uptime: None,
                            server_uptime: None,
                        })
                    }
                }
                IpPacket::Ipv6(ip_data) => {
                    if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                        process_ipv6_packet(&ipv6, &mut connection_tracker, matcher.as_ref())
                    } else {
                        Ok(TcpAnalysisResult {
                            syn: None,
                            syn_ack: None,
                            mtu: None,
                            client_uptime: None,
                            server_uptime: None,
                        })
                    }
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
                                // Receiver dropped, exit worker
                                break;
                            }
                        } else {
                            // Pool is shutting down
                            break;
                        }
                    }
                }
                Err(_e) => {
                    tracing::debug!("Error processing packet: {_e}");
                }
            }
        }

        tracing::debug!("TCP worker {worker_id} exiting");
    }

    /// Dispatches a packet to the appropriate worker based on source IP hash.
    ///
    /// Uses hash-based assignment to ensure packets from the same source IP
    /// always go to the same worker, maintaining state consistency.
    pub fn dispatch(&self, packet: Vec<u8>) -> DispatchResult {
        // Extract source IP for hashing
        let source_ip_hash = Self::hash_source_ip(&packet);
        
        // NonZeroUsize guarantees num_workers.get() > 0
        let worker_id = source_ip_hash
            .checked_rem(self.num_workers.get())
            .unwrap_or(0);

        if let Ok(senders) = self.packet_senders.lock() {
            if senders.is_empty() {
                return DispatchResult::Dropped; // Pool is shutting down
            }

            match senders[worker_id].try_send(packet) {
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
        } else {
            DispatchResult::Dropped // Failed to lock
        }
    }

    /// Hashes the source IP from a packet for worker assignment.
    ///
    /// Parses the IP header to extract source IP and returns its hash.
    fn hash_source_ip(packet: &[u8]) -> usize {
        // Skip Ethernet header (14 bytes) if present
        // Both IPv4 (0x0800) and IPv6 (0x86DD) use same offset
        let ip_start: usize = if packet.len() > 14
            && ((packet[12] == 0x08 && packet[13] == 0x00)
                || (packet[12] == 0x86 && packet[13] == 0xDD))
        {
            14
        } else {
            0 // Raw IP packet
        };

        let min_length = ip_start.checked_add(20).unwrap_or(usize::MAX);
        if packet.len() < min_length {
            // Packet too short, use fallback hash
            return Self::fallback_hash(packet);
        }

        let ip_packet = &packet[ip_start..];
        let version = (ip_packet[0] >> 4) & 0x0F;

        match version {
            4 => {
                // IPv4: source IP at bytes 12-15
                if ip_packet.len() >= 16 {
                    let src_ip = &ip_packet[12..16];
                    Self::hash_bytes(src_ip)
                } else {
                    Self::fallback_hash(packet)
                }
            }
            6 => {
                // IPv6: source IP at bytes 8-23
                if ip_packet.len() >= 24 {
                    let src_ip = &ip_packet[8..24];
                    Self::hash_bytes(src_ip)
                } else {
                    Self::fallback_hash(packet)
                }
            }
            _ => Self::fallback_hash(packet),
        }
    }

    /// Hashes a byte slice using DefaultHasher.
    fn hash_bytes(bytes: &[u8]) -> usize {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish() as usize
    }

    /// Fallback hash for invalid packets.
    fn fallback_hash(packet: &[u8]) -> usize {
        Self::hash_bytes(packet)
    }

    /// Returns current pool statistics.
    pub fn stats(&self) -> PoolStats {
        let mut workers = Vec::new();

        if let Ok(senders) = self.packet_senders.lock() {
            for (id, sender) in senders.iter().enumerate() {
                workers.push(WorkerStats {
                    id,
                    queue_size: sender.len(),
                    dropped: self.worker_dropped[id].load(Ordering::Relaxed),
                });
            }
        }

        PoolStats {
            total_dispatched: self.dispatched_count.load(Ordering::Relaxed),
            total_dropped: self.dropped_count.load(Ordering::Relaxed),
            workers,
        }
    }

    /// Initiates graceful shutdown of the worker pool.
    pub fn shutdown(&self) {
        // Clear all senders to signal workers to stop
        if let Ok(mut senders) = self.packet_senders.lock() {
            senders.clear();
        }

        // Drop result sender to signal workers
        if let Ok(mut sender) = self.result_sender.lock() {
            *sender = None;
        }
    }
}

