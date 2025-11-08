//! Parallel processing support for HTTP analysis using worker pool architecture.
//!
//! This module provides multi-threaded packet processing with hash-based worker assignment
//! to maintain HTTP flow consistency (request/response tracking). Unlike TCP which hashes
//! only the source IP, HTTP hashes the complete flow (src_ip, dst_ip, src_port, dst_port)
//! to ensure requests and responses from the same connection are processed by the same worker.

use crate::error::HuginnNetHttpError;
use crate::http_process::{FlowKey, HttpProcessors, TcpFlow};
use crate::{HttpAnalysisResult, SignatureMatcher};
use crossbeam_channel::{bounded, Sender};
use huginn_net_db as db;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use ttl_cache::TtlCache;

/// Worker pool for parallel HTTP packet processing.
pub struct WorkerPool {
    packet_senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
    result_sender: Arc<Mutex<Option<Sender<HttpAnalysisResult>>>>,
    dispatched_count: Arc<AtomicU64>,
    dropped_count: Arc<AtomicU64>,
    worker_dropped: Vec<Arc<AtomicU64>>,
    num_workers: usize,
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
    /// - `result_tx`: Channel to send analysis results
    /// - `database`: Optional signature database for matching
    /// - `max_connections`: Maximum HTTP flows to track per worker
    ///
    /// # Returns
    /// A new `WorkerPool` or an error if creation fails.
    pub fn new(
        num_workers: usize,
        queue_size: usize,
        result_tx: Sender<HttpAnalysisResult>,
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

        for worker_id in 0..num_workers {
            let (tx, rx) = bounded::<Vec<u8>>(queue_size);
            packet_senders.push(tx);

            let result_tx_clone = result_tx.clone();
            let db_clone = database.clone();
            let dropped = Arc::new(AtomicU64::new(0));
            worker_dropped.push(Arc::clone(&dropped));

            thread::Builder::new()
                .name(format!("http-worker-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(rx, result_tx_clone, db_clone, max_connections, dropped)
                })
                .map_err(|e| {
                    HuginnNetHttpError::Misconfiguration(format!(
                        "Failed to spawn worker thread {worker_id}: {e}"
                    ))
                })?;
        }

        Ok(Arc::new(Self {
            packet_senders: Arc::new(Mutex::new(packet_senders)),
            result_sender: Arc::new(Mutex::new(Some(result_tx))),
            dispatched_count: Arc::new(AtomicU64::new(0)),
            dropped_count: Arc::new(AtomicU64::new(0)),
            worker_dropped,
            num_workers,
        }))
    }

    /// Worker thread main loop.
    fn worker_loop(
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        result_tx: Sender<HttpAnalysisResult>,
        database: Option<Arc<db::Database>>,
        max_connections: usize,
        dropped: Arc<AtomicU64>,
    ) {
        let matcher = database
            .as_ref()
            .map(|db| SignatureMatcher::new(db.as_ref()));
        let mut http_flows = TtlCache::new(max_connections);
        let http_processors = HttpProcessors::new();

        while let Ok(packet) = rx.recv() {
            match Self::process_packet(&packet, &mut http_flows, &http_processors, matcher.as_ref())
            {
                Ok(result) => {
                    if result_tx.send(result).is_err() {
                        // Result channel closed, stop worker
                        break;
                    }
                }
                Err(_) => {
                    // Packet processing error, increment dropped count
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
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
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::ipv6::Ipv6Packet;

        match parse_packet(packet) {
            IpPacket::Ipv4(ip_data) => {
                if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                    process::process_ipv4_packet(&ipv4, http_flows, http_processors, matcher)
                } else {
                    Ok(HttpAnalysisResult { http_request: None, http_response: None })
                }
            }
            IpPacket::Ipv6(ip_data) => {
                if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                    process::process_ipv6_packet(&ipv6, http_flows, http_processors, matcher)
                } else {
                    Ok(HttpAnalysisResult { http_request: None, http_response: None })
                }
            }
            IpPacket::None => Ok(HttpAnalysisResult { http_request: None, http_response: None }),
        }
    }

    /// Dispatches a packet to a worker based on flow hash.
    pub fn dispatch(&self, packet: Vec<u8>) -> DispatchResult {
        let worker_id = Self::hash_flow(&packet, self.num_workers);

        self.dispatched_count.fetch_add(1, Ordering::Relaxed);

        if let Ok(senders) = self.packet_senders.lock() {
            if let Some(sender) = senders.get(worker_id) {
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
        } else {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            DispatchResult::Dropped
        }
    }

    /// Computes worker assignment based on HTTP flow hash.
    ///
    /// Hashes the complete flow (src_ip, dst_ip, src_port, dst_port) to ensure
    /// all packets from the same connection go to the same worker for proper
    /// request/response tracking.
    fn hash_flow(packet: &[u8], num_workers: usize) -> usize {
        // Skip Ethernet header (14 bytes) if present
        let ip_start: usize = if packet.len() > 14
            && ((packet[12] == 0x08 && packet[13] == 0x00)
                || (packet[12] == 0x86 && packet[13] == 0xDD))
        {
            14
        } else {
            0 // Raw IP packet
        };

        let min_length = ip_start.saturating_add(40); // IP header + TCP header minimum
        if packet.len() < min_length {
            // Packet too short, use fallback hash
            return Self::fallback_hash(packet, num_workers);
        }

        let ip_packet = &packet[ip_start..];
        let version = (ip_packet[0] >> 4) & 0x0F;

        match version {
            4 => Self::hash_ipv4_flow(ip_packet, num_workers),
            6 => Self::hash_ipv6_flow(ip_packet, num_workers),
            _ => Self::fallback_hash(packet, num_workers),
        }
    }

    /// Hashes IPv4 flow (src_ip, dst_ip, src_port, dst_port).
    fn hash_ipv4_flow(ip_packet: &[u8], num_workers: usize) -> usize {
        if ip_packet.len() < 20 {
            return Self::fallback_hash(ip_packet, num_workers);
        }

        // Check if protocol is TCP (6)
        let protocol = ip_packet[9];
        if protocol != 6 {
            // Not TCP, hash source IP only
            let src_ip = &ip_packet[12..16];
            return Self::hash_bytes(src_ip)
                .checked_rem(num_workers)
                .unwrap_or(0);
        }

        // IPv4 header is variable length (IHL field)
        let ihl = (ip_packet[0] & 0x0F) as usize;
        let ip_header_len = ihl.saturating_mul(4);

        if ip_packet.len() < ip_header_len.saturating_add(4) {
            // TCP header not fully present, hash IP only
            let src_ip = &ip_packet[12..16];
            return Self::hash_bytes(src_ip)
                .checked_rem(num_workers)
                .unwrap_or(0);
        }

        // Extract: src_ip, dst_ip, src_port, dst_port
        let src_ip = &ip_packet[12..16];
        let dst_ip = &ip_packet[16..20];
        let tcp_header = &ip_packet[ip_header_len..];
        let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);

        (hasher.finish() as usize)
            .checked_rem(num_workers)
            .unwrap_or(0)
    }

    /// Hashes IPv6 flow (src_ip, dst_ip, src_port, dst_port).
    fn hash_ipv6_flow(ip_packet: &[u8], num_workers: usize) -> usize {
        if ip_packet.len() < 40 {
            return Self::fallback_hash(ip_packet, num_workers);
        }

        // Check if next header is TCP (6)
        let next_header = ip_packet[6];
        if next_header != 6 {
            // Not TCP, hash source IP only
            let src_ip = &ip_packet[8..24];
            return Self::hash_bytes(src_ip)
                .checked_rem(num_workers)
                .unwrap_or(0);
        }

        if ip_packet.len() < 44 {
            // TCP header not fully present, hash IP only
            let src_ip = &ip_packet[8..24];
            return Self::hash_bytes(src_ip)
                .checked_rem(num_workers)
                .unwrap_or(0);
        }

        // Extract: src_ip, dst_ip, src_port, dst_port
        let src_ip = &ip_packet[8..24];
        let dst_ip = &ip_packet[24..40];
        let tcp_header = &ip_packet[40..];
        let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);

        (hasher.finish() as usize)
            .checked_rem(num_workers)
            .unwrap_or(0)
    }

    /// Hashes a byte slice using DefaultHasher.
    fn hash_bytes(bytes: &[u8]) -> usize {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish() as usize
    }

    /// Fallback hash for invalid packets.
    ///
    /// Used when a packet is too short, malformed, or has an unknown IP version.
    /// Instead of discarding the packet or crashing, we hash the entire packet contents
    /// to distribute it to a worker. This sacrifices per-flow state consistency
    /// for that specific packet, but ensures robustness in production environments
    /// with corrupted traffic, fragmentation issues, or malicious crafted packets.
    ///
    /// Note: This is specific to HTTP's hash-based flow routing.
    fn fallback_hash(packet: &[u8], num_workers: usize) -> usize {
        Self::hash_bytes(packet)
            .checked_rem(num_workers)
            .unwrap_or(0)
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
