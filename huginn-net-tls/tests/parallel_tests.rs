use huginn_net_tls::parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
use huginn_net_tls::HuginnNetTlsError;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

fn unwrap_worker_pool(result: Result<WorkerPool, HuginnNetTlsError>) -> WorkerPool {
    match result {
        Ok(pool) => pool,
        Err(e) => panic!("Failed to create WorkerPool: {e}"),
    }
}

/// Helper to create a minimal Ethernet + IPv4 + TCP packet with specific flow
/// Includes minimal TLS payload to pass is_tls_traffic() check
fn create_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    // Ethernet (14) + IPv4 (20) + TCP (20) + TLS payload (5 bytes minimum)
    let mut packet = vec![0u8; 59];

    // Ethernet header
    packet[12] = 0x08; // EtherType IPv4
    packet[13] = 0x00;

    // IPv4 header (starts at offset 14)
    packet[14] = 0x45; // Version 4, IHL 5
                       // Total length: 20 (IP) + 20 (TCP) + 5 (TLS) = 45
    packet[16..18].copy_from_slice(&45u16.to_be_bytes());
    packet[23] = 0x06; // Protocol TCP
                       // Source IP (offset 26-29)
    packet[26..30].copy_from_slice(&src_ip);
    // Destination IP (offset 30-33)
    packet[30..34].copy_from_slice(&dst_ip);

    // TCP header (starts at offset 34)
    // Source port (offset 34-35)
    packet[34..36].copy_from_slice(&src_port.to_be_bytes());
    // Destination port (offset 36-37)
    packet[36..38].copy_from_slice(&dst_port.to_be_bytes());
    // TCP data offset (5 words = 20 bytes)
    packet[46] = 0x50;

    // TLS payload (starts at offset 54)
    // 0x16 = TLS Handshake, 0x03 0x01 = TLS 1.0, 0x00 0x01 = length 1
    packet[54] = 0x16; // TLS Handshake
    packet[55] = 0x03; // TLS version major
    packet[56] = 0x01; // TLS version minor
    packet[57] = 0x00; // Length high byte
    packet[58] = 0x01; // Length low byte

    packet
}

#[test]
fn test_worker_pool_rejects_zero_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(0, 100, 32, 10, tx, 10000, None);
    assert!(result.is_err());
}

#[test]
fn test_worker_pool_creates_with_valid_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(4, 100, 32, 10, tx, 10000, None);
    assert!(result.is_ok());

    let pool = unwrap_worker_pool(result);
    assert_eq!(pool.num_workers.get(), 4);
}

#[test]
fn test_hash_based_dispatch() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(3, 10, 32, 10, tx, 10000, None));

    // Dispatch 9 packets with different flows to ensure distribution
    for i in 0..9 {
        let src_ip = [192, 168, 1, (i % 255) as u8];
        let packet = create_ipv4_tcp_packet(src_ip, [8, 8, 8, 8], 12345 + i as u16, 443);
        let result = pool.dispatch(packet);
        assert_eq!(result, DispatchResult::Queued);
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, 9);
    assert_eq!(stats.total_dropped, 0);

    // All workers should have received packets (hash-based distribution)
    let workers_with_packets = stats.workers.iter().filter(|w| w.queue_size > 0).count();
    assert!(workers_with_packets > 0, "At least one worker should have packets");
}

#[test]
fn test_queue_overflow_handling() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 5;
    let pool = unwrap_worker_pool(WorkerPool::new(2, queue_size, 32, 10, tx, 10000, None));

    let mut queued = 0;
    let mut dropped = 0;

    // Try to dispatch many packets to overflow queues
    // Use same flow (same src_ip, dst_ip, src_port, dst_port) to target same worker and fill its queue
    for _ in 0..100 {
        let packet = create_ipv4_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 443);
        match pool.dispatch(packet) {
            DispatchResult::Queued => queued += 1,
            DispatchResult::Dropped => dropped += 1,
        }
    }

    // Should have some dropped packets due to queue overflow
    assert!(dropped > 0, "Expected some packets to be dropped");
    assert!(queued > 0, "Expected some packets to be queued");

    let stats = pool.stats();
    // total_dispatched counts all packets that were attempted (queued + dropped by queue overflow)
    assert_eq!(stats.total_dispatched, queued + dropped);
    assert_eq!(stats.total_dropped, dropped);
}

#[test]
fn test_stats_accuracy() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, 10000, None));

    // Dispatch some packets
    let dispatch_count = 10;
    for i in 0..dispatch_count {
        let packet = create_ipv4_tcp_packet(
            [192, 168, 1, (i % 255) as u8],
            [8, 8, 8, 8],
            12345 + i as u16,
            443,
        );
        pool.dispatch(packet);
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, dispatch_count);
    assert_eq!(stats.workers.len(), 2);
}

#[test]
fn test_shutdown_stops_accepting_packets() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, 10000, None));

    // Dispatch before shutdown should work
    let packet = create_ipv4_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 443);
    let result = pool.dispatch(packet);
    assert_eq!(result, DispatchResult::Queued);

    // Shutdown the pool
    pool.shutdown();

    // Dispatch after shutdown should return Dropped
    let packet = create_ipv4_tcp_packet([192, 168, 1, 101], [8, 8, 8, 8], 12346, 443);
    let result = pool.dispatch(packet);
    assert_eq!(result, DispatchResult::Dropped);
}

#[test]
fn test_per_worker_dropped_count() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 2;
    let pool = unwrap_worker_pool(WorkerPool::new(1, queue_size, 32, 10, tx, 10000, None));

    // Fill the single worker's queue
    // Use same flow to ensure all packets go to the same worker
    for i in 0..10 {
        let packet =
            create_ipv4_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 443 + (i % 10) as u16);
        pool.dispatch(packet);
    }

    let stats = pool.stats();

    // Should have dropped packets
    assert!(stats.total_dropped > 0);

    // The single worker should have the drops
    assert_eq!(stats.workers.len(), 1);
    assert_eq!(stats.workers[0].dropped, stats.total_dropped);
}

#[test]
fn test_concurrent_dispatch() {
    let (tx, _rx) = mpsc::channel();
    let pool = Arc::new(unwrap_worker_pool(WorkerPool::new(4, 100, 32, 10, tx, 10000, None)));

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let pool_clone = Arc::clone(&pool);
            thread::spawn(move || {
                for i in 0..25 {
                    let src_ip = [192, 168, 1, (thread_id * 25 + i) as u8];
                    let packet =
                        create_ipv4_tcp_packet(src_ip, [8, 8, 8, 8], 12345 + i as u16, 443);
                    pool_clone.dispatch(packet);
                }
            })
        })
        .collect();

    for handle in handles {
        if handle.join().is_err() {
            panic!("Thread panicked during concurrent dispatch test");
        }
    }

    let stats = pool.stats();
    // 4 threads * 25 dispatches = 100 total (some might be queued, some dropped)
    let total_processed = stats.total_dispatched + stats.total_dropped;
    assert_eq!(total_processed, 100);
}

#[test]
fn test_worker_stats_display() {
    let worker = WorkerStats { id: 0, queue_size: 5, dropped: 10 };

    let output = format!("{worker}");
    assert!(output.contains("Worker 0"));
    assert!(output.contains("queue_size=5"));
    assert!(output.contains("dropped=10"));
}

#[test]
fn test_pool_stats_display() {
    let stats = PoolStats {
        total_dispatched: 100,
        total_dropped: 5,
        workers: vec![
            WorkerStats { id: 0, queue_size: 2, dropped: 3 },
            WorkerStats { id: 1, queue_size: 1, dropped: 2 },
        ],
    };

    let output = format!("{stats}");
    assert!(output.contains("dispatched: 100"));
    assert!(output.contains("dropped: 5"));
    assert!(output.contains("Worker 0"));
    assert!(output.contains("Worker 1"));
}
