use huginn_net_tcp::parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
use huginn_net_tcp::HuginnNetTcpError;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

fn unwrap_worker_pool(result: Result<WorkerPool, HuginnNetTcpError>) -> WorkerPool {
    match result {
        Ok(pool) => pool,
        Err(e) => panic!("Failed to create WorkerPool: {e}"),
    }
}

/// Helper to create a minimal Ethernet + IPv4 + TCP packet with a specific source IP
fn create_ipv4_packet(src_ip: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; 54]; // Ethernet (14) + IPv4 (20) + TCP (20)

    // Ethernet header
    packet[12] = 0x08; // EtherType IPv4
    packet[13] = 0x00;

    // IPv4 header (starts at offset 14)
    packet[14] = 0x45; // Version 4, IHL 5
    packet[23] = 0x06; // Protocol TCP
                       // Source IP (offset 26-29)
    packet[26..30].copy_from_slice(&src_ip);
    // Destination IP (offset 30-33)
    packet[30..34].copy_from_slice(&[10, 0, 0, 2]);

    packet
}

#[test]
fn test_worker_pool_rejects_zero_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(0, 100, 32, 10, tx, None, 1000, None);
    assert!(result.is_err());
}

#[test]
fn test_worker_pool_creates_with_valid_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(4, 100, 32, 10, tx, None, 1000, None);
    assert!(result.is_ok());

    let pool = unwrap_worker_pool(result);
    assert_eq!(pool.num_workers.get(), 4);
}

#[test]
fn test_hash_based_dispatch_consistency() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 10;
    let pool = unwrap_worker_pool(WorkerPool::new(4, queue_size, 32, 10, tx, None, 1000, None));

    // Create packets with the same source IP
    // Dispatch enough packets to overflow the queue, ensuring some get dropped
    // This allows us to verify that all packets go to the same worker
    let src_ip = [192, 168, 1, 100];
    let mut queued = 0;
    let mut dropped = 0;

    for _ in 0..(queue_size * 2) {
        match pool.dispatch(create_ipv4_packet(src_ip)) {
            DispatchResult::Queued => queued += 1,
            DispatchResult::Dropped => dropped += 1,
        }
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, queued);
    assert_eq!(stats.total_dropped, dropped);

    // All packets should go to the same worker (hash-based routing)
    // Since we overflowed the queue, at least one worker should have dropped packets
    // and only one worker should have dropped packets (the one handling this IP)
    let workers_with_drops = stats.workers.iter().filter(|w| w.dropped > 0).count();

    assert_eq!(
        workers_with_drops, 1,
        "Expected all packets from same source IP to go to same worker (only one worker should have drops)"
    );

    assert!(stats.total_dispatched > 0, "Expected some packets to be dispatched");
}

#[test]
fn test_different_ips_distributed() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 10;
    let pool = unwrap_worker_pool(WorkerPool::new(4, queue_size, 32, 10, tx, None, 1000, None));

    // Create packets with different source IPs
    let src_ips = vec![
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        [192, 168, 1, 3],
        [192, 168, 1, 4],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
    ];

    // Dispatch multiple packets per IP to increase chance queues aren't empty when checked
    let mut total_dispatched = 0u64;
    for src_ip in &src_ips {
        for _ in 0..5 {
            if pool.dispatch(create_ipv4_packet(*src_ip)) == DispatchResult::Queued {
                total_dispatched += 1;
            }
        }
    }

    let stats = pool.stats();

    // Verify packets were dispatched (some may have been dropped due to queue overflow)
    assert_eq!(stats.total_dispatched, total_dispatched);
    assert!(stats.total_dispatched > 0, "Expected some packets to be dispatched");

    // Packets should be distributed across workers
    // Check queue_size OR dropped count, as packets may have been processed
    // by the time stats() is called. The key is that multiple workers were involved.
    let workers_with_activity = stats
        .workers
        .iter()
        .filter(|w| w.queue_size > 0 || w.dropped > 0)
        .count();

    assert!(
        workers_with_activity > 1,
        "Expected packets from different IPs to be distributed across multiple workers"
    );
}

#[test]
fn test_queue_overflow_handling() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 5;
    let pool = unwrap_worker_pool(WorkerPool::new(2, queue_size, 32, 10, tx, None, 1000, None));

    let mut queued = 0;
    let mut dropped = 0;

    // Try to dispatch many packets to overflow queues
    // Use same IP so they all go to same worker
    let src_ip = [192, 168, 1, 100];
    for _ in 0..100 {
        match pool.dispatch(create_ipv4_packet(src_ip)) {
            DispatchResult::Queued => queued += 1,
            DispatchResult::Dropped => dropped += 1,
        }
    }

    // Should have some dropped packets due to queue overflow
    assert!(dropped > 0, "Expected some packets to be dropped");
    assert!(queued > 0, "Expected some packets to be queued");

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, queued);
    assert_eq!(stats.total_dropped, dropped);
}

#[test]
fn test_stats_accuracy() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, None, 1000, None));

    // Dispatch some packets
    let dispatch_count = 10;
    for i in 0..dispatch_count {
        pool.dispatch(create_ipv4_packet([192, 168, 1, i as u8]));
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, dispatch_count);
    assert_eq!(stats.workers.len(), 2);
}

#[test]
fn test_shutdown_stops_accepting_packets() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, None, 1000, None));

    // Dispatch before shutdown should work
    let result = pool.dispatch(create_ipv4_packet([192, 168, 1, 1]));
    assert_eq!(result, DispatchResult::Queued);

    // Shutdown the pool
    pool.shutdown();

    // Dispatch after shutdown should return Dropped
    let result = pool.dispatch(create_ipv4_packet([192, 168, 1, 1]));
    assert_eq!(result, DispatchResult::Dropped);
}

#[test]
fn test_per_worker_dropped_count() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 2;
    let pool = unwrap_worker_pool(WorkerPool::new(1, queue_size, 32, 10, tx, None, 1000, None));

    // Fill the single worker's queue (same source IP)
    let src_ip = [192, 168, 1, 100];
    for _ in 0..10 {
        pool.dispatch(create_ipv4_packet(src_ip));
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
    let pool = Arc::new(unwrap_worker_pool(WorkerPool::new(4, 100, 32, 10, tx, None, 1000, None)));

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let pool_clone = Arc::clone(&pool);
            thread::spawn(move || {
                for i in 0..25 {
                    let src_ip = [192, 168, thread_id, i];
                    pool_clone.dispatch(create_ipv4_packet(src_ip));
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

#[test]
fn test_state_isolation() {
    let (tx, _rx) = mpsc::channel();
    // Use a smaller queue size to ensure packets remain in queue when checked
    let queue_size = 5;
    let pool = unwrap_worker_pool(WorkerPool::new(3, queue_size, 32, 10, tx, None, 1000, None));

    // Dispatch packets from 3 different IPs (should go to different workers)
    let ips = [[10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]];

    // Send enough packets per IP to fill queues quickly (more than queue_size)
    // This ensures packets remain in queues when stats() is called
    let packets_per_ip = queue_size * 2;
    let mut total_dispatched = 0u64;

    for ip in &ips {
        for _ in 0..packets_per_ip {
            if pool.dispatch(create_ipv4_packet(*ip)) == DispatchResult::Queued {
                total_dispatched += 1;
            }
        }
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, total_dispatched);
    assert!(stats.total_dispatched > 0, "Expected some packets to be dispatched");

    // Verify workers have received packets
    // Check both queue_size and dropped to account for packets that may have been processed
    // or dropped due to queue overflow
    let active_workers = stats
        .workers
        .iter()
        .filter(|w| w.queue_size > 0 || w.dropped > 0)
        .count();
    assert!(active_workers > 0, "Expected at least one worker to have packets");

    let workers_with_queue = stats.workers.iter().filter(|w| w.queue_size > 0).count();
    assert!(
        workers_with_queue > 0 || stats.total_dropped > 0,
        "Expected workers to have packets in queue or have dropped packets"
    );
}
