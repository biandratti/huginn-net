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
    let result = WorkerPool::new(0, 100, tx, None, 1000);
    assert!(result.is_err());
}

#[test]
fn test_worker_pool_creates_with_valid_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(4, 100, tx, None, 1000);
    assert!(result.is_ok());

    let pool = unwrap_worker_pool(result);
    assert_eq!(pool.num_workers.get(), 4);
}

#[test]
fn test_hash_based_dispatch_consistency() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(4, 10, tx, None, 1000));

    // Create packets with the same source IP
    let src_ip = [192, 168, 1, 100];
    let packets: Vec<_> = (0..10).map(|_| create_ipv4_packet(src_ip)).collect();

    // Dispatch all packets
    for packet in packets {
        pool.dispatch(packet);
    }

    let stats = pool.stats();

    // All packets should go to the same worker (hash-based routing)
    let workers_with_packets = stats
        .workers
        .iter()
        .filter(|w| w.queue_size > 0 || w.dropped > 0)
        .count();

    assert_eq!(
        workers_with_packets, 1,
        "Expected all packets from same source IP to go to same worker"
    );
}

#[test]
fn test_different_ips_distributed() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(4, 10, tx, None, 1000));

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

    for src_ip in src_ips {
        pool.dispatch(create_ipv4_packet(src_ip));
    }

    let stats = pool.stats();

    // Packets should be distributed across workers
    let workers_with_packets = stats.workers.iter().filter(|w| w.queue_size > 0).count();

    assert!(
        workers_with_packets > 1,
        "Expected packets from different IPs to be distributed"
    );
}

#[test]
fn test_queue_overflow_handling() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 5;
    let pool = unwrap_worker_pool(WorkerPool::new(2, queue_size, tx, None, 1000));

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
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, tx, None, 1000));

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
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, tx, None, 1000));

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
    let pool = unwrap_worker_pool(WorkerPool::new(1, queue_size, tx, None, 1000));

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
    let pool = Arc::new(unwrap_worker_pool(WorkerPool::new(4, 100, tx, None, 1000)));

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
    let pool = unwrap_worker_pool(WorkerPool::new(3, 100, tx, None, 1000));

    // Dispatch packets from 3 different IPs (should go to different workers)
    let ips = [[10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]];

    for ip in &ips {
        // Send multiple packets from each IP
        for _ in 0..5 {
            pool.dispatch(create_ipv4_packet(*ip));
        }
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, 15);

    // Verify workers have received packets
    let active_workers = stats.workers.iter().filter(|w| w.queue_size > 0).count();
    assert!(active_workers > 0, "Expected at least one worker to have packets");
}
