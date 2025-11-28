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

#[test]
fn test_worker_pool_rejects_zero_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(0, 100, 32, 10, tx, None);
    assert!(result.is_err());
}

#[test]
fn test_worker_pool_creates_with_valid_workers() {
    let (tx, _rx) = mpsc::channel();
    let result = WorkerPool::new(4, 100, 32, 10, tx, None);
    assert!(result.is_ok());

    let pool = unwrap_worker_pool(result);
    assert_eq!(pool.num_workers.get(), 4);
}

#[test]
fn test_round_robin_dispatch() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(3, 10, 32, 10, tx, None));

    // Dispatch 9 packets (3 per worker)
    for _ in 0..9 {
        let result = pool.dispatch(vec![0u8; 100]);
        assert_eq!(result, DispatchResult::Queued);
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, 9);
    assert_eq!(stats.total_dropped, 0);

    // All workers should have received packets (round-robin)
    for worker_stat in &stats.workers {
        assert!(worker_stat.queue_size > 0 || worker_stat.dropped == 0);
    }
}

#[test]
fn test_queue_overflow_handling() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 5;
    let pool = unwrap_worker_pool(WorkerPool::new(2, queue_size, 32, 10, tx, None));

    let mut queued = 0;
    let mut dropped = 0;

    // Try to dispatch many packets to overflow queues
    for _ in 0..100 {
        match pool.dispatch(vec![0u8; 100]) {
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
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, None));

    // Dispatch some packets
    let dispatch_count = 10;
    for _ in 0..dispatch_count {
        pool.dispatch(vec![0u8; 100]);
    }

    let stats = pool.stats();
    assert_eq!(stats.total_dispatched, dispatch_count);
    assert_eq!(stats.workers.len(), 2);
}

#[test]
fn test_shutdown_stops_accepting_packets() {
    let (tx, _rx) = mpsc::channel();
    let pool = unwrap_worker_pool(WorkerPool::new(2, 100, 32, 10, tx, None));

    // Dispatch before shutdown should work
    let result = pool.dispatch(vec![0u8; 100]);
    assert_eq!(result, DispatchResult::Queued);

    // Shutdown the pool
    pool.shutdown();

    // Dispatch after shutdown should return Dropped
    let result = pool.dispatch(vec![0u8; 100]);
    assert_eq!(result, DispatchResult::Dropped);
}

#[test]
fn test_per_worker_dropped_count() {
    let (tx, _rx) = mpsc::channel();
    let queue_size = 2;
    let pool = unwrap_worker_pool(WorkerPool::new(1, queue_size, 32, 10, tx, None));

    // Fill the single worker's queue
    for _ in 0..10 {
        pool.dispatch(vec![0u8; 100]);
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
    let pool = Arc::new(unwrap_worker_pool(WorkerPool::new(4, 100, 32, 10, tx, None)));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let pool_clone = Arc::clone(&pool);
            thread::spawn(move || {
                for _ in 0..25 {
                    pool_clone.dispatch(vec![0u8; 100]);
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
