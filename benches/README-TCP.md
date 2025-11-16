# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

## Test Data

PCAP dataset: `macos_tcp_flags.pcap` repeated 1000x for statistical stability (43,000 packets total).

Analysis results:
- **SYN packets**: 1,000 (OS fingerprinting)
- **SYN-ACK packets**: 42,000 (Server response analysis)
- **MTU detections**: 1,000 (Network infrastructure)
- **Uptime calculations**: 0 (No TCP timestamp options)

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| Packet Parsing | 9 ns | 111.1M pps | Structure validation |
| Full TCP Analysis | 1.530 µs | 653.6K pps | Complete processing |
| With OS Matching | 915 ns | 1.09M pps | Database lookup |
| Without OS Matching | 397 ns | 2.52M pps | Skip database |
| Overhead Analysis | - | 167x | Parsing → Full analysis |

### Parallel Mode (Multi-Worker)

**Configuration**: `batch_size=32`, `timeout_ms=10`, `queue_size=100`

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|-------------|------------|---------|------------|-------------|-------|
| 1 (seq) | 1.530 µs | 653.6K pps | 1.00x | 12.4% | 124.3% [OVERLOAD] | Baseline |
| 2 | 273 ns | 3.66M pps | 5.60x | 2.2% | 22.2% | Good scaling |
| 4 | 249 ns | 4.02M pps | 6.15x | 2.0% | 20.2% | **Optimal** |
| 8 | 253 ns | 3.95M pps | 6.05x | 2.1% | 20.6% | Excellent scaling |

**Worker Architecture**: Hash-based worker assignment (packets from same source IP route to same worker)

**Note**: Maintains per-connection state consistency. Benchmarks include worker pool overhead. Tested on 8-core system.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | 397 ns (2.52M pps) | 915 ns (1.09M pps) | 130.2% | Database lookup |
| Link Matching | 1.142 µs (875.7K pps) | 1.205 µs (829.9K pps) | 5.6% | MTU database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 425 ns | 2.35M pps | Memory-constrained |
| Standard (1000) | 509 ns | 1.96M pps | Typical usage |
| Large (10000) | 379 ns | 2.64M pps | High connection volumes |

**Note**: Larger cache provides +31% throughput improvement for high-volume scenarios.

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (4 workers) | Parallel (8 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 12.4% CPU [OK] | 2.0% CPU [OK] | 2.1% CPU [OK] |
| 10 Gbps (812,740 pps) | 124.3% [OVERLOAD] | 20.2% CPU [OK] | 20.6% CPU [OK] |

**Recommendation**: Use 4 workers for optimal efficiency. Sequential mode requires parallel processing for 10 Gbps.

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would be higher (16-32 workers), potentially reaching 10-20M+ pps. The 4-worker optimum is specific to 8-core systems.

## Key Findings

### Performance Characteristics

1. **Ultra-Fast Parsing**: TCP packet validation in 9 nanoseconds
2. **High Throughput**: 653.6K pps sequential, 4.02M pps with 4 workers
3. **Moderate Overhead**: 167x from parsing to full analysis
4. **Excellent Parallel Scaling**: 6.15x speedup with 4 workers (20.2% CPU for 10 Gbps)
5. **Hash-Based Routing**: Maintains per-connection state consistency
6. **Production Ready**: Easily handles 10 Gbps workloads with parallel mode

### Optimization Impact

| Optimization | Performance Impact | Notes |
|--------------|-------------------|-------|
| **Parallel mode (4 workers)** | 4.02M pps (20.2% CPU @ 10 Gbps) | **Recommended** |
| Sequential mode | 653.6K pps (124.3% CPU @ 10 Gbps) | Requires parallel |
| Disable OS matching | -130.2% overhead | Skip database lookup |
| Disable link matching | -5.6% overhead | Skip MTU database |
| Large cache (10K) | +31% throughput | Better for high volumes |
| Lock-free dispatch | Enables parallel scaling | Eliminated Mutex contention |
| Batch processing | Reduced syscall overhead | Amortizes per-packet costs |

### Architectural Insights

TCP processing uses:
- **Hash-based dispatch**: Routes packets by source IP to specific workers
- **Stateful tracking**: Maintains per-connection state for SYN/SYN-ACK correlation
- **Isolated caches**: Each worker has its own connection tracker
- **TTL expiration**: 30-second connection timeout for memory management

This architecture ensures consistent per-connection state while enabling high parallel throughput.

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

The benchmark automatically generates a comprehensive report including:
- Sequential mode throughput
- Parallel mode performance (2, 4, and 8 workers)
- Capacity planning for 1 Gbps and 10 Gbps networks
- Feature-specific performance analysis (OS matching, MTU detection)
- Cache size impact analysis
- Absolute throughput metrics per configuration

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability (43,000 packets)
- Measured using Criterion.rs with statistical analysis
- Connection cache uses 30-second TTL-based expiration
- Database matching uses optimized p0f-compatible lookup structures
- Parallel mode uses hash-based worker assignment (same source IP → same worker)
- Worker pool uses crossbeam channels for lock-free dispatch
- Batch processing reduces per-packet overhead
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead
- Testing environment: Standard laptop (non-server hardware)
- Results measured on x86_64 architecture
