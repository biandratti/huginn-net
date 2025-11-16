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
| Packet Parsing | 12 ns | 83.3M pps | Structure validation |
| Full TCP Analysis | 1.025 µs | 975.6k pps | Complete processing |
| Overhead Analysis | - | 84x | Parsing → Full analysis |

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|-------------|------------|------------|-------------|-------|
| 2 | 476 ns | 2.10M pps | 3.9% | 38.7% | Good performance |
| 4 | 474 ns | 2.11M pps | 3.9% | 38.5% | **Best throughput** |
| 8 | 493 ns | 2.03M pps | 4.0% | 40.1% | Good scaling |

**Worker Architecture**: Hash-based worker assignment (packets from same source IP route to same worker)
**Note**: Maintains per-connection state consistency. Benchmarks include worker pool overhead. Tested on 8-core system.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | 488 ns (2.05M pps) | 915 ns (1.09M pps) | 87% | Database lookup |
| Link Matching | 394 ns (2.54M pps) | 826 ns (1.21M pps) | 110% | MTU database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 441 ns | 2.27M pps | Memory-constrained |
| Standard (1000) | 614 ns | 1.63M pps | Typical usage |
| Large (10000) | 395 ns | 2.53M pps | High connection volumes |

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (4 workers) | Parallel (8 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 8.3% CPU [OK] | 3.9% CPU [OK] | 4.0% CPU [OK] |
| 10 Gbps (812,740 pps) | 83.3% CPU [OK] | 38.5% CPU [OK] | 40.1% CPU [OK] |

**Note**: Tested on 8-core system. TCP easily handles 10 Gbps with parallel mode (4 workers optimal). Hash-based routing ensures state consistency.

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would be higher (16-32 workers), potentially reaching higher throughput. The 4-worker optimum is specific to 8-core systems.

## Key Findings

### Performance Characteristics

1. **Fast Parsing**: TCP packet validation in 12 nanoseconds
2. **High Throughput**: 975.6k pps sequential, 2.11M pps with 4 workers
3. **Lower Overhead**: 84x from parsing to full analysis (improved from 135x)
4. **Stable Parallel Performance**: 4 workers achieve 2.11M pps (38.5% CPU for 10 Gbps)
5. **Hash-Based Routing**: Maintains per-connection state consistency
6. **Production Ready**: Handles 10 Gbps workloads with parallel mode

### Optimizations Applied

TCP module includes the same optimizations as TLS and HTTP:
- **Lock-free dispatch**: Removed `Mutex` from packet senders
- **Blocking I/O with batching**: `recv_timeout()` with batch processing (default: 32 packets)
- **Graceful shutdown**: `AtomicBool` flag for responsive worker termination
- **Eliminated redundant parsing**: `IpPacket` stores parsed packets instead of raw bytes
- **Configurable batching**: `batch_size` and `timeout_ms` via `with_config()` API
- **WorkerConfig struct**: Grouped worker parameters for cleaner signatures
- **Comprehensive documentation**: Detailed configuration guides with trade-offs

### Optimization Insights

| Optimization | Performance Gain | Notes |
|--------------|------------------|-------|
| Disable OS matching | 87% faster | Skip database lookup |
| Disable link matching | 110% faster | Skip MTU database |
| Use large cache (10K) | 55% faster | Better for high volumes |
| Use small cache (100) | 28% faster | Better CPU cache locality |
| Use parallel mode (4 workers) | 2.11M pps throughput | Best for high-throughput |

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
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead
- Testing environment: Standard laptop (non-server hardware)
- Results measured on x86_64 architecture
