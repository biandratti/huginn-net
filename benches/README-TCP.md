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

### Sequential Mode (Single-Core)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| Packet Parsing | 6 ns | 166.7M pps | Structure validation |
| Full TCP Analysis | 1.012 µs | 988.1k pps | Complete processing |
| Overhead Analysis | - | 164x | Parsing → Full analysis |

### Parallel Mode (Multi-Core)

| Workers | Time/Packet | Throughput | Speedup | Efficiency | Notes |
|---------|-------------|------------|---------|------------|-------|
| 2 | 346 ns | 2.89M pps | 2.92x | 146% | Excellent scaling |
| 4 | 329 ns | 3.04M pps | 3.08x | 77% | Good scaling |
| 8 | 340 ns | 2.94M pps | 2.98x | 37% | Diminishing returns |

**Note**: TCP parallel processing uses **hash-based worker assignment** where packets from the same source IP always route to the same worker, maintaining per-connection state consistency.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | 405 ns (2.47M pps) | 883 ns (1.13M pps) | 118% | Database lookup |
| Link Matching | 409 ns (2.44M pps) | 963 ns (1.04M pps) | 135% | MTU database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 446 ns | 2.24M pps | Memory-constrained |
| Standard (1000) | 566 ns | 1.77M pps | Typical usage |
| Large (10000) | 391 ns | 2.56M pps | High connection volumes |

### Network Capacity

| Scenario | Sequential (1 core) | Parallel (8 cores) | Improvement |
|----------|--------------------|--------------------|-------------|
| 1 Gbps (81,274 pps) | 8.2% CPU | 2.8% CPU | 2.9x reduction |
| 10 Gbps (812,740 pps) | 82.2% CPU | 27.6% CPU | 3.0x reduction |

## Key Findings

### Performance Characteristics

1. **Very Fast Parsing**: TCP packet validation in 6 nanoseconds
2. **High Throughput**: 988k packets/second sequential, 3.04M with 4 workers
3. **Moderate Overhead**: 164x from parsing to full analysis
4. **Good Parallel Scaling**: 3.08x speedup with 4 workers (77% efficiency)
5. **Hash-Based Routing**: Maintains per-connection state consistency

### Optimization Insights

| Optimization | Performance Gain | Notes |
|--------------|------------------|-------|
| Disable OS matching | 118% faster | Skip database lookup |
| Disable link matching | 135% faster | Skip MTU database |
| Use large cache (10K) | 31% faster | Better for high volumes |
| Use small cache (100) | 21% faster | Better CPU cache locality |
| Use 4 workers (parallel) | 208% faster | Best efficiency |

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
- Speedup and efficiency metrics

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability (43,000 packets)
- Measured using Criterion.rs with statistical analysis
- Connection cache uses 30-second TTL-based expiration
- Database matching uses optimized p0f-compatible lookup structures
- Parallel mode uses hash-based worker assignment (same source IP → same worker)
- Results measured on x86_64 architecture
