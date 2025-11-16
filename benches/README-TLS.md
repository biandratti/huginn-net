# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability (1000 TLS Client Hello packets).

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| TLS Detection | 23 ns | 43.5M pps | Packet validation |
| Full TLS Processing | 19.7 µs | 50.8K pps | Complete JA4 fingerprinting |
| Overhead Analysis | - | 877x | Detection → Full processing |

### Parallel Mode (Multi-Worker)

| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|------------|-------------|-------|
| 2 | 603.5K pps | 13.5% | 134.7% | Excellent efficiency |
| 4 | 623.4K pps | 13.0% | 130.4% | **Best throughput** |
| 8 | 323.1K pps | 25.2% | 251.5% | Diminishing returns |

**Worker Architecture**: Round-robin dispatch (stateless processing)
**Note**: Benchmarks include worker pool creation/dispatch/shutdown overhead

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (2 workers) | Parallel (4 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 160.0% CPU [OVERLOAD] | 13.5% CPU [OK] | 13.0% CPU [OK] |
| 10 Gbps (812,740 pps) | 1599.6% CPU [OVERLOAD] | 134.7% CPU [OVERLOAD] | 130.4% CPU [OVERLOAD] |

**Note**: Tested on 8-core system. Maximum measured throughput is **623.4K pps** with 4 workers, which represents 77% of 10 Gbps packet rate.

**Scaling considerations**: The 4-worker optimum is specific to 8-core systems. On server hardware with more cores, higher worker counts may improve throughput, though actual performance will depend on workload characteristics and system configuration.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: TLS packet validation in 23 nanoseconds
2. **JA4 Processing**: Complete fingerprinting in 19.7 microseconds per packet (sequential)
3. **High Overhead**: 877x from detection to full processing (expected for cryptographic operations)
4. **Optimal Workers**: Best throughput with 4 workers (623.4K pps, 13.0% CPU @ 1 Gbps)
5. **Excellent Scaling**: 2-4 workers provide 12x throughput improvement over sequential mode
6. **10 Gbps Limit**: Maximum throughput of 623.4K pps is ~77% of 10 Gbps requirements (812K pps)

### Mode Selection

| Workload | Mode | Configuration | Measured Throughput |
|----------|------|---------------|---------------------|
| < 1 Gbps (< 81K pps) | Parallel (2 workers) | `HuginnNetTls::with_config(2, 100)` | 603.5K pps |
| 1-7 Gbps (81K-620K pps) | Parallel (4 workers) | `HuginnNetTls::with_config(4, 100)` | 623.4K pps |

**Note**: Throughput measurements are from benchmarks on 8-core laptop. Results may vary with different hardware and network conditions.

## Running Benchmarks

```bash
cargo bench --bench bench_tls
```

The benchmark automatically generates a comprehensive report including:
- Sequential mode throughput and capacity planning
- Parallel mode throughput with scaling analysis
- 1 Gbps and 10 Gbps network capacity assessment
- Code recommendations for production deployment

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability
- Measured using Criterion.rs with statistical analysis
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead
- Lock-free architecture enables excellent multi-core scaling
- Batch processing (default: 32 packets, 10ms timeout) optimizes throughput vs. latency
- Results measured on x86_64 architecture with 8 CPU cores
- Testing environment: Standard laptop (non-server hardware)
