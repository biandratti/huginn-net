# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability (1000 TLS Client Hello packets).

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| TLS Detection | 14 ns | 71.4M pps | Packet validation |
| Full TLS Processing | 20.1 µs | 49.7K pps | Complete JA4 fingerprinting |
| Overhead Analysis | - | 839x | Detection → Full processing |

### Parallel Mode (Multi-Worker)

| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|------------|-------------|-------|
| 2 | 200.7K pps | 40.5% | 404.9% | Good throughput |
| 4 | 232.9K pps | 34.9% | 348.9% | **Best throughput** |
| 8 | 137.1K pps | 59.3% | 593.0% | Diminishing returns |

**Worker Architecture**: Round-robin dispatch (stateless processing)
**Note**: Benchmarks include worker pool creation/dispatch/shutdown overhead

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (2 workers) | Parallel (4 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 163.5% CPU [OVERLOAD] | 40.5% CPU [OK] | 34.9% CPU [OK] |
| 10 Gbps (812,740 pps) | 1635.5% CPU [OVERLOAD] | 404.9% CPU [OVERLOAD] | 348.9% CPU [OVERLOAD] |

**Note**: Tested on 8-core system. TLS shows best throughput with **4 workers** (232.9K pps). 10 Gbps requires more optimization or hardware acceleration.

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would be higher (16-32 workers), potentially reaching 1M+ pps. The 4-worker optimum is specific to 8-core systems. TLS uses round-robin dispatch which scales better linearly with more cores than TCP's hash-based routing.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: TLS packet validation in 14 nanoseconds
2. **JA4 Processing**: Complete fingerprinting in 20.1 microseconds per packet (sequential)
3. **High Overhead**: 839x from detection to full processing (expected for cryptographic operations)
4. **Optimal Workers**: Best throughput with 4 workers (232.9K pps, 34.9% CPU @ 1 Gbps)
5. **Scaling Behavior**: Performance degrades with 8+ workers due to dispatch overhead

### Mode Selection

| Workload | Mode | Configuration | Expected Throughput |
|----------|------|---------------|---------------------|
| < 1 Gbps | Parallel (2 workers) | `HuginnNetTls::with_config(2, 100)` | 200.7K pps |
| 1-2 Gbps | Parallel (4 workers) | `HuginnNetTls::with_config(4, 100)` | 232.9K pps |

**Note**: Parallel processing includes worker pool overhead. Results may vary on server-grade hardware.

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
- Throughput decreases with more workers (round-robin dispatch overhead)
- Results measured on x86_64 architecture with 8 CPU cores
- Testing environment: Standard laptop (non-server hardware)
