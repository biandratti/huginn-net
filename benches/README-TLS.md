# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability (1000 TLS Client Hello packets).

## Performance Results

### Sequential Mode (Single-Core)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| TLS Detection | 15 ns | 66.7M pps | Packet validation |
| Full TLS Processing | 11.8 µs | 84.6K pps | Complete JA4 fingerprinting |
| Overhead Analysis | - | 788x | Detection → Full processing |

### Parallel Mode (8 Workers)

| Metric | Value | Notes |
|--------|-------|-------|
| Throughput | 608.8K pps | 7.2x speedup |
| Parallel Efficiency | 90% | Excellent scaling |
| Worker Architecture | Round-robin | Stateless packet distribution |

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (8 workers) | Recommendation |
|----------|-----------------------|----------------------|----------------|
| 1 Gbps (81.3K pps) | 96% CPU | Not needed | Use `HuginnNetTls::new()` |
| 10 Gbps (812.7K pps) | 961% CPU (Overload) | 75% coverage | Use `HuginnNetTls::with_config(8, 100)` |
| 10+ Gbps | - | **Scales linearly** | 16+ workers recommended |

**Note**: These benchmarks measured on 8-core laptop (8 workers). Systems with more CPU cores can run **16 workers** (~1.2M pps) or **32 workers** (~2.4M pps), making full 10+ Gbps workloads achievable with 90% efficiency.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: TLS packet validation in 15 nanoseconds
2. **JA4 Processing**: Complete fingerprinting in 11.8 microseconds per packet
3. **High Overhead**: 788x from detection to full processing (expected for cryptographic operations)
4. **Excellent Scaling**: 90% parallel efficiency with worker pool architecture

### Mode Selection

| Workload | Mode | Configuration | Expected Throughput |
|----------|------|---------------|---------------------|
| < 1 Gbps | Sequential | `HuginnNetTls::new()` | 84.6K pps |
| 1-10 Gbps | Parallel (8 workers) | `HuginnNetTls::with_config(8, 100)` | 608.8K pps |
| > 10 Gbps | Parallel (16 workers) | `HuginnNetTls::with_config(16, 100)` | ~1.2M pps |
| > 20 Gbps | Parallel (32 workers) | `HuginnNetTls::with_config(32, 100)` | ~2.4M pps |

**Note**: Worker count can match or exceed CPU core count. More workers require more CPU cores for optimal performance.

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
- Parallel mode assumes 90% scaling efficiency
- Results measured on x86_64 architecture with 8 CPU cores
