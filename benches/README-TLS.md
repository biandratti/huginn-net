# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability (1000 TLS Client Hello packets).

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| TLS Detection | 21 ns | 48M pps | Packet validation |
| Full TLS Processing | 22 µs | 45K pps | Complete JA4 fingerprinting with TCP reassembly |
| Overhead Analysis | - | 1034x | Detection → Full processing |

### Parallel Mode (Multi-Worker)

| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|------------|-------------|-------|
| 2 | 97K pps | 84% | 835% | Hash-based flow dispatch |
| 4 | 97K pps | 84% | 841% | Hash-based flow dispatch |
| 8 | 96K pps | 85% | 851% | Hash-based flow dispatch |

**Worker Architecture**: Hash-based flow dispatch (TCP reassembly with TtlCache)
**Note**: Benchmarks include worker pool creation/dispatch/shutdown overhead. Throughput is lower than previous round-robin implementation due to TCP reassembly overhead and flow state management.

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (2 workers) | Parallel (4 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 212% CPU [OVERLOAD] | 84% CPU [OK] | 84% CPU [OK] |
| 10 Gbps (812,740 pps) | 2121% CPU [OVERLOAD] | 835% CPU [OVERLOAD] | 841% CPU [OVERLOAD] |

**Note**: Tested on 8-core system. Maximum measured throughput is **97K pps** with 2-4 workers, which represents 12% of 10 Gbps packet rate.

**Scaling considerations**: The 4-worker optimum is specific to 8-core systems. On server hardware with more cores, higher worker counts may improve throughput, though actual performance will depend on workload characteristics and system configuration.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: TLS packet validation in 21 nanoseconds
2. **JA4 Processing**: Complete fingerprinting in 22 microseconds per packet (sequential) with TCP reassembly
3. **High Overhead**: 1034x from detection to full processing (includes TCP reassembly + JA4 calculation)
4. **Worker Performance**: All worker configurations (2, 4, 8) achieve similar throughput (96-97K pps) due to TCP reassembly overhead
5. **Parallel Scaling**: 2 workers provide 2.2x throughput improvement over sequential mode (97K vs 45K pps)
6. **10 Gbps Limit**: Maximum throughput of 97K pps is 12% of 10 Gbps requirements (812K pps)
7. **TCP Reassembly Impact**: Flow state management (TtlCache) adds overhead but enables proper handling of fragmented ClientHello messages

### Mode Selection

| Workload | Mode | Configuration | Measured Throughput |
|----------|------|---------------|---------------------|
| < 1 Gbps (< 81K pps) | Parallel (2 workers) | `HuginnNetTls::with_config(2, 100)` | 97K pps |
| 1 Gbps (81K pps) | Parallel (2-4 workers) | `HuginnNetTls::with_config(2-4, 100)` | 97K pps |

**Note**: Throughput measurements are from benchmarks on 8-core laptop. Results may vary with different hardware and network conditions. The current implementation prioritizes correctness (TCP reassembly for fragmented ClientHello) over raw throughput compared to the previous stateless round-robin approach.

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
- Hash-based flow dispatch ensures packets from same TCP flow go to same worker (required for TCP reassembly)
- TCP reassembly with TtlCache (20-second TTL) enables proper handling of fragmented ClientHello messages
- Batch processing (default: 32 packets, 10ms timeout) optimizes throughput vs. latency
- Results measured on x86_64 architecture with 8 CPU cores
- Testing environment: Standard laptop (non-server hardware)
