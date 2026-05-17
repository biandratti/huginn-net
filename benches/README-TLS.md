# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability (1,000,000 total packets processed per iteration).

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| TLS Detection | ~18 ns | ~56M pps | `is_tls_traffic` byte check only |
| Packet Parsing | ~6 ns | ~167M pps | Ethernet/IP/TCP header parsing |
| Full TLS Processing | ~20 µs | ~50K pps | ClientHello parse + JA4 calculation via TtlCache |

### Parallel Mode (Multi-Worker)

| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|------------|-------------|-------|
| 2 | ~97K pps | ~84% | ~838% | Hash-based flow dispatch |
| 4 | ~96K pps | ~84% | ~839% | Hash-based flow dispatch |
| 8 | ~96K pps | ~84% | ~843% | Hash-based flow dispatch |

**Worker Architecture**: Hash-based flow dispatch — packets from the same TCP flow (src/dst IP + port) always route to the same worker. Each worker maintains its own `TtlCache<FlowKey, TlsClientHelloReader>` for stateful TCP reassembly, required to handle fragmented ClientHello messages.

**Note**: Benchmarks include worker pool creation/dispatch/shutdown overhead. 2 and 4 workers achieve equivalent throughput; 8 workers show marginal degradation due to scheduling overhead on an 8-core system.

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (2 workers) | Parallel (4 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | ~163% CPU [OVERLOAD] | ~84% CPU [OK] | ~84% CPU [OK] |
| 10 Gbps (812,740 pps) | ~1625% CPU [OVERLOAD] | ~838% CPU [OVERLOAD] | ~839% CPU [OVERLOAD] |

**Note**: Tested on 8-core system. Maximum measured throughput is **~97K pps** with 2–4 workers, representing ~12% of 10 Gbps packet rate. Results are stable across repeated runs; the 2-worker configuration is the recommended minimum for 1 Gbps environments.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: TLS byte-level validation in ~18 nanoseconds per packet
2. **JA4 Processing**: Complete fingerprinting in ~20 microseconds per packet (sequential), dominated by TCP reassembly state management
3. **Overhead**: ~1100x from detection to full JA4 processing; ~3300x from raw parsing to full processing (JA4 calculation only)
4. **Worker Performance**: 2 and 4 workers achieve nearly identical throughput (~97K pps); adding more workers does not help on 8-core hardware due to TCP reassembly overhead being the bottleneck
5. **Parallel Scaling**: 2 workers provide ~1.9x throughput improvement over sequential (97K vs ~50K pps)
6. **10 Gbps Limit**: Maximum throughput of ~97K pps is ~12% of 10 Gbps requirements (812K pps)
7. **TCP Reassembly Impact**: Per-worker `TtlCache` state management adds overhead but enables correct handling of fragmented ClientHello across multiple TCP segments

### Mode Selection

| Workload | Mode | Configuration | Measured Throughput |
|----------|------|---------------|---------------------|
| < 1 Gbps (< 81K pps) | Parallel (2 workers) | `HuginnNetTls::with_config(2, 100)` | ~97K pps |
| 1 Gbps (81K pps) | Parallel (2–4 workers) | `HuginnNetTls::with_config(2-4, 100)` | ~97K pps |

**Note**: Throughput measurements are from benchmarks on an 8-core laptop. Results may vary with different hardware and network conditions.

## Running Benchmarks

```bash
cargo bench --bench bench_tls
```

The benchmark automatically generates a comprehensive report including:
- Sequential mode throughput and capacity planning
- Parallel mode throughput with scaling analysis
- 1 Gbps and 10 Gbps network capacity assessment

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability (Criterion.rs with 100 samples)
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead
- **Dispatch**: Hash-based flow routing (`packet_hash::hash_flow`) — same TCP flow always goes to the same worker
- **Reassembly**: Each worker has its own `TtlCache<FlowKey, TlsClientHelloReader>` for stateful TCP reassembly
- Batch processing (default: 32 packets, 10ms timeout) optimizes throughput vs. latency
- Results measured on x86_64 architecture with 8 CPU cores
- Testing environment: Standard laptop (non-server hardware)
