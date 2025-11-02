# Huginn-Net Benchmarks

This directory contains comprehensive performance benchmarks for all Huginn-Net protocol libraries. Each benchmark is designed to measure specific aspects of network protocol analysis performance.

## Available Benchmarks

| Protocol | Benchmark File | Library | Command |
|----------|---------------|---------|---------|
| **TLS** | `bench_tls.rs` | `huginn-net-tls` | `cargo bench -p huginn-net-tls` |
| **TCP** | `bench_tcp.rs` | `huginn-net-tcp` | `cargo bench -p huginn-net-tcp` |
| **HTTP** | `bench_http.rs` | `huginn-net-http` | `cargo bench -p huginn-net-http` |

## Performance Summary

### Sequential Mode (Single-Core) Throughput

| Protocol | Detection | Full Analysis | Processing Time | Use Case |
|----------|-----------|---------------|-----------------|----------|
| **TCP** | 6.1M pps | 167K pps | 6.4 μs | OS fingerprinting, MTU detection |
| **TLS** | 66.7M pps | 84.6K pps | 11.8 μs | JA4 fingerprinting, TLS analysis |
| **HTTP** | 23.7M pps | 26K pps | 37.8 μs | Browser/server detection |

### Parallel Mode Performance (TLS)

| Mode | Cores | Throughput | Speedup | 1 Gbps Support | 10 Gbps Support |
|------|-------|------------|---------|----------------|-----------------|
| Sequential | 1 | 84.6K pps | 1.0x | 96% CPU | Overload (961% CPU) |
| Parallel | 8 | 608.8K pps | 7.2x | Sufficient | 75% coverage |

**Note**: TLS parallel processing uses worker pool architecture with round-robin packet distribution. Optimal worker count typically matches available CPU cores.

## Key Performance Insights

### Protocol Efficiency Ranking
1. **TCP**: Best balance of speed and analysis depth
2. **TLS**: Moderate speed with cryptographic complexity, scales well in parallel mode (7.2x with 8 cores)
3. **HTTP**: Comprehensive but slower due to header parsing

### Parallel Processing Support
- **TLS**: Full parallel support with worker pool architecture
  - 7.2x speedup with 8 cores (90% efficiency)
  - Handles 1 Gbps without parallel mode
  - Requires parallel mode for 10 Gbps workloads
- **TCP**: Planned (requires hash-based worker assignment for stateful connections)
- **HTTP**: Planned (requires hash-based worker assignment for flow tracking)

### PCAP Effectiveness
- **HTTP**: 12.5% effectiveness (2/16 packets useful)
- **TCP**: 9.3% effectiveness (4/43 packets useful)
- **TLS**: 100% effectiveness with repeated dataset (1000 TLS packets from 1 original)

## Performance Optimization Recommendations

### For Maximum Performance
**Use protocol-specific libraries instead of the generic `huginn-net`:**

- **TCP Analysis**: Use `huginn-net-tcp` directly
- **TLS Analysis**: Use `huginn-net-tls` directly  
- **HTTP Analysis**: Use `huginn-net-http` directly

### Protocol-Specific Optimizations

#### TCP Optimization
- Disable OS matching when not needed (20% performance gain)
- Use appropriate cache sizes (100-10,000 connections)
- Larger caches provide better performance (~8% improvement)

#### TLS Optimization
- **Sequential Mode**: Sufficient for 1 Gbps workloads (96% CPU)
- **Parallel Mode**: Required for 10 Gbps workloads (8 workers recommended)
- Use `HuginnNetTls::new()` for sequential processing
- Use `HuginnNetTls::with_config(workers, queue_size)` for parallel processing
- Parallel efficiency: ~90% scaling with worker count
- Pre-filter non-TLS packets for significant gains
- JA4 calculation is front-loaded during processing

#### HTTP Optimization
- Server matching can be disabled (25% performance gain)
- Flow cache size has minimal impact (~1% variation)
- Consider selective feature enabling based on requirements

## Detailed Analysis Reports

Each protocol has a dedicated analysis report with comprehensive performance data:

- **[TLS Analysis Report](README-TLS.md)** - JA4 fingerprinting performance
- **[TCP Analysis Report](README-TCP.md)** - OS fingerprinting and network analysis
- **[HTTP Analysis Report](README-HTTP.md)** - Browser and server detection

## Technical Notes

- All benchmarks run in release mode with full compiler optimizations
- Results measured using Criterion.rs with statistical analysis
- Timing measurements include complete analysis pipelines
- PCAP effectiveness varies based on protocol handshake presence
- Sequential mode results are single-core measurements on x86_64 architecture
- Parallel mode assumes 90% scaling efficiency per worker
- TLS parallel benchmarks repeated 1000x for statistical stability

## Contributing

When adding new benchmarks:
1. Follow the existing benchmark structure and naming conventions
2. Include comprehensive performance analysis in protocol-specific READMEs
3. Use real-world PCAP data for accurate performance measurements
4. Document any new optimization techniques or performance insights
5. Include parallel mode benchmarks when applicable