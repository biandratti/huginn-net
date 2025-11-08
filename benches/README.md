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
| **TCP** | 166.7M pps | 988.1K pps | 1.012 μs | OS fingerprinting, MTU detection |
| **TLS** | 66.7M pps | 84.6K pps | 11.8 μs | JA4 fingerprinting, TLS analysis |
| **HTTP** | 200M pps | 562.1K pps | 1.779 μs | Browser/server detection |

### Parallel Mode Performance

#### TLS (Round-Robin Dispatch)
| Mode | Workers | Throughput | Speedup | 1 Gbps Support | 10 Gbps Support |
|------|---------|------------|---------|----------------|-----------------|
| Sequential | 1 | 84.6K pps | 1.0x | 96% CPU | Overload (961% CPU) |
| Parallel | 8 | 608.8K pps | 7.2x | Sufficient | 75% coverage |

#### TCP (Hash-Based Worker Assignment)
| Mode | Workers | Throughput | Speedup | Efficiency | 1 Gbps | 10 Gbps |
|------|---------|------------|---------|------------|--------|---------|
| Sequential | 1 | 988.1K pps | 1.0x | 100% | 8.2% CPU | 82.2% CPU |
| Parallel | 4 | 3.04M pps | 3.08x | 77% | 2.7% CPU | 26.7% CPU |
| Parallel | 8 | 2.94M pps | 2.98x | 37% | 2.8% CPU | 27.6% CPU |

**Notes**: 
- TLS uses round-robin dispatch (stateless processing) - **scales linearly with more workers**
- TCP uses hash-based routing (same source IP → same worker for state consistency)
- TCP shows best efficiency with 4 workers; diminishing returns beyond that
- These benchmarks measured on laptop hardware (8 CPU cores); **more workers on server-class CPUs (16-32+ cores) would show significantly better performance**, especially for TLS

## Key Performance Insights

### Protocol Efficiency Ranking
1. **TCP**: Fastest (988k pps sequential, 3.04M parallel) - excellent balance of speed and analysis depth
2. **HTTP**: Fast (562.1K pps) - comprehensive application-layer analysis
3. **TLS**: Moderate (84.6K pps sequential, 608.8K parallel) - cryptographic complexity

### Parallel Processing Support
- **TCP**: Full parallel support with hash-based worker assignment
  - 3.08x speedup with 4 workers (77% efficiency)
  - Best performance at 4 workers (3.04M pps)
  - Hash-based routing maintains per-connection state consistency
  - Same source IP always routes to same worker
  - Each worker has isolated connection tracker and cache
  - Handles 10 Gbps at 26.7% CPU (4 workers on 8-core system)
  
- **TLS**: Full parallel support with worker pool architecture
  - 7.2x speedup with 8 workers (90% efficiency)
  - **Projected scaling**: ~14x with 16 workers, ~28x with 32 workers (if 90% efficiency maintained)
  - Handles 1 Gbps without parallel mode
  - Requires parallel mode for 10 Gbps workloads
  - Uses round-robin dispatch (stateless processing)
  - **Scales effectively with more workers**
  
- **HTTP**: Planned (requires hash-based worker assignment for flow tracking)

### PCAP Effectiveness
- **HTTP**: 6.2% effectiveness with repeated dataset (16,000 packets from 16 original)
- **TCP**: 102.3% effectiveness with repeated dataset (43,000 packets from 43 original)
- **TLS**: 100% effectiveness with repeated dataset (1,000 packets from 1 original)

## Performance Optimization Recommendations

### For Maximum Performance
**Use protocol-specific libraries instead of the generic `huginn-net`:**

- **TCP Analysis**: Use `huginn-net-tcp` directly
- **TLS Analysis**: Use `huginn-net-tls` directly  
- **HTTP Analysis**: Use `huginn-net-http` directly

### Protocol-Specific Optimizations

#### TCP Optimization
- **Parallel mode (4 workers)**: 208% faster than sequential (3.08x speedup)
- Disable OS matching when not needed (118% faster)
- Disable link matching when not needed (135% faster)
- Use large cache (10K connections) for high volumes (31% faster)
- Use small cache (100 connections) for better CPU cache locality (21% faster)
- Hash-based routing ensures consistent per-connection state

#### TLS Optimization
- **Sequential Mode**: Sufficient for 1 Gbps workloads (96% CPU)
- **Parallel Mode**: Required for 10 Gbps workloads (8 workers recommended)
- Use `HuginnNetTls::new()` for sequential processing
- Use `HuginnNetTls::with_config(workers, queue_size)` for parallel processing
- Parallel efficiency: ~90% scaling with worker count
- Pre-filter non-TLS packets for significant gains
- JA4 calculation is front-loaded during processing

#### HTTP Optimization
- Disable browser matching when not needed (46% faster)
- Disable server matching when not needed (48% faster)
- Use large cache (10K flows) for high volumes (8% faster)
- Header analysis only (skip database matching) for best performance (49% faster)

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
- TLS parallel mode uses round-robin dispatch (90% scaling efficiency with workers)
- TCP parallel mode uses hash-based worker assignment (77% efficiency at 4 workers)
- TLS, TCP, and HTTP benchmarks use repeated datasets (1000x) for statistical stability

## Contributing

When adding new benchmarks:
1. Follow the existing benchmark structure and naming conventions
2. Include comprehensive performance analysis in protocol-specific READMEs
3. Use real-world PCAP data for accurate performance measurements
4. Document any new optimization techniques or performance insights
5. Include parallel mode benchmarks when applicable