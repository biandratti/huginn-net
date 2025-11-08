# Huginn-Net Benchmarks

This directory contains comprehensive performance benchmarks for all Huginn-Net protocol libraries. Each benchmark is designed to measure specific aspects of network protocol analysis performance.

## Available Benchmarks

| Protocol | Benchmark File | Library | Command |
|----------|---------------|---------|---------|
| **TLS** | `bench_tls.rs` | `huginn-net-tls` | `cargo bench -p huginn-net-tls` |
| **TCP** | `bench_tcp.rs` | `huginn-net-tcp` | `cargo bench -p huginn-net-tcp` |
| **HTTP** | `bench_http.rs` | `huginn-net-http` | `cargo bench -p huginn-net-http` |

## Performance Summary

### Sequential Mode (Single-Thread) Throughput

| Protocol | Detection | Full Analysis | Processing Time | Use Case |
|----------|-----------|---------------|-----------------|----------|
| **TCP** | 166.7M pps | 1.11M pps | 901 ns | OS fingerprinting, MTU detection |
| **HTTP** | 200M pps | 797K pps | 1.254 μs | Browser/server detection, flow tracking |
| **TLS** | 66.7M pps | 49.7K pps | 20.1 μs | JA4 fingerprinting, TLS analysis |

### Parallel Mode Performance

#### TLS (Round-Robin Dispatch)
| Mode | Workers | Throughput | Speedup | 1 Gbps Support | 10 Gbps Support |
|------|---------|------------|---------|----------------|-----------------|
| Sequential | 1 | 84.6K pps | 1.0x | 96% CPU | Overload (961% CPU) |
| Parallel | 8 | 608.8K pps | 7.2x | Sufficient | 75% coverage |

#### TCP (Hash-Based Worker Assignment)
| Mode | Workers | Throughput | 1 Gbps | 10 Gbps |
|------|---------|------------|--------|---------|
| Sequential | 1 | 1.11M pps | 7.3% CPU | 73.0% CPU |
| Parallel | 2 | 2.11M pps | 3.9% CPU | 38.5% CPU |
| Parallel | 4 | 3.56M pps | 2.3% CPU | 22.8% CPU |
| Parallel | 8 | 3.00M pps | 2.7% CPU | 27.1% CPU |

#### HTTP (Flow-Based Hash Routing)
| Mode | Workers | Throughput | 1 Gbps | 10 Gbps |
|------|---------|------------|--------|---------|
| Sequential | 1 | 797K pps | 10.2% CPU | 101.9% CPU [OVERLOAD] |
| Parallel | 2 | 1.07M pps | 7.6% CPU | 76.1% CPU |
| Parallel | 4 | 294K pps | 27.6% CPU | 276.0% CPU [OVERLOAD] |
| Parallel | 8 | 328K pps | 24.7% CPU | 247.2% CPU [OVERLOAD] |

**Notes**: 
- **TLS**: Round-robin dispatch (stateless) - scales linearly with more workers
- **TCP**: Hash-based routing (source IP → worker) - maintains per-connection state consistency
- **HTTP**: Flow-based routing (src_ip, dst_ip, src_port, dst_port → worker) - maintains request/response pairs
- TCP shows best performance with 4 workers (3.56M pps, 22.8% CPU @ 10 Gbps)
- HTTP shows best performance with 2 workers (1.07M pps, 76.1% CPU @ 10 Gbps)
- HTTP's complex flow tracking limits parallel scaling beyond 2 workers
- These benchmarks measured on laptop hardware (8 CPU cores)
- **Server-class hardware (32-64+ cores) would show significantly better parallel performance**:
  - TCP could reach 10-20M+ pps with 16-32 workers
  - HTTP could benefit from 4+ workers on systems with 32+ cores
  - TLS could reach 1M+ pps with 16-32 workers
  - Optimal worker count typically 50-75% of available cores
- Current optimal worker counts are specific to 8-core systems

## Key Performance Insights

### Protocol Efficiency Ranking
1. **TCP**: Fastest (1.11M pps sequential, 3.56M pps parallel @ 4 workers) - excellent balance of speed and analysis depth
2. **HTTP**: Fast (797K pps sequential, 1.07M pps parallel @ 2 workers) - comprehensive application-layer analysis with flow tracking
3. **TLS**: Moderate (49.7K pps sequential, 232.9K pps parallel @ 4 workers) - cryptographic complexity

### Parallel Processing Support
- **TCP**: Full parallel support with hash-based worker assignment
  - Best performance at 4 workers (3.56M pps, 22.8% CPU @ 10 Gbps)
  - Parallel mode: 2 workers (2.11M pps), 4 workers (3.56M pps), 8 workers (3.00M pps)
  - Sequential mode: 1.11M pps (73.0% CPU @ 10 Gbps)
  - Hash-based routing maintains per-connection state consistency
  - Same source IP always routes to same worker
  - Each worker has isolated connection tracker and cache
  - Production ready: Handles 10 Gbps easily with parallel mode
  
- **TLS**: Full parallel support with worker pool architecture
  - Best throughput: 232.9K pps with 4 workers (34.9% CPU @ 1 Gbps)
  - Sequential mode: 49.7K pps (163.5% CPU for 1 Gbps)
  - Parallel (2 workers): 200.7K pps (40.5% CPU @ 1 Gbps)
  - Parallel (4 workers): 232.9K pps (34.9% CPU @ 1 Gbps)
  - Uses round-robin dispatch (stateless processing)
  - Performance degrades with 8+ workers (dispatch overhead)
  - 10 Gbps requires further optimization
  
- **HTTP**: Full parallel support with flow-based hash routing
  - Best performance at 2 workers (1.07M pps, 76.1% CPU @ 10 Gbps)
  - Parallel mode: 2 workers (1.07M pps), 4 workers (294K pps), 8 workers (328K pps)
  - Sequential mode: 797K pps (101.9% CPU @ 10 Gbps)
  - Flow-based routing maintains request/response consistency
  - Complex flow tracking limits parallel scaling beyond 2 workers
  - Each worker has isolated flow cache and state
  - Production ready: 2 workers handle 10 Gbps at 76% CPU

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
- **Parallel mode (4 workers)**: 3.56M pps throughput (22.8% CPU for 10 Gbps) - **Recommended**
- **Sequential mode**: 1.11M pps throughput (73.0% CPU for 10 Gbps)
- Disable OS matching when not needed (118% faster)
- Disable link matching when not needed (135% faster)
- Use large cache (10K connections) for high volumes (31% faster)
- Use small cache (100 connections) for better CPU cache locality (21% faster)
- Hash-based routing ensures consistent per-connection state

#### TLS Optimization
- **Sequential Mode**: 49.7K pps throughput (163.5% CPU for 1 Gbps - requires parallel mode)
- **Parallel Mode (4 workers)**: 232.9K pps throughput (34.9% CPU for 1 Gbps) - **Recommended**
- **Parallel Mode (2 workers)**: 200.7K pps throughput (40.5% CPU for 1 Gbps)
- Use `HuginnNetTls::with_config(4, 100)` for optimal throughput
- Performance degrades with 8+ workers due to dispatch overhead
- Pre-filter non-TLS packets for significant gains
- JA4 calculation is front-loaded during processing

#### HTTP Optimization
- **Sequential Mode**: 797K pps throughput (101.9% CPU for 10 Gbps - requires parallel mode)
- **Parallel Mode (2 workers)**: 1.07M pps throughput (76.1% CPU for 10 Gbps) - **Recommended**
- Use `HuginnNetHttp::with_config(2, 100)` for optimal throughput
- Disable browser matching when not needed (reduces overhead)
- Disable server matching when not needed (reduces overhead)
- Use large cache (10K flows) for high volumes
- Complex flow tracking limits scaling beyond 2 workers on 8-core systems

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
- Sequential mode results are single-thread measurements on x86_64 architecture
- TLS parallel mode uses round-robin dispatch (best throughput with 4 workers: 232.9K pps)
- TCP parallel mode uses hash-based worker assignment (best throughput with 4 workers: 3.56M pps)
- TLS, TCP, and HTTP benchmarks use repeated datasets (1000x) for statistical stability
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead

## Contributing

When adding new benchmarks:
1. Follow the existing benchmark structure and naming conventions
2. Include comprehensive performance analysis in protocol-specific READMEs
3. Use real-world PCAP data for accurate performance measurements
4. Document any new optimization techniques or performance insights
5. Include parallel mode benchmarks when applicable