# Huginn-Net Benchmarks

This directory contains comprehensive performance benchmarks for all Huginn-Net protocol libraries. Each benchmark is designed to measure specific aspects of network protocol analysis performance.

## Available Benchmarks

| Protocol | Benchmark File | Library | Command |
|----------|---------------|---------|---------|
| **TLS** | `bench_tls.rs` | `huginn-net-tls` | `cargo bench -p huginn-net-tls` |
| **TCP** | `bench_tcp.rs` | `huginn-net-tcp` | `cargo bench -p huginn-net-tcp` |
| **HTTP** | `bench_http.rs` | `huginn-net-http` | `cargo bench -p huginn-net-http` |

## Performance Summary

### Single-Core Throughput Comparison

| Protocol | Parsing Only | Full Analysis | Use Case |
|----------|-------------|---------------|----------|
| **TCP** | 6.1M packets/sec | 167K packets/sec | OS fingerprinting, MTU detection |
| **TLS** | 316M packets/sec | 72K packets/sec | JA4 fingerprinting, TLS analysis |
| **HTTP** | 23.7M packets/sec | 26K packets/sec | Browser/server detection |

### Processing Time Comparison

| Protocol | Minimal Parsing | Full Analysis | Complexity |
|----------|----------------|---------------|------------|
| **TCP** | 163 ns | 6.4 μs | Medium (OS fingerprinting) |
| **TLS** | 3.2 ns | 11.6 μs | High (JA4 cryptographic) |
| **HTTP** | 42 ns | 37.8 μs | Highest (header analysis) |

## Key Performance Insights

### Protocol Efficiency Ranking
1. **TCP**: Best balance of speed and analysis depth
2. **TLS**: Moderate speed with cryptographic complexity
3. **HTTP**: Comprehensive but slower due to header parsing

### PCAP Effectiveness
- **HTTP**: 12.5% effectiveness (2/16 packets useful)
- **TCP**: 9.3% effectiveness (4/43 packets useful)
- **TLS**: 11% effectiveness (1/9 packets useful)

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
- TLS 1.2 processes 40% faster than ALPN H2
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
- Performance results are single-core measurements on x86_64 architecture

## Contributing

When adding new benchmarks:
1. Follow the existing benchmark structure and naming conventions
2. Include comprehensive performance analysis in protocol-specific READMEs
3. Use real-world PCAP data for accurate performance measurements
4. Document any new optimization techniques or performance insights