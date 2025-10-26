# TCP Benchmark Analysis

This document provides detailed analysis of TCP processing performance using `huginn-net-tcp` library. The benchmarks measure OS fingerprinting, MTU detection, uptime calculation, and overall processing overhead across different configuration scenarios.

## Test Data Overview

The benchmark uses a macOS TCP flags PCAP file containing real TCP traffic:

| PCAP File | Total Packets | TCP Analysis Results | Effectiveness |
|-----------|---------------|---------------------|---------------|
| macos_tcp_flags.pcap | 43 | 44 (1 SYN + 42 SYN-ACK + 1 MTU + 0 Uptime) | 102% |

### Analysis Results Breakdown
- **SYN packets**: 1 (OS fingerprinting source)
- **SYN-ACK packets**: 42 (Server response analysis)
- **MTU detections**: 1 (Maximum Transmission Unit calculation)
- **Uptime calculations**: 0 (No TCP timestamp options or insufficient data for calculation)

## Performance Results

### Core Processing Performance

| Operation | Time (microseconds) | Notes |
|-----------|-------------------|-------|
| Minimal packet parsing | 0.129 | Structure validation only |
| TCP without OS matching | 13.6 | Basic TCP analysis |
| TCP with OS matching | 16.6 | Full p0f-style fingerprinting |
| MTU without link matching | 13.8 | Raw MTU calculation |
| MTU with link matching | 22.3 | MTU + link type detection |
| Uptime with tracking | 15.7 | TCP timestamp-based uptime calculation |
| Full TCP analysis | 21.3 | Complete TCP analysis pipeline |
| Full analysis with collection | 26.4 | Complete result processing |

### Processing Overhead Analysis

| Comparison | Baseline | Target | Overhead | Impact |
|------------|----------|--------|----------|---------|
| Parsing vs Full Analysis | 129 ns | 21.3 μs | 165x | Expected for comprehensive analysis |
| No OS vs OS Matching | 13.6 μs | 16.6 μs | 22% | Database lookup overhead |
| No Link vs Link Matching | 13.8 μs | 22.3 μs | 62% | MTU database matching |
| Analysis vs Collection | 21.3 μs | 26.4 μs | 24% | Result extraction overhead |

### Cache Size Impact Analysis

| Cache Size | Processing Time | Use Case |
|------------|----------------|----------|
| Small (100 connections) | 12.7 μs | Memory-constrained environments |
| Standard (1000 connections) | 15.7 μs | Typical network monitoring |
| Large (10000 connections) | 14.2 μs | High-throughput analysis |

**Finding**: Smaller caches provide better performance due to better CPU cache locality. Standard cache balances memory usage and performance. Large caches are optimal for high connection volumes.

### Throughput Estimates

Based on single-core performance:

| Scenario | Packets/Second | Use Case |
|----------|----------------|----------|
| Minimal parsing only | ~7,750,000 | High-speed packet filtering |
| Basic TCP analysis | ~73,500 | TCP flow analysis |
| Full OS fingerprinting | ~60,200 | Complete security analysis |
| Full TCP analysis | ~46,900 | Complete TCP processing pipeline |
| MTU detection | ~44,800 | Network infrastructure analysis |

## Benchmark Categories

### 1. OS Fingerprinting Performance
- **tcp_with_os_matching**: Complete p0f-style OS detection with database matching
- **tcp_without_os_matching**: TCP analysis without OS signature matching
- **tcp_packet_parsing**: Basic packet structure validation

### 2. MTU Detection Analysis
- **mtu_with_link_matching**: MTU calculation with link type identification
- **mtu_without_link_matching**: Raw MTU calculation only

### 3. Uptime Calculation Performance
- **uptime_with_tracking**: TCP timestamp-based uptime calculation with connection tracking
- **uptime_small_cache**: Performance with limited connection cache (100 entries)
- **uptime_large_cache**: Performance with extended connection cache (10,000 entries)

### 4. Processing Overhead Comparison
- **minimal_processing**: Basic packet parsing and validation
- **full_tcp_analysis**: Complete TCP analysis with all features enabled
- **full_analysis_with_collection**: Full analysis with result collection and processing

## Key Findings

### Performance Characteristics

1. **Efficient Filtering**: Basic TCP packet validation takes only ~129 nanoseconds
2. **Reasonable Analysis Cost**: Complete TCP analysis requires 13-27 microseconds per packet
3. **Database Overhead**: OS matching adds ~22% processing time
4. **MTU Matching Cost**: MTU database matching adds ~62% overhead
5. **Cache Efficiency**: Smaller caches (100 connections) perform 19% faster than standard (1000 connections) due to better CPU cache locality

### Scalability Insights

1. **High-Throughput Capability**: Can process 60,000+ packets/second with full OS fingerprinting
2. **Memory vs Performance Trade-off**: Smaller caches offer better CPU cache locality
3. **Selective Analysis**: Significant performance gains when disabling unused features
4. **Connection Tracking**: TTL-based cache expiration (30 seconds) balances memory and accuracy


## How to Reproduce

1. Ensure PCAP file is present in the `pcap/` directory:
   - `macos_tcp_flags.pcap`

2. Run the TCP-specific benchmark:
```bash
cargo bench --bench bench_tcp
```

## Interpretation Guidelines

### For Network Security Applications
- The library provides excellent performance for real-time TCP fingerprinting
- OS detection latency (16.6μs) is suitable for network monitoring
- Packet filtering efficiency (129ns) enables processing of very high-volume traffic
- Complete TCP analysis (21.3μs) balances depth and speed

### For Performance Optimization
- Disable OS matching when not needed (18% performance gain)
- Use smaller cache sizes (100 connections) for better CPU cache locality (19% faster)
- Consider selective feature enabling for maximum throughput
- MTU database matching has significant overhead (62%) - use only when needed

### For Infrastructure Monitoring
- MTU detection adds moderate overhead (~8.5μs) for valuable network insights
- Uptime calculation provides useful forensic information (15.7μs per tracked connection)
- Connection tracking uses 30-second TTL for optimal memory management
- Client/Server uptime separation provides detailed host analysis

### For Capacity Planning
- Single-core throughput: 60,000+ TCP packets per second (full OS fingerprinting)
- Basic analysis throughput: 73,500+ packets per second
- Memory usage: Scales with connection cache size (100-10,000 connections)
- CPU utilization: Primarily bound by database lookups and connection tracking
- Cache sizing: Smaller caches (100) offer best CPU cache locality

## Technical Notes

- Benchmarks run in release mode with full compiler optimizations
- Results measured using Criterion.rs with statistical analysis
- Outliers (1-17% of measurements) indicate consistent performance patterns
- All timing measurements include complete TCP analysis pipeline
- PCAP effectiveness varies based on TCP handshake and option presence
- Connection cache uses 30-second TTL-based expiration for memory management
- Database matching uses optimized lookup structures for performance
- Uptime detection implements p0f-conformant algorithm with client/server separation
- FrequencyState enum provides type-safe frequency tracking without performance overhead

## TCP Performance Summary

| Operation Type | Processing Time | Throughput (packets/sec) | Use Case |
|---------------|----------------|-------------------------|----------|
| Packet parsing | 129 ns | ~7,750,000 | High-speed filtering |
| Basic TCP analysis | 13.6 μs | ~73,500 | Flow monitoring |
| OS fingerprinting | 16.6 μs | ~60,200 | Security analysis |
| Full TCP analysis | 21.3 μs | ~46,900 | Complete processing |
| MTU detection | 22.3 μs | ~44,800 | Network diagnostics |
| Uptime tracking | 15.7 μs | ~63,700 | Host uptime analysis |

TCP analysis provides balanced performance between parsing efficiency and analysis depth, making it well-suited for real-time network security applications requiring OS detection, network infrastructure monitoring, and host uptime tracking. The implementation includes p0f-conformant uptime detection with separate client/server tracking and 30-second TTL-based connection cache management.
