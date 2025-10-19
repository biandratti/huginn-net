# TCP Benchmark Analysis

This document provides detailed analysis of TCP processing performance using `huginn-net-tcp` library. The benchmarks measure OS fingerprinting, MTU detection, uptime calculation, and overall processing overhead across different configuration scenarios.

## Test Data Overview

The benchmark uses a macOS TCP flags PCAP file containing real TCP traffic:

| PCAP File | Total Packets | TCP Analysis Results | Effectiveness |
|-----------|---------------|---------------------|---------------|
| macos_tcp_flags.pcap | 43 | 4 (1 SYN + 1 SYN-ACK + 1 MTU + 1 Uptime) | 9.3% |

### Analysis Results Breakdown
- **SYN packets**: 1 (OS fingerprinting source)
- **SYN-ACK packets**: 1 (Server response analysis)
- **MTU detections**: 1 (Maximum Transmission Unit calculation)
- **Uptime calculations**: 1 (TCP timestamp-based uptime estimation)

## Performance Results

### Core Processing Performance

| Operation | Time (microseconds) | Notes |
|-----------|-------------------|-------|
| Minimal packet parsing | 0.127 | Structure validation only |
| TCP without OS matching | 5.0 | Basic TCP analysis |
| TCP with OS matching | 6.0 | Full p0f-style fingerprinting |
| MTU without link matching | 5.0 | Raw MTU calculation |
| MTU with link matching | 6.1 | MTU + link type detection |
| Full analysis with collection | 7.0 | Complete result processing |

### Processing Overhead Analysis

| Comparison | Baseline | Target | Overhead | Impact |
|------------|----------|--------|----------|---------|
| Parsing vs Full Analysis | 127 ns | 6.2 μs | 49x | Expected for comprehensive analysis |
| No OS vs OS Matching | 5.0 μs | 6.0 μs | 20% | Database lookup overhead |
| No Link vs Link Matching | 5.0 μs | 6.1 μs | 22% | MTU database matching |
| Analysis vs Collection | 6.2 μs | 7.0 μs | 13% | Result extraction overhead |

### Cache Size Impact Analysis

| Cache Size | Processing Time | Use Case |
|------------|----------------|----------|
| Small (100 connections) | 5.3 μs | Memory-constrained environments |
| Standard (1000 connections) | 5.1 μs | Typical network monitoring |
| Large (10000 connections) | 4.9 μs | High-throughput analysis |

**Finding**: Larger caches provide better performance due to reduced cache misses during connection tracking.

### Throughput Estimates

Based on single-core performance:

| Scenario | Packets/Second | Use Case |
|----------|----------------|----------|
| Minimal parsing only | ~7,800,000 | High-speed packet filtering |
| Basic TCP analysis | ~200,000 | TCP flow analysis |
| Full OS fingerprinting | ~167,000 | Complete security analysis |
| MTU detection | ~164,000 | Network infrastructure analysis |

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

1. **Efficient Filtering**: Basic TCP packet validation takes only ~127 nanoseconds
2. **Reasonable Analysis Cost**: Complete TCP analysis requires 5-7 microseconds per packet
3. **Database Overhead**: OS and MTU matching adds ~20-22% processing time
4. **Cache Efficiency**: Larger connection caches improve performance by ~8%

### Scalability Insights

1. **High-Throughput Capability**: Can process 167,000+ packets/second with full analysis
2. **Memory vs Performance Trade-off**: Larger caches provide better performance
3. **Selective Analysis**: Significant performance gains when disabling unused features


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
- OS detection latency (6μs) is suitable for high-speed network monitoring
- Packet filtering efficiency (127ns) enables processing of very high-volume traffic

### For Performance Optimization
- Disable OS matching when not needed (20% performance gain)
- Use appropriate cache sizes based on expected connection volume
- Consider selective feature enabling for maximum throughput

### For Infrastructure Monitoring
- MTU detection adds minimal overhead (~1μs) for valuable network insights
- Uptime calculation provides useful forensic information with negligible cost
- Connection tracking scales well with proper cache sizing

### For Capacity Planning
- Single-core throughput: 167,000+ TCP packets per second (full OS fingerprinting)
- Basic analysis throughput: 200,000+ packets per second
- Memory usage: Scales with connection cache size (100-10,000 connections)
- CPU utilization: Primarily bound by database lookups and connection tracking

## Technical Notes

- Benchmarks run in release mode with full compiler optimizations
- Results measured using Criterion.rs with statistical analysis
- Outliers (3-17% of measurements) indicate consistent performance patterns
- All timing measurements include complete TCP analysis pipeline
- PCAP effectiveness varies based on TCP handshake and option presence
- Connection cache uses TTL-based expiration for memory management
- Database matching uses optimized lookup structures for performance

## TCP Performance Summary

| Operation Type | Processing Time | Throughput (packets/sec) | Use Case |
|---------------|----------------|-------------------------|----------|
| Packet parsing | 127 ns | ~7,800,000 | High-speed filtering |
| Basic TCP analysis | 5.0 μs | ~200,000 | Flow monitoring |
| OS fingerprinting | 6.0 μs | ~167,000 | Security analysis |
| MTU detection | 6.1 μs | ~164,000 | Network diagnostics |

TCP analysis provides balanced performance between parsing efficiency and analysis depth, making it well-suited for real-time network security applications requiring OS detection and network infrastructure monitoring.
