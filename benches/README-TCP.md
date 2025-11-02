# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

## Test Data

PCAP dataset: `macos_tcp_flags.pcap` repeated 1000x for statistical stability (43,000 packets total).

Analysis results:
- **SYN packets**: 1,000 (OS fingerprinting)
- **SYN-ACK packets**: 42,000 (Server response analysis)
- **MTU detections**: 1,000 (Network infrastructure)
- **Uptime calculations**: 0 (No TCP timestamp options)

## Performance Results

### Sequential Mode (Single-Core)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| Packet Parsing | 6 ns | 166.7M pps | Structure validation |
| Full TCP Analysis | 798 ns | 1.25M pps | Complete processing |
| Overhead Analysis | - | 127x | Parsing → Full analysis |

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | 346 ns (2.89M pps) | 582 ns (1.72M pps) | 68% | Database lookup |
| Link Matching | 348 ns (2.87M pps) | 595 ns (1.68M pps) | 71% | MTU database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 408 ns | 2.45M pps | Memory-constrained |
| Standard (1000) | 499 ns | 2.00M pps | Typical usage |
| Large (10000) | 364 ns | 2.75M pps | High connection volumes |

### Network Capacity

| Scenario | Sequential (1 core) | Status |
|----------|--------------------|--------------------|
| 1 Gbps (81,274 pps) | 6.5% CPU | Sufficient |
| 10 Gbps (812,740 pps) | 64.9% CPU | Sufficient |

## Key Findings

### Performance Characteristics

1. **Very Fast Parsing**: TCP packet validation in 6 nanoseconds
2. **High Throughput**: 1.25M packets/second with full analysis
3. **Low Overhead**: 127x from parsing to full analysis (lower than TLS)
4. **Excellent Scaling**: Handles 10 Gbps at 64.9% CPU (single core)

### Optimization Insights

| Optimization | Performance Gain | Notes |
|--------------|------------------|-------|
| Disable OS matching | 68% faster | Skip database lookup |
| Disable link matching | 71% faster | Skip MTU database |
| Use large cache (10K) | 23% faster | Better for high volumes |
| Use small cache (100) | 18% faster | Better CPU cache locality |

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

The benchmark automatically generates a comprehensive report including:
- Sequential mode throughput
- Capacity planning for 1 Gbps and 10 Gbps networks
- Feature-specific performance analysis (OS matching, MTU detection)
- Cache size impact analysis

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability (43,000 packets)
- Measured using Criterion.rs with statistical analysis
- Connection cache uses 30-second TTL-based expiration
- Database matching uses optimized p0f-compatible lookup structures
- Results measured on x86_64 architecture
