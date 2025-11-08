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
| Full TCP Analysis | 898 ns | 1.11M pps | Complete processing |
| Overhead Analysis | - | 135x | Parsing → Full analysis |

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|-------------|------------|------------|-------------|-------|
| 2 | 474 ns | 2.11M pps | 3.9% | 38.5% | Good performance |
| 4 | 281 ns | 3.56M pps | 2.3% | 22.8% | **Best throughput** |
| 8 | 333 ns | 3.00M pps | 2.7% | 27.1% | Good scaling |

**Worker Architecture**: Hash-based worker assignment (packets from same source IP route to same worker)
**Note**: Maintains per-connection state consistency. Benchmarks include worker pool overhead. Tested on 8-core system.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | 405 ns (2.47M pps) | 883 ns (1.13M pps) | 118% | Database lookup |
| Link Matching | 409 ns (2.44M pps) | 963 ns (1.04M pps) | 135% | MTU database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 446 ns | 2.24M pps | Memory-constrained |
| Standard (1000) | 566 ns | 1.77M pps | Typical usage |
| Large (10000) | 391 ns | 2.56M pps | High connection volumes |

### Network Capacity

| Scenario | Sequential (1 worker) | Parallel (4 workers) | Parallel (8 workers) |
|----------|-----------------------|----------------------|----------------------|
| 1 Gbps (81,274 pps) | 7.3% CPU [OK] | 2.3% CPU [OK] | 2.7% CPU [OK] |
| 10 Gbps (812,740 pps) | 73.0% CPU [OK] | 22.8% CPU [OK] | 27.1% CPU [OK] |

**Note**: Tested on 8-core system. TCP easily handles 10 Gbps with parallel mode (4 workers optimal). Hash-based routing ensures state consistency.

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would be higher (16-32 workers), potentially reaching 10-20M+ pps. The 4-worker optimum is specific to 8-core systems where 8 workers already saturate the hardware.

## Key Findings

### Performance Characteristics

1. **Very Fast Parsing**: TCP packet validation in 6 nanoseconds
2. **High Throughput**: 1.11M pps sequential, 3.56M pps with 4 workers
3. **Moderate Overhead**: 135x from parsing to full analysis
4. **Excellent Parallel Scaling**: 4 workers achieve 3.56M pps (22.8% CPU for 10 Gbps)
5. **Hash-Based Routing**: Maintains per-connection state consistency
6. **Production Ready**: Easily handles 10 Gbps workloads with parallel mode

### Optimization Insights

| Optimization | Performance Gain | Notes |
|--------------|------------------|-------|
| Disable OS matching | 118% faster | Skip database lookup |
| Disable link matching | 135% faster | Skip MTU database |
| Use large cache (10K) | 31% faster | Better for high volumes |
| Use small cache (100) | 21% faster | Better CPU cache locality |
| Use parallel mode (4 workers) | 3.56M pps throughput | Best for high-throughput |

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

The benchmark automatically generates a comprehensive report including:
- Sequential mode throughput
- Parallel mode performance (2, 4, and 8 workers)
- Capacity planning for 1 Gbps and 10 Gbps networks
- Feature-specific performance analysis (OS matching, MTU detection)
- Cache size impact analysis
- Absolute throughput metrics per configuration

## Technical Notes

- Benchmarks use release mode with full compiler optimizations
- Dataset repeated 1000x for statistical stability (43,000 packets)
- Measured using Criterion.rs with statistical analysis
- Connection cache uses 30-second TTL-based expiration
- Database matching uses optimized p0f-compatible lookup structures
- Parallel mode uses hash-based worker assignment (same source IP → same worker)
- Parallel benchmarks include worker pool creation/dispatch/shutdown overhead
- Testing environment: Standard laptop (non-server hardware)
- Results measured on x86_64 architecture
