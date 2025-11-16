# HTTP Benchmark Analysis

Performance benchmarks for `huginn-net-http` library measuring browser detection, web server identification, and HTTP protocol analysis.

## Test Data

The benchmark uses `http-simple-get.pcap` repeated 1000x for statistical stability:

| Metric | Value |
|--------|-------|
| Total packets | 16,000 (16 original × 1000) |
| HTTP requests | 500 |
| HTTP responses | 500 |
| Browser detections | 500 (100% success rate) |
| Server detections | 500 (100% success rate) |
| HTTP/1.x requests | 500 |
| HTTP/2 requests | 0 |
| Effectiveness | 6.2% |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| Packet Parsing | 7 ns | 142.9M pps | Structure validation |
| Full HTTP Analysis | 1.899 µs | 526.6K pps | Complete processing |
| With Browser Matching | 2.386 µs | 419.1K pps | User-Agent lookup |
| Without Browser Matching | 1.654 µs | 604.6K pps | Skip User-Agent |
| Overhead Analysis | - | 268x | Parsing → Full analysis |

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| Browser Matching | 1.654 µs (604.6K pps) | 2.386 µs (419.1K pps) | 44.3% | Database lookup |
| Server Matching | 1.590 µs (628.9K pps) | 2.065 µs (484.3K pps) | 29.9% | Server database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 1.429 µs | 699.8K pps | Memory-constrained |
| Large (10K) | 1.384 µs | 722.5K pps | High flow volumes |

**Note**: Larger cache provides +3.2% throughput improvement for high-volume scenarios.

### Parallel Mode (Multi-Worker)

**Configuration**: `batch_size=16`, `timeout_ms=10`, `queue_size=100`

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|---------|------------|-------------|-------|
| 1 (seq) | 526.6K pps | 1.00x | 15.4% | 154.3% [OVERLOAD] | Baseline |
| 2 | 1.54M pps | 2.93x | 5.3% | 52.7% | **Optimal** |
| 4 | 1.38M pps | 2.62x | 5.9% | 59.0% | Diminishing returns |
| 8 | 1.40M pps | 2.66x | 5.8% | 57.9% | Overhead limits scaling |

**Key Insight**: HTTP's complex flow tracking (per-connection state) limits parallel efficiency compared to stateless protocols. Best throughput with 2 workers due to:
- Flow-based hashing concentrates related packets to same worker
- Cache locality benefits from keeping flows together
- Lower inter-worker contention with fewer workers

### Network Capacity

| Scenario | Sequential (1 thread) | 2 Workers | 4 Workers | 8 Workers |
|----------|---------------------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | 15.4% CPU | 5.3% CPU ✓ | 5.9% CPU ✓ | 5.8% CPU ✓ |
| 10 Gbps (812,740 pps) | 154.3% [OVERLOAD] | 52.7% CPU ✓ | 59.0% CPU ✓ | 57.9% CPU ✓ |

**Recommendation**: Use 2 workers for optimal efficiency. Additional workers provide marginal benefit on 8-core systems due to flow tracking overhead.

## Key Findings

### Performance Characteristics

1. **Fast Detection**: HTTP packet validation in 7 nanoseconds
2. **Flow Processing**: Complete analysis in 1.899 microseconds per packet (sequential)
3. **High Overhead**: 268x from parsing to full processing (expected for stateful flow tracking)
4. **Parallel Efficiency**: 2.93x speedup with 2 workers (best configuration)
5. **Scaling Limit**: 4-8 workers show diminishing returns due to flow-based hashing overhead

### Optimization Impact

| Optimization | Performance Impact | Notes |
|--------------|-------------------|-------|
| **Parallel mode (2 workers)** | 1.54M pps (52.7% CPU @ 10 Gbps) | **Recommended** |
| Sequential mode | 526.6K pps (154.3% CPU @ 10 Gbps) | Overload |
| Disable browser matching | -44.3% overhead | Skip User-Agent lookup |
| Disable server matching | -29.9% overhead | Skip server lookup |
| Large cache (10K) | +3.2% throughput | Better for high volumes |

### Architectural Insights

HTTP processing differs from TLS/TCP due to:
- **Stateful flow tracking**: Maintains per-connection TCP flow state
- **Request/response correlation**: Pairs HTTP requests with responses
- **Flow-based hashing**: Routes packets by 4-tuple (src_ip, dst_ip, src_port, dst_port)
- **Cache-heavy workload**: TtlCache lookups for every packet

This architecture limits parallel scaling compared to stateless protocols but ensures correct HTTP session reconstruction.

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would likely remain 2-4 workers due to flow-based hashing concentrating work. Unlike CPU-bound workloads, HTTP's I/O and cache patterns benefit from fewer, busier workers.

## Running Benchmarks

```bash
cargo bench --bench bench_http
```

The benchmark processes 16,000 packets (16 original repeated 1000x) and reports:
- Browser and server detection performance
- Protocol analysis capabilities
- Cache size impact
- Parallel scaling characteristics
- Network capacity planning

## Technical Notes

- Benchmarks run in release mode with full optimizations
- Results measured using Criterion.rs with statistical analysis
- Dataset repeated 1000x for statistical stability
- Measurements on x86_64 architecture (8-core system)
- Flow cache uses TTL-based expiration
- Database matching uses optimized lookup structures
- Supports HTTP/1.x and HTTP/2 protocols
- Worker pool uses crossbeam channels for lock-free dispatch
- Batch processing reduces per-packet overhead
