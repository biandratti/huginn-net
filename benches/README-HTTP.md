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
| Packet Parsing | 5 ns | 200M pps | Structure validation |
| Full HTTP Analysis | 1.254 µs | 797K pps | Complete processing |
| Overhead Analysis | - | 242x | Parsing → Full analysis |

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| Browser Matching | 1.005 µs (995K pps) | 1.263 µs (791K pps) | 25.6% | Database lookup |
| Server Matching | 1.046 µs (956K pps) | 1.263 µs (791K pps) | 20.7% | Server database |

### Cache Size Impact

| Cache Size | Time | Throughput | Best For |
|------------|------|------------|----------|
| Small (100) | 1.033 µs | 968K pps | Memory-constrained |
| Large (10K) | 1.019 µs | 981K pps | High flow volumes |

### Parallel Mode (Multi-Worker)

| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|------------|------------|-------------|-------|
| 2 | 1.07M pps | 7.6% | 76.1% | Optimal configuration |
| 4 | 294.5K pps | 27.6% | 276.0% | Overhead exceeds benefit |
| 8 | 328.7K pps | 24.7% | 247.2% | Overhead exceeds benefit |

**Note**: Parallel benchmarks include worker pool overhead and flow-based hashing. HTTP processing is heavier than TCP due to complex flow tracking and state management. Only 2 workers provide improvement over sequential mode on 8-core systems.

### Network Capacity

| Scenario | Sequential (1 thread) | 2 Workers | Status |
|----------|---------------------|-----------|--------|
| 1 Gbps (81,274 pps) | 10.2% CPU | 7.6% CPU | Sufficient |
| 10 Gbps (812,740 pps) | 101.9% CPU [OVERLOAD] | 76.1% CPU | Sufficient |

## Key Findings

### Performance Characteristics

1. **Fast Detection**: HTTP packet validation in 5 nanoseconds
2. **Flow Processing**: Complete analysis in 1.254 microseconds per packet (sequential)
3. **High Overhead**: 242x from parsing to full processing (expected for flow tracking)
4. **Optimal Workers**: Best throughput with 2 workers (1.07M pps, 76.1% CPU @ 10 Gbps)
5. **Scaling Behavior**: Performance degrades with 4+ workers due to flow tracking overhead

### Optimization Insights

| Optimization | Performance Impact | Notes |
|--------------|-------------------|-------|
| **Parallel mode (2 workers)** | 1.07M pps (76% CPU @ 10 Gbps) | **Recommended** |
| Sequential mode | 797K pps (102% CPU @ 10 Gbps) | Overload |
| Disable browser matching | -25.6% overhead | Skip User-Agent lookup |
| Disable server matching | -20.7% overhead | Skip server lookup |
| Use large cache (10K) | +1.3% throughput | Better for high volumes |

**Scaling on larger systems**: On server hardware with 32-64+ cores, optimal worker count would be higher (4-8 workers), though HTTP's complex flow tracking limits parallel efficiency compared to TCP or TLS. The 2-worker optimum is specific to 8-core systems.

## Running Benchmarks

```bash
cargo bench --bench bench_http
```

The benchmark processes 16,000 packets (16 original repeated 1000x) and reports:
- Browser and server detection performance
- Protocol analysis capabilities
- Cache size impact
- Network capacity planning

## Technical Notes

- Benchmarks run in release mode with full optimizations
- Results measured using Criterion.rs with statistical analysis
- Dataset repeated 1000x for statistical stability
- Single-thread measurements on x86_64 architecture
- Flow cache uses TTL-based expiration
- Database matching uses optimized lookup structures
- Supports HTTP/1.x and HTTP/2 protocols
