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

### Sequential Mode (Single-Core)

| Operation | Time/Packet | Throughput | Use Case |
|-----------|-------------|------------|----------|
| Minimal parsing | 7 ns | 142.86M pps | High-speed filtering |
| Packet parsing | 5 ns | 200M pps | Structure validation |
| Large cache (10K) | 979 ns | 1.02M pps | High-volume analysis |
| Small cache (100) | 1.055 µs | 947.9k pps | Memory-constrained |
| Header analysis | 1.191 µs | 839.6k pps | Protocol examination |
| Without matching | 1.389 µs | 719.9k pps | Basic HTTP analysis |
| Protocol detection | 1.531 µs | 653.2k pps | Version identification |
| Full analysis | 1.779 µs | 562.1k pps | Complete processing |
| Server without matching | 1.205 µs | 829.9k pps | Basic server analysis |
| Server with matching | 1.812 µs | 551.9k pps | Server identification |
| Browser matching | 2.029 µs | 492.9k pps | Browser fingerprinting |

### Feature-Specific Performance

| Feature | Time/Packet | Throughput | Performance Gain |
|---------|-------------|------------|------------------|
| Without browser matching | 1.389 µs | 719.9k pps | +46% faster |
| Without server matching | 1.205 µs | 829.9k pps | +48% faster |
| Header analysis only | 1.191 µs | 839.6k pps | +49% faster |
| Large cache vs small | 979 ns vs 1.055 µs | 1.02M vs 947.9k | +8% faster |

### Network Capacity

| Scenario | Sequential (1 core) | Status |
|----------|--------------------|--------------------|
| 1 Gbps (81,274 pps) | 14.5% CPU | Sufficient |
| 10 Gbps (812,740 pps) | 144.6% CPU | Overload |

## Key Findings

### Performance Characteristics

1. **Very Fast Detection**: Packet parsing at 200M pps (5 ns/packet)
2. **Efficient Analysis**: Full HTTP analysis at 562k pps (1.779 µs/packet)
3. **Browser Matching Cost**: Adds 46% overhead (719.9k → 492.9k pps)
4. **Server Matching Cost**: Adds 48% overhead when disabled
5. **Cache Impact**: Large cache provides 8% improvement over small cache

### Optimization Insights

| Optimization | Performance Gain | Notes |
|--------------|------------------|-------|
| Disable browser matching | +46% faster | Skip User-Agent database lookup |
| Disable server matching | +48% faster | Skip server database lookup |
| Use large cache (10K) | +8% faster | Better for high volumes |
| Header analysis only | +49% faster | Skip database matching |

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
- Single-core measurements on x86_64 architecture
- Flow cache uses TTL-based expiration
- Database matching uses optimized lookup structures
- Supports HTTP/1.x and HTTP/2 protocols
