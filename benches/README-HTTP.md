# HTTP Benchmark Analysis

Performance benchmarks for `huginn-net-http` library measuring browser detection, web server identification, and HTTP protocol analysis.

> **Numbers source**: Criterion.rs medians (runs ÷ 16,000 packets). The inline report printed at the end of each bench run uses `measure_average_time` with 3–10 iterations and no warmup — those numbers can be 1.5–2x off from Criterion and should be ignored. Only Criterion output is authoritative.

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
| Effectiveness | 6.2% (only HTTP packets matter) |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| Packet Parsing | ~4 ns | ~250M pps | Ethernet/IP/TCP header parsing |
| Full HTTP Analysis | ~0.95 µs | ~1.05M pps | Complete flow processing |
| With Browser Matching | ~0.73 µs | ~1.37M pps | Matcher short-circuits flow on early hit |
| Without Browser Matching | ~0.85 µs | ~1.18M pps | All packets processed to completion |
| With Server Matching | ~0.99 µs | ~1.01M pps | Response header lookup |
| Without Server Matching | ~0.86 µs | ~1.16M pps | Skip server header lookup |

> **Browser matching is faster than no matching** — the `HttpSignatureMatcher` identifies the browser early and can short-circuit remaining header processing. Server matching adds overhead because responses require full header scanning before the server label is known.

### Feature-Specific Performance

| Feature | Without | With | Delta | Notes |
|---------|---------|------|-------|-------|
| Browser Matching | ~0.85 µs (1.18M pps) | ~0.73 µs (1.37M pps) | −14% | Early exit on UA match |
| Server Matching | ~0.86 µs (1.16M pps) | ~0.99 µs (1.01M pps) | +15% | Full response scan required |

### Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~0.85 µs | ~1.18M pps | Frequent evictions under load |
| Large (10K) | ~0.83 µs | ~1.20M pps | Better flow retention |

**Note**: Cache size difference is ~2% — negligible for most deployments. Use large cache only when expecting sustained high-volume flows.

### Parallel Mode (Multi-Worker)

**Configuration**: `batch_size=16`, `timeout_ms=10`, `queue_size=100`

| Workers | Time/Packet | Throughput | Speedup vs sequential | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|-----------------------|------------|-------------|
| 1 (seq) | ~0.95 µs | ~1.05M pps | 1.00x | 7.7% | 77.4% [near limit] |
| 2 | ~0.65 µs | ~1.54M pps | 1.46x | 5.3% | 52.7% ✓ |
| 4 | ~0.67 µs | ~1.49M pps | 1.42x | 5.5% | 54.6% ✓ |
| 8 | ~0.77–0.81 µs | ~1.23–1.29M pps | ~1.2x | 6.3% | ~63% ✓ |

**Key Insight**: 2 workers is the sweet spot. Sequential already handles 10 Gbps at ~77% CPU (feasible with headroom); 2 workers drops that to 53%, comfortable for production. 8 workers shows higher variance and diminishing returns due to flow-based hashing concentrating traffic.

### Network Capacity

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | 7.7% ✓ | 5.3% ✓ | 5.5% ✓ | 6.3% ✓ |
| 10 Gbps (812,740 pps) | 77.4% ✓ | 52.7% ✓ | 54.6% ✓ | ~63% ✓ |

**Unlike TLS, HTTP sequential mode can sustain 10 Gbps on a single core** (~77% CPU with headroom).

## Key Findings

### Performance Characteristics

1. **Fast Parsing**: HTTP packet structure validation in ~4 nanoseconds
2. **Flow Processing**: Complete analysis in ~0.95 µs per packet (sequential)
3. **Browser Matching Benefit**: Matcher short-circuits processing — ~14% faster with matching than without
4. **Parallel Efficiency**: 2 workers provides 1.46x speedup; beyond 2 workers shows diminishing returns
5. **10 Gbps feasible**: Both sequential (~77% CPU) and parallel 2w (~53% CPU) handle 10 Gbps line rate

### Architectural Insights

HTTP processing relies on stateful flow tracking (per-connection `TtlCache`) and flow-based hashing that routes same-connection packets to the same worker, required for correct HTTP request/response pairing.

This limits parallel scaling compared to stateless protocols (parallel adds only ~1.5x vs ~2x for stateless), but sequential performance is strong enough that 2 workers comfortably handles 10 Gbps.

## Running Benchmarks

```bash
cargo bench --bench bench_http
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead).

## Technical Notes

- Benchmarks run in release mode with full optimizations (Criterion.rs, 100 samples)
- Dataset repeated 1000x for stability; per-packet numbers = criterion median ÷ 16,000
- Each `b.iter()` closure reconstructs `HttpSignatureMatcher` and `HttpProcessors` — includes one-time setup overhead per iteration, slightly inflating sequential numbers vs real-world sustained throughput
- Flow cache uses TTL-based expiration (`TtlCache`)
- Worker pool uses crossbeam channels with hash-based flow dispatch
- HTTP/1.x fully supported; HTTP/2 present in dataset at 0% (no H2 packets in this PCAP)
- Results measured on x86_64, 8-core laptop
