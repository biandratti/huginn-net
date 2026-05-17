# HTTP Benchmark Analysis

Performance benchmarks for `huginn-net-http` library measuring browser detection, web server identification, and HTTP protocol analysis.

> **Numbers source**: Criterion.rs medians across 5 runs of `bench_http` (per-run throughput = run total ÷ 16,000 packets). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations with no warmup and can drift 10–50% from Criterion; only Criterion output is authoritative.

## Test Data

PCAP dataset: `http-simple-get.pcap` repeated 1000x for statistical stability.

| Metric | Value |
|--------|-------|
| Total packets per iteration | 16,000 (16 original × 1,000) |
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
| Full HTTP Analysis | ~1.39 µs | ~720K pps | Complete flow processing (request + response + matching) |
| With Browser Matching | ~1.42 µs | ~700K pps | UA → browser DB lookup |
| Without Browser Matching | ~1.10 µs | ~910K pps | Skip UA lookup |
| With Server Matching | ~1.48 µs | ~680K pps | Server header → server DB lookup |
| Without Server Matching | ~1.10 µs | ~915K pps | Skip server lookup |

> **Matching adds cost** — both browser and server matching require a DB lookup that runs on every successful detection. Disabling matching gives ~30% headroom for use cases that only need flow tracking / header capture without OS/UA fingerprinting.

### Feature-Specific Performance

| Feature | Without | With | Delta | Notes |
|---------|---------|------|-------|-------|
| Browser Matching | ~1.10 µs (910K pps) | ~1.42 µs (700K pps) | +29% | UA → browser DB lookup |
| Server Matching | ~1.10 µs (915K pps) | ~1.48 µs (680K pps) | +35% | Response header scan + DB lookup |
| Protocol Detection | — | ~1.17 µs (854K pps) | — | Fast-reject heuristic + parser dispatch |
| Header Analysis | — | ~1.10 µs (909K pps) | — | Per-packet header extraction |

### Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~1.07 µs | ~935K pps | Frequent evictions under load |
| Large (10K) | ~1.07 µs | ~936K pps | Better flow retention |

**Note**: Cache size difference is negligible (<1%) for this workload. The PCAP keeps few concurrent flows, so the 100-slot cache rarely evicts.

### Parallel Mode (Multi-Worker)

**Configuration**: `batch_size=16`, `timeout_ms=10`, `queue_size=100`

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~1.39 µs | ~720K pps | 1.00x | ~11.3% ✓ | ~113% **[OVERLOAD]** |
| 2 | ~647 ns | ~1.55M pps | 2.15x | ~5.3% ✓ | ~52.6% ✓ |
| 4 | ~918 ns | ~1.09M pps | 1.51x | ~7.5% ✓ | ~74.8% ✓ |
| 8 | ~1.02 µs | ~982K pps | 1.36x | ~8.3% ✓ | ~82.7% ✓ |

**Key Insight**: 2 workers is the sweet spot and the **projected minimum** for 10 Gbps line rate. Sequential extrapolates to ~113% CPU at 10 Gbps (overload); 2 workers projects to ~53% with comfortable headroom. 4 and 8 workers show diminishing returns due to flow-based hashing concentrating connection traffic on a single worker.

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better than this 8-core laptop; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~11.3% ✓ | ~5.3% ✓ | ~7.5% ✓ | ~8.3% ✓ |
| 10 Gbps (812,740 pps) | ~113% **[OVERLOAD]** | ~52.6% ✓ | ~74.8% ✓ | ~82.7% ✓ |

**1 Gbps projects comfortably across any configuration including sequential**. **10 Gbps projects to require at least 2 workers** — sequential extrapolates above 100% CPU at full analysis on a single core.

## Key Findings

### Performance Characteristics

1. **Fast parsing**: HTTP packet structure validation in ~4 nanoseconds
2. **Flow processing**: Complete analysis in ~1.39 µs per packet (sequential, full analysis with matching)
3. **Matching cost**: Browser/server DB lookups add ~30–35% per packet — disable if not needed
4. **Parallel efficiency**: 2 workers provides 2.15x speedup; beyond 2 workers shows diminishing returns due to flow-based hashing
5. **10 Gbps projects to need 2 workers**: Sequential extrapolates to ~113% CPU at line rate; 2 workers projects to ~53%

### Architectural Insights

HTTP processing relies on stateful flow tracking (per-connection `TtlCache`) and flow-based hashing that routes same-connection packets to the same worker, which is required for correct HTTP request/response pairing.

This limits parallel scaling compared to stateless protocols (parallel adds only ~2.15x vs ~3–4x for stateless), but 2 workers comfortably handles 10 Gbps so this is rarely a practical concern.

## Running Benchmarks

```bash
cargo bench --bench bench_http
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh http 5
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead).

---

*Hardware: x86_64, 8-core laptop. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
