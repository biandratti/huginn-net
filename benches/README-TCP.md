# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

> **Numbers source**: Criterion.rs medians across 5 runs of `bench_tcp` (per-run throughput = run total ÷ 43,000 packets). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations with no warmup and can diverge from Criterion; only Criterion output is authoritative.

## Test Data

PCAP dataset: `macos_tcp_flags.pcap` repeated 1000x for statistical stability.

| Metric | Value |
|--------|-------|
| Total packets per iteration | 43,000 (43 original × 1,000) |
| SYN packets | 1,000 |
| SYN-ACK packets | 42,000 |
| MTU detections | 1,000 |
| Uptime calculations | 0 (no TCP timestamp options in this PCAP) |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| Packet Parsing | ~10 ns | ~99M pps | Ethernet/IP/TCP header parsing |
| Full TCP Analysis | ~1.06 µs | ~942K pps | Complete flow processing |
| With OS Matching | ~1.07 µs | ~930K pps | p0f SYN/SYN-ACK database lookup |
| Without OS Matching | ~556 ns | ~1.80M pps | Skip OS database |
| With MTU Matching | ~1.06 µs | ~942K pps | MTU-to-link-type database lookup |
| Without MTU Matching | ~561 ns | ~1.78M pps | Skip link-type lookup |

> Numbers are medians across 5 Criterion sessions. Per-run variance is typically ±5–10%; outlier runs are filtered out by taking the median.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | ~556 ns (1.80M pps) | ~1.07 µs (930K pps) | ~93% | p0f database lookup per SYN/SYN-ACK |
| MTU/Link Matching | ~561 ns (1.78M pps) | ~1.06 µs (942K pps) | ~89% | MTU database scan |

### Uptime Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~547 ns | ~1.83M pps | Sufficient for this PCAP (0 uptime hits) |
| Large (10K) | ~544 ns | ~1.84M pps | Better under real uptime tracking load |

**Note**: This PCAP has 0 uptime calculations (no TCP timestamp options), so cache size differences are minimal here. Expect a larger gap in real traffic with uptime-bearing flows.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~1.06 µs | ~942K pps | 1.00x | ~8.6% ✓ | ~86% ✓ |
| 2 | ~478 ns | ~2.09M pps | 2.22x | ~3.9% ✓ | ~39% ✓ |
| 4 | ~476 ns | ~2.10M pps | 2.23x | ~3.9% ✓ | ~39% ✓ |
| 8 | ~484 ns | ~2.06M pps | 2.19x | ~3.9% ✓ | ~39% ✓ |

**Key Insight**: 2 and 4 workers achieve identical throughput (~2.1M pps). Adding more workers does not help on 8-core hardware — parallel benchmarks include worker pool creation/dispatch/shutdown overhead per iteration, which sets the floor at ~20 ms for this 43K-packet workload regardless of worker count.

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better than this 8-core laptop; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~8.6% ✓ | ~3.9% ✓ | ~3.9% ✓ | ~3.9% ✓ |
| 10 Gbps (812,740 pps) | ~86% ✓ | ~39% ✓ | ~39% ✓ | ~39% ✓ |

**TCP projects to handle 10 Gbps in all modes.** Sequential extrapolates to ~86% CPU (tight but not overloading a single core); parallel projects to ~39%. For 10 Gbps environments, parallel mode (2–4 workers) is the recommended baseline pending real-load validation.

## Key Findings

### Performance Characteristics

1. **Fast sequential**: ~942K pps full analysis — 10 Gbps projects to ~86% CPU on a single core
2. **OS matching overhead**: ~93% over base — the p0f database lookup is the dominant cost per SYN/SYN-ACK
3. **MTU matching overhead**: ~89% — comparable to OS matching, scans MTU-to-link-type table
4. **Parallel scaling**: 2 workers provide ~2.22× throughput improvement over sequential (2.09M vs 942K pps); 4 workers marginally better, 8 workers slightly worse
5. **Production ready**: Sequential projects to ~86% CPU at 10 Gbps; parallel projects to ~39%

### Architectural Insights

TCP processing uses hash-based worker assignment: the same TCP flow always routes to the same worker, required for stateful SYN/SYN-ACK correlation. Each worker maintains its own `TtlCache<ConnectionKey, …>` for connection state.

Parallel scaling plateaus at 2 workers (~2.1M pps) because the workload is bound by per-packet work (OS/MTU matching DB lookups) rather than dispatch parallelism. The hash-based routing is essential for correctness but creates uneven load distribution at higher worker counts.

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh tcp 5
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

---

*Hardware: x86_64, 8-core laptop. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
