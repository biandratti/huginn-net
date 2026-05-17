# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

> **Numbers source**: Criterion.rs medians ÷ 43,000 packets per iteration, taken as the median across 5 bench sessions (`./benches/run_bench.sh tcp`). The inline report printed at the end of each bench run uses `measure_average_time` and can diverge from Criterion — only Criterion output is authoritative.

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
| Link Matching | ~561 ns (1.78M pps) | ~1.06 µs (942K pps) | ~89% | MTU database scan |

### Uptime Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~547 ns | ~1.83M pps | Sufficient for this PCAP (0 uptime hits) |
| Large (10K) | ~544 ns | ~1.84M pps | Better under real uptime tracking load |

**Note**: This PCAP has 0 uptime calculations (no TCP timestamp options), so cache size differences are minimal here. Expect a larger gap in real traffic with uptime-bearing flows.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|-------------|------------|------------|-------------|-------|
| 2 | ~478 ns | ~2.09M pps | ~3.9% | ~39% | Recommended minimum |
| 4 | ~476 ns | ~2.10M pps | ~3.9% | ~39% | Same throughput as 2W |
| 8 | ~484 ns | ~2.06M pps | ~3.9% | ~39% | Marginal degradation from scheduling overhead |

**Worker Architecture**: Hash-based worker assignment (same TCP flow always routes to the same worker). Each worker maintains its own `TtlCache<ConnectionKey, …>` for stateful SYN/SYN-ACK correlation.

**Scaling behavior**: 2 and 4 workers achieve identical throughput (~2.1M pps). Adding more workers does not help on 8-core hardware — parallel benchmarks include worker pool creation/dispatch/shutdown overhead per iteration, which sets the floor at ~20 ms for this 43K-packet workload regardless of worker count.

### Network Capacity

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~8.6% CPU ✓ | ~3.9% CPU ✓ | ~3.9% CPU ✓ | ~3.9% CPU ✓ |
| 10 Gbps (812,740 pps) | ~86% CPU ✓ | ~39% CPU ✓ | ~39% CPU ✓ | ~39% CPU ✓ |

**TCP handles 10 Gbps in all modes.** Sequential at ~86% CPU is tight but does not overload a single core; parallel drops to ~39%. For 10 Gbps environments, the parallel mode (2–4 workers) is recommended.

## Key Findings

### Performance Characteristics

1. **Fast sequential**: ~942K pps full analysis — 10 Gbps at ~86% CPU on a single core
2. **OS matching overhead**: ~93% over base — the p0f database lookup is the dominant cost per SYN/SYN-ACK
3. **MTU matching overhead**: ~89% — comparable to OS matching, scans MTU-to-link-type table
4. **Parallel headroom**: 2–4 workers achieve ~2.1M pps; 8 workers shows marginal degradation from scheduling overhead on 8-core hardware
5. **Parallel scaling**: 2 workers provide ~2.2× throughput improvement over sequential (2.09M vs 942K pps)
6. **Hash-based routing**: Required for stateful SYN/SYN-ACK pairing; same flow always lands on same worker
7. **Production ready**: Sequential handles 10 Gbps with ~86% CPU; parallel modes drop to ~39% CPU

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

## Technical Notes

- Benchmarks run in release mode with full optimizations (Criterion.rs, 100 samples per benchmark)
- Dataset repeated 1000x; per-packet numbers = criterion median ÷ 43,000
- Each `b.iter()` may include matcher construction — slightly inflates per-packet numbers vs sustained real-world throughput
- Parallel benchmarks include full worker pool creation/dispatch/shutdown per iteration — sets a floor around ~20 ms regardless of worker count
- Connection cache uses TTL-based expiration (`TtlCache`)
- Worker pool uses crossbeam channels with hash-based flow dispatch
- Results measured on x86_64, 8-core laptop
