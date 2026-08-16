# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

> **Numbers source**: Criterion.rs medians across 5 runs of `bench_tcp` (per-run throughput = run total ÷ 43,000 packets). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations with no warmup and can diverge from Criterion; only Criterion output is authoritative.

## Test Data

PCAP dataset: `macos_tcp_flags.pcap` repeated 1000x for statistical stability.

| Metric | Value |
|--------|-------|
| Total packets per iteration | 43,000 (43 original × 1,000) |
| SYN packets | 1,000 |
| SYN-ACK packets | 1,000 |
| MTU detections | 1,000 |
| Uptime calculations | 0 (no TCP timestamp options in this PCAP) |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| Packet Parsing | ~8 ns | ~128M pps | Ethernet/IP/TCP header parsing |
| Full TCP Analysis | ~305 ns | ~3.28M pps | Complete flow processing |
| With OS Matching | ~273 ns | ~3.67M pps | p0f SYN/SYN-ACK database lookup |
| Without OS Matching | ~298 ns | ~3.36M pps | Skip OS database |
| With MTU Matching | ~309 ns | ~3.24M pps | MTU-to-link-type database lookup |
| Without MTU Matching | ~291 ns | ~3.44M pps | Skip link-type lookup |

> Numbers are medians across 5 Criterion sessions. Per-run variance is typically ±5–10%; outlier runs are filtered out by taking the median.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | ~298 ns (3.36M pps) | ~273 ns (3.67M pps) | ~−8% | p0f database lookup per SYN/SYN-ACK |
| MTU/Link Matching | ~291 ns (3.44M pps) | ~309 ns (3.24M pps) | ~6% | MTU database scan |

### Uptime Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~303 ns | ~3.30M pps | Sufficient for this PCAP (0 uptime hits) |
| Large (10K) | ~283 ns | ~3.53M pps | Better under real uptime tracking load |

**Note**: This PCAP has 0 uptime calculations (no TCP timestamp options), so cache size differences are minimal here. Expect a larger gap in real traffic with uptime-bearing flows.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~305 ns | ~3.28M pps | 1.00x | ~2.5% ✓ | ~25% ✓ |
| 2 | ~412 ns | ~2.43M pps | 0.74x | ~3.3% ✓ | ~33% ✓ |
| 4 | ~410 ns | ~2.44M pps | 0.74x | ~3.3% ✓ | ~33% ✓ |
| 8 | ~444 ns | ~2.25M pps | 0.69x | ~3.6% ✓ | ~36% ✓ |

**Key Insight**: Parallel 2 and 4 workers achieve ~2.44M pps. Parallel benches include worker pool creation/dispatch/shutdown overhead per iteration; on this workload sequential full analysis remains higher (~3.28M pps).

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~2.5% ✓ | ~3.3% ✓ | ~3.3% ✓ | ~3.6% ✓ |
| 10 Gbps (812,740 pps) | ~25% ✓ | ~33% ✓ | ~33% ✓ | ~36% ✓ |

**TCP projects to handle 10 Gbps in all modes.** Sequential extrapolates to ~25% CPU; parallel projects to ~33–36%.

## Key Findings

### Performance Characteristics

1. **Sequential**: ~3.28M pps full analysis — 10 Gbps projects to ~25% CPU on a single core
2. **OS matching overhead**: ~−8% vs without matching (within run-to-run noise)
3. **MTU matching overhead**: ~6%
4. **Parallel scaling**: 2/4 workers ~2.44M pps; 8 workers ~2.25M pps
5. **Capacity**: Sequential projects to ~25% CPU at 10 Gbps; parallel projects to ~33–36%

### Architectural Insights

TCP processing uses hash-based worker assignment: the same TCP flow always routes to the same worker, required for stateful SYN/SYN-ACK correlation. Each worker maintains its own `TtlCache<ConnectionKey, …>` for connection state.

Parallel throughput plateaus near ~2.44M pps (2–4 workers). The hash-based routing is essential for correctness but creates uneven load distribution at higher worker counts.

## Running Benchmarks

```bash
cargo bench -p huginn-net-tcp --features full --bench bench_tcp
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh tcp
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

---

*Hardware: x86_64, 14 CPUs. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
