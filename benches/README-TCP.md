# TCP Benchmark Analysis

Performance analysis of `huginn-net-tcp` library for OS fingerprinting, MTU detection, and uptime calculation.

> **Numbers source**: Criterion.rs medians ÷ 43,000 packets per iteration. The inline report printed at the end of each bench run uses `measure_average_time` with 3 iterations and no warmup — those numbers can diverge from Criterion and should be ignored. Only Criterion output is authoritative.

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
| Packet Parsing | ~5 ns | ~210M pps | Ethernet/IP/TCP header parsing |
| Full TCP Analysis | ~480–510 ns | ~1.97–2.07M pps | Complete flow processing |
| With OS Matching | ~395–440 ns | ~2.3–2.5M pps | p0f SYN/SYN-ACK database lookup |
| Without OS Matching | ~260–280 ns | ~3.6–3.8M pps | Skip OS database |
| With MTU Matching | ~490–580 ns | ~1.7–2.0M pps | MTU-to-link-type database lookup |
| Without MTU Matching | ~270–330 ns | ~3.0–3.7M pps | Skip link-type lookup |

> Ranges reflect run-to-run variance across three Criterion sessions. Runs 1 and 3 are most stable; run 2 had elevated outlier counts on several benchmarks.

### Feature-Specific Performance

| Feature | Without | With | Overhead | Notes |
|---------|---------|------|----------|-------|
| OS Matching | ~270 ns (3.7M pps) | ~400 ns (2.5M pps) | ~130–140% | p0f database lookup per SYN/SYN-ACK |
| Link Matching | ~300 ns (3.3M pps) | ~530 ns (1.9M pps) | ~100% | MTU database scan |

### Uptime Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~260 ns | ~3.85M pps | Sufficient for this PCAP (0 uptime hits) |
| Large (10K) | ~260–290 ns | ~3.5–3.8M pps | Better under real uptime tracking load |

**Note**: This PCAP has 0 uptime calculations (no TCP timestamp options), so cache size differences are minimal here. Expect larger gap in real traffic with uptime-bearing flows.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU | Notes |
|---------|-------------|------------|------------|-------------|-------|
| 2 | ~240–280 ns | ~3.6–4.2M pps | ~2.0% | ~20% | Good |
| 4 | ~240–280 ns | ~3.6–4.2M pps | ~2.0% | ~20% | Good |
| 8 | ~238–263 ns | ~3.8–4.2M pps | ~1.9% | ~19% | Converges in stable runs |

**Worker Architecture**: Hash-based worker assignment (same TCP flow always routes to the same worker). Each worker maintains its own `TtlCache<ConnectionKey, …>` for stateful SYN/SYN-ACK correlation.

**Scaling behavior**: TCP parallel shows mild monotonic improvement from 2 → 8 workers in the two most stable runs. The high outlier counts (15–23%) across all parallel benchmarks indicate the 43K-packet workload approaches the noise floor — pool creation/shutdown overhead is non-negligible per iteration. Absolute differences between worker counts are within measurement noise.

### Network Capacity

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~4.1% CPU ✓ | ~2.0% CPU ✓ | ~2.0% CPU ✓ | ~1.9% CPU ✓ |
| 10 Gbps (812,740 pps) | ~41% CPU ✓ | ~20% CPU ✓ | ~20% CPU ✓ | ~19% CPU ✓ |

**TCP handles 10 Gbps comfortably in all modes.** Sequential at ~41% CPU leaves headroom; parallel drops to ~20%. No OVERLOAD scenario in any configuration.

## Key Findings

### Performance Characteristics

1. **Very fast sequential**: ~2M pps full analysis — 10 Gbps at ~41% CPU on a single core
2. **OS matching overhead**: ~130% over base — the p0f database lookup is the dominant cost per SYN/SYN-ACK
3. **MTU matching overhead**: ~100% — comparable to OS matching, scans MTU-to-link-type table
4. **Parallel headroom**: 2–8 workers all achieve ~3.6–4.2M pps; differences are within measurement noise
5. **Hash-based routing**: Required for stateful SYN/SYN-ACK pairing; same flow always lands on same worker
6. **Production ready**: All configurations handle 10 Gbps with significant CPU headroom

## Running Benchmarks

```bash
cargo bench --bench bench_tcp
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

## Technical Notes

- Benchmarks run in release mode with full optimizations (Criterion.rs, 100 samples per benchmark)
- Dataset repeated 1000x; per-packet numbers = criterion median ÷ 43,000
- Each `b.iter()` includes `TcpDatabase::load_default()` or matcher construction — slightly inflates per-packet numbers vs sustained real-world throughput
- Parallel benchmarks include full worker pool creation/dispatch/shutdown per iteration (3 iterations via `measure_average_time`) — explains the high outlier counts (15–23%)
- Connection cache uses TTL-based expiration (`TtlCache`)
- Worker pool uses crossbeam channels with hash-based flow dispatch
- Results measured on x86_64, 8-core laptop
