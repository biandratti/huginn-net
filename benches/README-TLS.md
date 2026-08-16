# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

> **Numbers source**: Criterion.rs medians across 5 runs of `bench_tls` (per-run throughput = run total ÷ 1,000 packets). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations with no warmup and can diverge from Criterion; only Criterion output is authoritative.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability.

| Metric | Value |
|--------|-------|
| Total packets per iteration | 1,000 (`tls12.pcap` × 1,000) |
| TLS handshakes | per-PCAP, dominated by ClientHello |
| Effectiveness | JA4 computed once per flow (TCP reassembly required) |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| TLS Detection | ~4 ns | ~234M pps | `is_tls_traffic` first-byte check only |
| Packet Parsing | ~2 ns | ~472M pps | Ethernet/IP/TCP header parsing |
| Full TLS Processing | ~5.6 µs | ~177K pps | ClientHello parse + JA4 calculation via `TtlCache` |

> **TLS is ~18× slower than TCP per packet** because ClientHello processing dominates: TCP reassembly across multiple segments, ALPN/cipher/extension parsing, and JA4 string assembly. Detection (`is_tls_traffic`) is cheap; full processing is expensive.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~5.6 µs | ~177K pps | 1.00x | ~46% ✓ | ~458% **[OVERLOAD]** |
| 2 | ~10.2 µs | ~98K pps | 0.55x | ~83% ✓ | ~830% **[OVERLOAD]** |
| 4 | ~10.3 µs | ~97K pps | 0.55x | ~84% ✓ | ~836% **[OVERLOAD]** |
| 8 | ~10.4 µs | ~96K pps | 0.54x | ~85% ✓ | ~847% **[OVERLOAD]** |

**Key Insight**: Parallel 2/4/8 workers plateau near ~96–98K pps. On this workload, sequential full analysis remains higher (~177K pps); parallel benches include worker pool creation/dispatch/shutdown overhead. The bottleneck is per-packet TCP reassembly state management in `TtlCache<FlowKey, TlsClientHelloReader>`, not worker count. **10 Gbps not projected feasible** on this hardware; the parallel plateau (~98K pps) is ~12% of the 10 Gbps packet rate.

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~46% ✓ | ~83% ✓ | ~84% ✓ | ~85% ✓ |
| 10 Gbps (812,740 pps) | ~458% **[OVERLOAD]** | ~830% **[OVERLOAD]** | ~836% **[OVERLOAD]** | ~847% **[OVERLOAD]** |

**1 Gbps projects comfortably in sequential mode** (~46% CPU). Parallel plateaus near ~98K pps (~83% @ 1 Gbps). **10 Gbps projects out of reach** for this single-machine setup regardless of worker count.

## Key Findings

### Performance Characteristics

1. **Fast detection**: TLS byte-level validation in ~4 nanoseconds per packet — cheap to filter non-TLS flows
2. **Processing**: Complete JA4 fingerprinting in ~5.6 µs per packet (sequential), dominated by TCP reassembly state management
3. **Detection-to-processing ratio**: ~1300× — large headroom for filtering before paying the JA4 cost
4. **Parallel scaling**: 2/4/8 workers plateau at ~96–98K pps
5. **1 Gbps**: Sequential projects to ~46% CPU
6. **10 Gbps not projected feasible**: Maximum ~98K pps (parallel) / ~177K pps (sequential) remains well below the 10 Gbps packet rate

### Architectural Insights

TLS processing uses hash-based flow dispatch (`packet_hash::hash_flow`): packets from the same TCP flow always route to the same worker, required for correct stateful TCP reassembly of fragmented ClientHello messages. Each worker maintains its own `TtlCache<FlowKey, TlsClientHelloReader>` for in-flight handshakes.

Unlike TCP and HTTP, TLS scaling is dominated by per-packet reassembly cost rather than dispatch overhead. This means adding workers cannot remove the bottleneck — only faster per-packet processing can.

## Running Benchmarks

```bash
cargo bench -p huginn-net-tls --bench bench_tls
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh tls
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

---

*Hardware: x86_64, 14 CPUs. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
