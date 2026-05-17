# TLS Benchmark Analysis

Performance analysis of `huginn-net-tls` library for JA4 fingerprinting with sequential and parallel processing modes.

> **Numbers source**: Criterion.rs medians across 5 runs of `bench_tls` (per-run throughput = run total ÷ 1,000 packets). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations with no warmup and can diverge from Criterion; only Criterion output is authoritative.

## Test Data

PCAP dataset: `tls12.pcap` repeated 1000x for statistical stability.

| Metric | Value |
|--------|-------|
| Total packets per iteration | 1,000,000 (1,000 original × 1,000) |
| TLS handshakes | per-PCAP, dominated by ClientHello |
| Effectiveness | JA4 computed once per flow (TCP reassembly required) |

## Performance Results

### Sequential Mode (Single-Thread)

| Operation | Time/Packet | Throughput | Notes |
|-----------|-------------|------------|-------|
| TLS Detection | ~18 ns | ~56M pps | `is_tls_traffic` first-byte check only |
| Packet Parsing | ~6 ns | ~167M pps | Ethernet/IP/TCP header parsing |
| Full TLS Processing | ~20 µs | ~50K pps | ClientHello parse + JA4 calculation via `TtlCache` |

> **TLS is ~400x slower than TCP per packet** because ClientHello processing dominates: TCP reassembly across multiple segments, ALPN/cipher/extension parsing, and JA4 string assembly. Detection (`is_tls_traffic`) is cheap; full processing is expensive.

### Parallel Mode (Multi-Worker)

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~20 µs | ~50K pps | 1.00x | ~163% **[OVERLOAD]** | ~1625% **[OVERLOAD]** |
| 2 | ~10.3 µs | ~97K pps | 1.94x | ~84% ✓ | ~838% **[OVERLOAD]** |
| 4 | ~10.4 µs | ~96K pps | 1.92x | ~84% ✓ | ~839% **[OVERLOAD]** |
| 8 | ~10.4 µs | ~96K pps | 1.92x | ~85% ✓ | ~843% **[OVERLOAD]** |

**Key Insight**: 2 workers nearly doubles throughput (~50K → ~97K pps) but 4 and 8 workers plateau. The bottleneck is per-packet TCP reassembly state management in `TtlCache<FlowKey, TlsClientHelloReader>`, not worker count. **10 Gbps not projected feasible** on 8-core hardware; the maximum throughput (~97K pps) is ~12% of the 10 Gbps packet rate.

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better than this 8-core laptop; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~163% **[OVERLOAD]** | ~84% ✓ | ~84% ✓ | ~85% ✓ |
| 10 Gbps (812,740 pps) | ~1625% **[OVERLOAD]** | ~838% **[OVERLOAD]** | ~839% **[OVERLOAD]** | ~843% **[OVERLOAD]** |

**1 Gbps projects to require parallel mode** (sequential extrapolates to ~163% CPU); 2 workers projects to ~84% CPU at 1 Gbps with little headroom. **10 Gbps projects out of reach** for this single-machine setup regardless of worker count.

## Key Findings

### Performance Characteristics

1. **Fast detection**: TLS byte-level validation in ~18 nanoseconds per packet — cheap to filter non-TLS flows
2. **Slow processing**: Complete JA4 fingerprinting in ~20 µs per packet (sequential), dominated by TCP reassembly state management
3. **Detection-to-processing ratio**: ~1100x — there is enormous headroom for filtering before paying the JA4 cost
4. **Parallel scaling**: 2 workers provide ~1.94× throughput improvement; 4–8 workers plateau (per-worker cache is the bottleneck)
5. **1 Gbps projects to require parallel**: Sequential extrapolates above 100% CPU at line rate; minimum recommended config is `HuginnNetTls::with_config(2, 100)`
6. **10 Gbps not projected feasible**: Maximum ~97K pps is ~12% of the 10 Gbps target — would need ~10x more workers on dedicated hardware

### Architectural Insights

TLS processing uses hash-based flow dispatch (`packet_hash::hash_flow`): packets from the same TCP flow always route to the same worker, required for correct stateful TCP reassembly of fragmented ClientHello messages. Each worker maintains its own `TtlCache<FlowKey, TlsClientHelloReader>` for in-flight handshakes.

Unlike TCP and HTTP, TLS scaling is dominated by per-packet reassembly cost rather than dispatch overhead. This means adding workers cannot remove the bottleneck — only faster per-packet processing can. JA4 string assembly and database lookups during fingerprinting are the next optimization targets.

## Running Benchmarks

```bash
cargo bench --bench bench_tls
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh tls 5
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead per iteration).

---

*Hardware: x86_64, 8-core laptop. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
