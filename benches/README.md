# Huginn-Net Benchmarks

Performance benchmarks for all Huginn-Net protocol libraries.

> **Numbers source**: Criterion.rs medians across 5 runs (`./benches/run_bench.sh <proto> 5`). Per-packet values are criterion median ÷ packets per iteration (TCP: 43,000 · HTTP: 16,000 · TLS: 1,000). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations and no warmup; only Criterion output is authoritative.

> **About CPU percentages**: All "1 Gbps CPU" / "10 Gbps CPU" values are **projections** derived from measured throughput (`CPU% = target_pps / measured_pps × 100`), not measurements under sustained packet load on a real NIC. They assume linear scaling and ignore kernel networking stack overhead, NIC IRQ handling, memory contention at line rate, and CPU clock stability. Treat as planning estimates: server-grade hardware (Xeon/EPYC, no thermal throttling, NIC flow steering, no background processes) typically delivers 30–80% better than this 8-core laptop; pathological workloads (cross-NUMA, deeply fragmented flows) may underperform.

## Available Benchmarks

| Protocol | Benchmark File | Library | Command |
|----------|---------------|---------|---------|
| **TLS** | `bench_tls.rs` | `huginn-net-tls` | `cargo bench -p huginn-net-tls` |
| **TCP** | `bench_tcp.rs` | `huginn-net-tcp` | `cargo bench -p huginn-net-tcp` |
| **HTTP** | `bench_http.rs` | `huginn-net-http` | `cargo bench -p huginn-net-http` |

## Performance Summary

### Sequential Mode (Single-Thread)

| Protocol | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU |
|----------|-------------|------------|------------|-------------|
| **TCP** | ~1.06 µs | ~942K pps | ~8.6% ✓ | ~86% ✓ |
| **HTTP** | ~1.39 µs | ~720K pps | ~11.3% ✓ | ~113% **[OVERLOAD]** |
| **TLS** | ~20 µs | ~50K pps | ~163% **[OVERLOAD]** | ~1625% **[OVERLOAD]** |

### Parallel Mode

All three protocols share the same dispatch architecture: hash-based flow routing (4-tuple src/dst IP+port → worker) so the same TCP flow always lands on the same worker, enabling stateful per-worker processing via `TtlCache`.

#### TCP

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~942K pps | 1.00x | ~8.6% ✓ | ~86% ✓ |
| 2 | ~2.09M pps | 2.22x | ~3.9% ✓ | ~39% ✓ |
| 4 | ~2.10M pps | 2.23x | ~3.9% ✓ | ~39% ✓ |
| 8 | ~2.06M pps | 2.19x | ~3.9% ✓ | ~39% ✓ |

#### HTTP

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~720K pps | 1.00x | ~11.3% ✓ | ~113% **[OVERLOAD]** |
| 2 | ~1.55M pps | 2.15x | ~5.3% ✓ | ~52.6% ✓ |
| 4 | ~1.09M pps | 1.51x | ~7.5% ✓ | ~74.8% ✓ |
| 8 | ~982K pps | 1.36x | ~8.3% ✓ | ~82.7% ✓ |

#### TLS

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~50K pps | 1.00x | ~163% **[OVERLOAD]** | ~1625% **[OVERLOAD]** |
| 2 | ~97K pps | 1.94x | ~84% ✓ | ~838% **[OVERLOAD]** |
| 4 | ~96K pps | 1.92x | ~84% ✓ | ~839% **[OVERLOAD]** |
| 8 | ~96K pps | 1.92x | ~85% ✓ | ~843% **[OVERLOAD]** |

## Key Insights

### Protocol Ranking by Throughput

1. **TCP** — ~942K pps sequential, ~2.10M pps parallel. The only protocol where 10 Gbps **projects comfortably** on a single core (~86% CPU); parallel projects to ~39%.
2. **HTTP** — ~720K pps sequential, ~1.55M pps parallel. Sequential **projects to overload** at 10 Gbps line rate (~113% CPU); production deployments project to need at least 2 workers (~53% @ 10 Gbps).
3. **TLS** — ~50K pps sequential, ~97K pps parallel. Even 1 Gbps projects to require parallel mode (~84% with 2 workers). 10 Gbps **not projected feasible** on 8-core hardware regardless of worker count; JA4 calculation + TCP reassembly dominate cost.

### Feature Overhead

| Protocol | Feature | Without | With | Overhead |
|----------|---------|---------|------|----------|
| TCP | OS matching | ~556 ns (1.80M pps) | ~1.07 µs (930K pps) | ~93% |
| TCP | MTU/link matching | ~561 ns (1.78M pps) | ~1.06 µs (942K pps) | ~89% |
| HTTP | Browser matching | ~1.10 µs (910K pps) | ~1.42 µs (700K pps) | +29% |
| HTTP | Server matching | ~1.10 µs (915K pps) | ~1.48 µs (680K pps) | +35% |

> **Matching always adds cost** — both OS, MTU, browser, and server matching require database lookups on every successful detection. Disable matching for use cases that only need flow tracking / header capture without OS/UA fingerprinting.

### Parallel Scaling Behavior

- **TCP**: 2/4/8 workers plateau at ~2.1M pps (within measurement noise). 2 workers already saturates the achievable throughput for this workload; more workers don't help on 8-core hardware.
- **HTTP**: 2 workers is optimal (~1.55M pps, +115% over sequential). 4 and 8 workers degrade (~1.09M and ~982K pps) because flow-based hashing concentrates per-connection traffic onto fewer workers as the pool grows.
- **TLS**: 2/4/8 workers plateau at ~97K pps. The bottleneck is per-packet TCP reassembly, not worker count — adding workers yields no gain.

## Detailed Analysis Reports

- **[TCP Analysis](README-TCP.md)** — OS fingerprinting, MTU detection, uptime calculation
- **[HTTP Analysis](README-HTTP.md)** — Browser/server detection, flow tracking
- **[TLS Analysis](README-TLS.md)** — JA4 fingerprinting, TCP reassembly architecture

---

*Hardware: x86_64, 8-core laptop. Optimal worker counts and absolute throughput are hardware-specific.*
