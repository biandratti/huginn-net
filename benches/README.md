# Huginn-Net Benchmarks

Performance benchmarks for all Huginn-Net protocol libraries.

> **Numbers source**: Criterion.rs medians across 5 runs (`./benches/run_bench.sh <proto>`). Per-packet values are criterion median ÷ packets per iteration (TCP: 43,000 · HTTP: 16,000 · TLS: 1,000). The inline `measure_average_time` summary printed at the end of each run uses 3–10 iterations and no warmup; only Criterion output is authoritative.

> **About CPU percentages**: All "1 Gbps CPU" / "10 Gbps CPU" values are **projections** derived from measured throughput (`CPU% = target_pps / measured_pps × 100`), not measurements under sustained packet load on a real NIC. They assume linear scaling and ignore kernel networking stack overhead, NIC IRQ handling, memory contention at line rate, and CPU clock stability. Treat as planning estimates: server-grade hardware (Xeon/EPYC, no thermal throttling, NIC flow steering, no background processes) typically delivers 30–80% better than this machine; pathological workloads (cross-NUMA, deeply fragmented flows) may underperform.

## Available Benchmarks

| Protocol | Benchmark File | Library | Command |
|----------|---------------|---------|---------|
| **TLS** | `bench_tls.rs` | `huginn-net-tls` | `cargo bench -p huginn-net-tls` |
| **TCP** | `bench_tcp.rs` | `huginn-net-tcp` | `cargo bench -p huginn-net-tcp --features full` |
| **HTTP** | `bench_http.rs` | `huginn-net-http` | `cargo bench -p huginn-net-http --features full` |

## Performance Summary

### Sequential Mode (Single-Thread)

| Protocol | Time/Packet | Throughput | 1 Gbps CPU | 10 Gbps CPU |
|----------|-------------|------------|------------|-------------|
| **TCP** | ~305 ns | ~3.28M pps | ~2.5% ✓ | ~25% ✓ |
| **HTTP** | ~704 ns | ~1.42M pps | ~5.7% ✓ | ~57% ✓ |
| **TLS** | ~5.6 µs | ~177K pps | ~46% ✓ | ~458% **[OVERLOAD]** |

### Parallel Mode

All three protocols share the same dispatch architecture: hash-based flow routing (4-tuple src/dst IP+port → worker) so the same TCP flow always lands on the same worker, enabling stateful per-worker processing via `TtlCache`.

#### TCP

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~3.28M pps | 1.00x | ~2.5% ✓ | ~25% ✓ |
| 2 | ~2.43M pps | 0.74x | ~3.3% ✓ | ~33% ✓ |
| 4 | ~2.44M pps | 0.74x | ~3.3% ✓ | ~33% ✓ |
| 8 | ~2.25M pps | 0.69x | ~3.6% ✓ | ~36% ✓ |

#### HTTP

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~1.42M pps | 1.00x | ~5.7% ✓ | ~57% ✓ |
| 2 | ~1.53M pps | 1.08x | ~5.3% ✓ | ~53% ✓ |
| 4 | ~1.42M pps | 1.00x | ~5.7% ✓ | ~57% ✓ |
| 8 | ~1.35M pps | 0.95x | ~6.0% ✓ | ~60% ✓ |

#### TLS

| Workers | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|---------|------------|-------------|
| 1 (seq) | ~177K pps | 1.00x | ~46% ✓ | ~458% **[OVERLOAD]** |
| 2 | ~98K pps | 0.55x | ~83% ✓ | ~830% **[OVERLOAD]** |
| 4 | ~97K pps | 0.55x | ~84% ✓ | ~836% **[OVERLOAD]** |
| 8 | ~96K pps | 0.54x | ~85% ✓ | ~847% **[OVERLOAD]** |

## Key Insights

### Protocol Ranking by Throughput

1. **TCP** — ~3.28M pps sequential, ~2.44M pps parallel. 10 Gbps **projects comfortably** on a single core (~25% CPU); parallel projects to ~33%.
2. **HTTP** — ~1.42M pps sequential, ~1.53M pps parallel. 10 Gbps projects to ~57% CPU sequential; 2 workers project to ~53%.
3. **TLS** — ~177K pps sequential, ~98K pps parallel. 1 Gbps projects to ~46% CPU sequential; parallel plateaus near ~98K pps (~83% @ 1 Gbps). 10 Gbps **not projected feasible** on this hardware regardless of worker count; JA4 calculation + TCP reassembly dominate cost.

### Feature Overhead

| Protocol | Feature | Without | With | Overhead |
|----------|---------|---------|------|----------|
| TCP | OS matching | ~298 ns (3.36M pps) | ~273 ns (3.67M pps) | ~−8% |
| TCP | MTU/link matching | ~291 ns (3.44M pps) | ~309 ns (3.24M pps) | ~6% |
| HTTP | Browser matching | ~617 ns (1.62M pps) | ~618 ns (1.62M pps) | ~0% |
| HTTP | Server matching | ~590 ns (1.70M pps) | ~684 ns (1.46M pps) | ~16% |

> **Matching cost** — OS/MTU/browser/server matching perform database lookups on successful detection. Disable matching for use cases that only need flow tracking / header capture without OS/UA fingerprinting.

### Parallel Scaling Behavior

- **TCP**: Sequential full analysis ~3.28M pps. Parallel 2/4 workers plateau at ~2.44M pps; 8 workers ~2.25M pps (worker pool overhead on this workload).
- **HTTP**: 2 workers ~1.53M pps (1.08× sequential). 4 and 8 workers ~1.42M / ~1.35M pps; flow-based hashing concentrates per-connection traffic onto fewer workers as the pool grows.
- **TLS**: Sequential full analysis ~177K pps. Parallel 2/4/8 workers plateau at ~96–98K pps (worker pool overhead on this workload). The bottleneck is per-packet TCP reassembly, not worker count.

## Detailed Analysis Reports

- **[TCP Analysis](README-TCP.md)** — OS fingerprinting, MTU detection, uptime calculation
- **[HTTP Analysis](README-HTTP.md)** — Browser/server detection, flow tracking
- **[TLS Analysis](README-TLS.md)** — JA4 fingerprinting, TCP reassembly architecture

---

*Hardware: x86_64, 14 CPUs. Optimal worker counts and absolute throughput are hardware-specific.*
