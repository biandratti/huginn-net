# Huginn-Net Benchmarks

Performance benchmarks for all Huginn-Net protocol libraries.

> **Numbers source**: Criterion.rs medians. Per-packet values are criterion median ÷ packets per iteration (TCP: 43,000 · HTTP: 16,000 · TLS: 1,000). The inline report printed at the end of each bench run uses `measure_average_time` with 3–10 iterations and no warmup — those values can diverge from Criterion and should be ignored.

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
| **TCP** | ~480–510 ns | ~2.0M pps | ~4.1% | ~41% |
| **HTTP** | ~0.95 µs | ~1.05M pps | ~7.7% | ~77% |
| **TLS** | ~20 µs | ~50K pps | ~162% [OVERLOAD] | ~1621% [OVERLOAD] |

### Parallel Mode

#### TLS — Hash-based flow dispatch, per-worker `TtlCache`
| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|------------|-------------|
| 1 (seq) | ~50K pps | ~162% [OVERLOAD] | ~1621% [OVERLOAD] |
| 2 | ~97K pps | ~84% | ~837% [OVERLOAD] |
| 4 | ~97K pps | ~84% | ~837% [OVERLOAD] |
| 8 | ~96K pps | ~85% | ~845% [OVERLOAD] |

#### TCP — Hash-based flow dispatch, per-worker `TtlCache`
| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|------------|-------------|
| 1 (seq) | ~2.0M pps | ~4.1% | ~41% |
| 2 | ~3.6–4.2M pps | ~2.0–2.3% | ~20–23% |
| 4 | ~3.9–4.2M pps | ~1.9–2.1% | ~19–21% |
| 8 | ~3.8–4.2M pps | ~1.9–2.2% | ~19–22% |

#### HTTP — Hash-based flow dispatch, per-worker `TtlCache`
| Workers | Throughput | 1 Gbps CPU | 10 Gbps CPU |
|---------|------------|------------|-------------|
| 1 (seq) | ~1.05M pps | ~7.7% | ~77% |
| 2 | ~1.53M pps | ~5.3% | ~53% |
| 4 | ~1.4M pps | ~5.8% | ~58% |
| 8 | ~1.3M pps | ~6.3% | ~63% |

All three protocols use the same dispatch architecture: hash-based flow routing (4-tuple src/dst IP+port → worker) so the same TCP flow always lands on the same worker, enabling stateful per-worker processing.

## Key Insights

### Protocol Ranking by Throughput

1. **TCP** — ~2M pps sequential, ~4M pps parallel. Handles 10 Gbps on a single core (~41% CPU); parallel adds headroom.
2. **HTTP** — ~1.05M pps sequential, ~1.53M pps parallel. Handles 10 Gbps sequential at ~77% CPU; 2 workers recommended for production headroom.
3. **TLS** — ~50K pps sequential, ~97K pps parallel. TLS is the only protocol that requires parallel mode to handle even 1 Gbps; JA4 calculation + TCP reassembly dominate cost.

### Feature Overhead

| Protocol | Feature | Without | With | Overhead |
|----------|---------|---------|------|----------|
| TCP | OS matching | ~270 ns | ~400 ns | ~130–140% |
| TCP | MTU/link matching | ~300 ns | ~530 ns | ~100% |
| HTTP | Browser matching | ~850 ns | ~730 ns | **−14%** (early exit) |
| HTTP | Server matching | ~860 ns | ~990 ns | +15% |

> HTTP browser matching is faster with the matcher enabled because `HttpSignatureMatcher` short-circuits flow processing on early UA match. Server matching adds overhead since full response header scanning is required before the label is known.

### Parallel Scaling Behavior

- **TLS**: 2 and 4 workers plateau at ~97K pps; adding more workers yields no gain. Bottleneck is TCP reassembly per packet, not worker count.
- **TCP**: Mild monotonic improvement 2→8 workers (~3.6M→4.2M pps), though differences are within measurement noise (high outlier counts). All configurations comfortably handle 10 Gbps.
- **HTTP**: 2 workers is optimal (~1.53M pps); 4–8 workers degrade slightly due to flow distribution overhead.

## Detailed Analysis Reports

- **[TLS Analysis](README-TLS.md)** — JA4 fingerprinting, TCP reassembly architecture
- **[TCP Analysis](README-TCP.md)** — OS fingerprinting, MTU detection, uptime calculation
- **[HTTP Analysis](README-HTTP.md)** — Browser/server detection, flow tracking

## Technical Notes

- Benchmarks run in release mode with full optimizations (Criterion.rs, 100 samples)
- Datasets repeated 1000x per run for statistical stability
- Parallel benchmarks include worker pool creation/dispatch/shutdown per `b.iter()` call
- TCP and HTTP datasets use PCAPs with mixed traffic; effectiveness ratios reflect real-world packet distribution
- Results measured on x86_64, 8-core laptop — parallel optimal worker counts are hardware-specific
