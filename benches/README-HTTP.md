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
| Packet Parsing | ~4 ns | ~237M pps | Ethernet/IP/TCP header parsing |
| Full HTTP Analysis | ~704 ns | ~1.42M pps | Complete flow processing (request + response + matching) |
| With Browser Matching | ~618 ns | ~1.62M pps | UA → browser DB lookup |
| Without Browser Matching | ~617 ns | ~1.62M pps | Skip UA lookup |
| With Server Matching | ~684 ns | ~1.46M pps | Server header → server DB lookup |
| Without Server Matching | ~590 ns | ~1.70M pps | Skip server lookup |

> **Matching cost** — browser and server matching perform DB lookups on successful detection. Disable matching for use cases that only need flow tracking / header capture without UA fingerprinting.

### Feature-Specific Performance

| Feature | Without | With | Delta | Notes |
|---------|---------|------|-------|-------|
| Browser Matching | ~617 ns (1.62M pps) | ~618 ns (1.62M pps) | ~0% | UA → browser DB lookup |
| Server Matching | ~590 ns (1.70M pps) | ~684 ns (1.46M pps) | ~16% | Response header scan + DB lookup |
| Protocol Detection | — | ~576 ns (1.74M pps) | — | Fast-reject heuristic + parser dispatch |
| Header Analysis | — | ~582 ns (1.72M pps) | — | Per-packet header extraction |

### Cache Size Impact

| Cache Size | Time/Packet | Throughput | Notes |
|------------|-------------|------------|-------|
| Small (100) | ~589 ns | ~1.70M pps | Frequent evictions under load |
| Large (10K) | ~578 ns | ~1.73M pps | Better flow retention |

**Note**: Cache size difference is small for this workload. The PCAP keeps few concurrent flows, so the 100-slot cache rarely evicts.

### Parallel Mode (Multi-Worker)

**Configuration**: `batch_size=16`, `timeout_ms=10`, `queue_size=100`

| Workers | Time/Packet | Throughput | Speedup | 1 Gbps CPU | 10 Gbps CPU |
|---------|-------------|------------|---------|------------|-------------|
| 1 (seq) | ~704 ns | ~1.42M pps | 1.00x | ~5.7% ✓ | ~57% ✓ |
| 2 | ~652 ns | ~1.53M pps | 1.08x | ~5.3% ✓ | ~53% ✓ |
| 4 | ~706 ns | ~1.42M pps | 1.00x | ~5.7% ✓ | ~57% ✓ |
| 8 | ~740 ns | ~1.35M pps | 0.95x | ~6.0% ✓ | ~60% ✓ |

**Key Insight**: 2 workers is the highest parallel throughput (~1.53M pps). Sequential full analysis is close (~1.42M pps). 4 and 8 workers show diminishing returns due to flow-based hashing concentrating connection traffic on a single worker.

### Network Capacity

> **Projections, not measurements** — CPU values below are `target_pps / measured_pps × 100`, not run under sustained packet load. Server-grade hardware typically performs 30–80% better; see the [master README](README.md) for methodology details.

| Scenario | Sequential | 2 Workers | 4 Workers | 8 Workers |
|----------|-----------|-----------|-----------|-----------|
| 1 Gbps (81,274 pps) | ~5.7% ✓ | ~5.3% ✓ | ~5.7% ✓ | ~6.0% ✓ |
| 10 Gbps (812,740 pps) | ~57% ✓ | ~53% ✓ | ~57% ✓ | ~60% ✓ |

**1 Gbps and 10 Gbps project comfortably across sequential and parallel configurations** on this hardware.

### Akamai HTTP/2 pipeline

`HTTP_Akamai` group, built with `--features full`. Each dataset is one fixture connection
replicated 1,000 times with distinct client ports (and, for TLS, distinct client randoms with
matching key log entries), generated in memory. Single Criterion run, median.

| Scenario | Dataset | Time / iteration | Per connection | Throughput |
|----------|---------|------------------|----------------|------------|
| `h2c_cleartext` | `akamai-h2c-prior.pcap` x1000 (9,000 packets) | ~17.6 ms | ~17.6 µs | ~511k pps |
| `tls13_keylog_decrypt` | `akamai-tls13-aes128-chrome.pcap` x1000 (13,000 packets) | ~25.9 ms | ~25.9 µs | ~503k pps |
| `tls13_no_keylog_baseline` | same TLS traffic, `akamai-keylog` compiled in, no `with_keylog` | ~10.4 ms | ~10.4 µs | ~1.25M pps |

**SC-005, key log throughput >= 50% of the baseline: not met (~40%).** These connections
are as short as a TLS connection gets (13 packets), so the per-connection work dominates
and is not amortized over later packets:

- tracking and reassembly, before any decryption: ~3.5 µs;
- key derivation (HKDF for the handshake and application secrets) and AEAD setup: ~2.6 µs;
- the Akamai extraction itself (`extract_akamai_fingerprint`: HPACK decoding, SHA-256):
  ~3.5 µs, the same cost as the standalone API;
- AES-GCM itself is cheap (hardware accelerated, ~0.5 µs per 1 KiB record).

On longer connections the gap shrinks: once a fingerprint is emitted the connection is
marked terminal and its later packets cost a single lookup.

**SC-005, pipeline with the new features disabled within +-3% of `master`:** both trees
built with `--features p0f-request,p0f-response`, one Criterion run each:

| Benchmark | master | this branch | Delta |
|-----------|--------|-------------|-------|
| `http_with_browser_matching` | 14.38 ms | 13.62 ms | -5.3% |
| `http_without_browser_matching` | 12.82 ms | 12.72 ms | -0.8% |
| `server_with_matching` | 14.75 ms | 15.41 ms | +4.5% |
| `server_without_matching` | 13.74 ms | 13.47 ms | -2.0% |
| `protocol_detection` | 13.29 ms | 12.51 ms | -5.9% |
| `header_analysis` | 13.55 ms | 12.87 ms | -5.0% |
| `small_flow_cache` | 12.27 ms | 12.50 ms | +1.9% |
| `large_flow_cache` | 12.35 ms | 12.41 ms | +0.4% |
| `full_http_analysis` | 15.00 ms | 14.36 ms | -4.2% |
| `full_analysis_with_collection` | 15.86 ms | 16.09 ms | +1.5% |

The deltas go both ways (mean -1.8%), which is run-to-run noise rather than a regression:
with these features the new code is compiled out. A single run is too noisy to resolve +-3%;
use `./benches/run_bench.sh http` on both trees for a median over 5 runs.

## Key Findings

### Performance Characteristics

1. **Fast parsing**: HTTP packet structure validation in ~4 nanoseconds
2. **Flow processing**: Complete analysis in ~704 ns per packet (sequential, full analysis with matching)
3. **Matching cost**: Browser matching ~0%; server matching ~16%
4. **Parallel efficiency**: 2 workers ~1.08× sequential; beyond 2 workers shows diminishing returns due to flow-based hashing
5. **10 Gbps capacity**: Sequential projects to ~57% CPU; 2 workers project to ~53%

### Architectural Insights

HTTP processing relies on stateful flow tracking (per-connection `TtlCache`) and flow-based hashing that routes same-connection packets to the same worker, which is required for correct HTTP request/response pairing.

This limits parallel scaling compared to stateless protocols, but sequential and 2-worker modes both project to handle 10 Gbps with headroom on this hardware.

## Running Benchmarks

```bash
cargo bench -p huginn-net-http --features full --bench bench_http
```

For multi-run statistical analysis (5 sessions, median across runs):

```bash
./benches/run_bench.sh http
```

Use **Criterion output** for analysis, not the inline summary report (which uses fewer iterations and includes construction overhead).

---

*Hardware: x86_64, 14 CPUs. Absolute numbers are hardware-specific; ratios and overheads transfer across machines.*
