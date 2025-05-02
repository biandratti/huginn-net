# Benchmarks

These benchmarks were run using `cargo bench` in release mode on a real pcap file containing a mix of SYN, SYN-ACK, MTU, Uptime, and HTTP packets.

## Packages analyzed

- SYN:           164
- SYN-ACK:       152
- MTU:           164
- Uptime:        144
- HTTP Request:  2
- HTTP Response: 4

## Performance results

| Metric                | Value                |
|-----------------------|---------------------|
| Total packets         | 164 (SYN, main ref) |
| Total time (mean)     | 513.67 ms           |
| Time per packet (mean)| ~3.13 ms            |
| Throughput            | ~320 packets/sec    |
| Criterion sample size | 100                 |
| Measurement time      | 60 seconds          |

## How to reproduce

1. Capture a pcap file (e.g., with `tcpdump -w dump.pca`).
2. Place the file as `dump.pca` in the project root or update the path in `benches/benchmark.rs`.
3. Run:

```sh
cargo build --release
cargo bench
```

> _Note: The benchmark measures only the core library processing, not the full CLI binary. For end-to-end timing, use `/usr/bin/time ./target/release/your_binary`._

## Interpretation

- The library processes each packet in approximately 3.1 ms on this dataset.