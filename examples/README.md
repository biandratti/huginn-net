### Get network interface
```
ip link show
```

### Output formats

All examples support `--format human` (default) and `--format json`.

| Format | Output | When to use |
|--------|--------|-------------|
| `human` | Multi-line, human-readable (default) | Terminal inspection, debugging |
| `json` | NDJSON — one JSON object per event on stdout | Pipelines, `jq`, log aggregators |

When using `--format json`, analysis events go to **stdout** and operational messages
(`Starting capture...`, stats) go to **stderr**, so piping to `jq` works cleanly.

### Process packages

#### Full Analysis (TCP, HTTP, TLS)
```
# Build example (human default)
cargo build --release --example capture -p huginn-net --features full

# Build with JSON output support
cargo build --release --example capture -p huginn-net --features full,json

# NDJSON on stdout
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture --format json live -i <INTERFACE> | jq -c
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log live -i <INTERFACE>

# Live capture
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log live -i <INTERFACE>                       

# PCAP analysis
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log pcap -f <TCP_TRAFFIC>.pcap

# Filtering examples
# Filter by destination port (e.g., HTTPS on port 443)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log -p 443 live -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log -I 192.168.1.100 live -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log -p 443 -I 192.168.1.100 live -i <INTERFACE>

# Filter PCAP file by port
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l capture.log -p 80 pcap -f traffic.pcap
```

#### TLS-Only Analysis
```
# Build example (human default)
cargo build --release --example capture-tls -p huginn-net-tls --features full

# Build with JSON output support
cargo build --release --example capture-tls -p huginn-net-tls --features full,json

# NDJSON on stdout
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls --format json live single -i <INTERFACE> | jq -c
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live single -i <INTERFACE>

# Live capture - Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded)
# -w: number of worker threads
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live parallel -i <INTERFACE> -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live parallel -i <INTERFACE> -w 8 -q 200

# PCAP file analysis
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (HTTPS only)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -p 443 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -p 443 -I 192.168.1.100 live parallel -i <INTERFACE> -w 4

# PCAP with filtering
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log pcap -f <PCAP_FILE>
```

#### TCP-Only Analysis
```
# Build example (human default)
cargo build --release --example capture-tcp -p huginn-net-tcp --features full

# Build with JSON output support
cargo build --release --example capture-tcp -p huginn-net-tcp --features full,json

# NDJSON on stdout
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp --format json live single -i <INTERFACE> | jq -c
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded, hash-based worker assignment)
# -w: number of worker threads
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live parallel -i <INTERFACE> -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live parallel -i <INTERFACE> -w 8 -q 200

# PCAP file analysis
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (e.g., SSH on port 22)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -p 22 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -p 443 -I 192.168.1.100 live parallel -i <INTERFACE> -w 4

# PCAP with filtering
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -p 22 pcap -f <PCAP_FILE>
```

#### HTTP-Only Analysis
```
# Build example (human default)
cargo build --release --example capture-http -p huginn-net-http --features full

# Build with JSON output support
cargo build --release --example capture-http -p huginn-net-http --features full,json

# NDJSON on stdout
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http --format json live single -i <INTERFACE> | jq -c
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live single -i <INTERFACE>

# Live capture - Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded, flow-based routing)
# -w: number of worker threads (recommended: 2 for optimal performance)
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live parallel -i <INTERFACE> -w 2 -q 100

# Example for 10 Gbps traffic (2 workers recommended)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live parallel -i <INTERFACE> -w 2 -q 100

# PCAP file analysis
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (HTTP on port 80)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -p 80 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -p 80 -I 192.168.1.100 live parallel -i <INTERFACE> -w 2

# PCAP with filtering
RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -p 80 pcap -f <PCAP_FILE>
```

#### Differences between examples:
- **`capture`**: Full analysis (TCP fingerprinting, HTTP analysis, TLS JA4, database matching)
- **`capture-tls`**: TLS-only analysis (JA4 fingerprinting, supports sequential and parallel modes with hash-based worker assignment)
- **`capture-tcp`**: TCP-only analysis (OS fingerprinting, MTU detection, uptime estimation, requires database, supports sequential and parallel modes with hash-based worker assignment)
- **`capture-http`**: HTTP-only analysis (browser fingerprinting, web server detection, language detection, requires database, supports sequential and parallel modes with flow-based routing)
