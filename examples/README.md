###  Get network Interface
```
ip link show
```

### Process packages

#### Full Analysis (TCP, HTTP, TLS)
```
# Build package
cargo build --release --examples -p huginn-net

# Live capture
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l <LOG_FILE.LOG> live -i <INTERFACE>                       

# PCAP analysis
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l <LOG_FILE.LOG> pcap -f <TCP_TRAFFIC>.pcap
```

#### TLS-Only Analysis
```
# Build TLS example
cargo build --release --examples -p huginn-net-tls

# Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log single -i eth0

# Parallel mode (multi-threaded)
# -w: number of worker threads (typically number of CPU cores)
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log parallel -i eth0 -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log parallel -i eth0 -w 8 -q 200
```

#### TCP-Only Analysis
```
# Build TCP example
cargo build --release --examples -p huginn-net-tcp

# Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log single -i eth0

# Parallel mode (multi-threaded, hash-based worker assignment)
# -w: number of worker threads (typically number of CPU cores)
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log parallel -i eth0 -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log parallel -i eth0 -w 8 -q 200
```

#### HTTP-Only Analysis
```
# Build HTTP example
cargo build --release --examples -p huginn-net-http

# Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log single -i eth0

# Parallel mode (multi-threaded, flow-based routing)
# -w: number of worker threads (recommended: 2 for optimal performance)
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log parallel -i eth0 -w 2 -q 100

# Example for 10 Gbps traffic (2 workers recommended)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log parallel -i eth0 -w 2 -q 100
```

#### Differences between examples:
- **`capture`**: Full analysis (TCP fingerprinting, HTTP analysis, TLS JA4, database matching)
- **`capture-tls`**: TLS-only analysis (JA4 fingerprinting, supports sequential and parallel modes with round-robin dispatch)
- **`capture-tcp`**: TCP-only analysis (OS fingerprinting, MTU detection, uptime estimation, requires database, supports sequential and parallel modes with hash-based worker assignment)
- **`capture-http`**: HTTP-only analysis (browser fingerprinting, web server detection, language detection, requires database, supports sequential and parallel modes with flow-based routing)
