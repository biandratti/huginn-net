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

# Sequential mode (single-threaded, lower resource usage)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log single -i eth0

# Parallel mode (multi-threaded, high throughput)
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

# Live TCP capture (focuses only on TCP fingerprinting)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l <TCP_LOG_FILE.LOG> live -i <INTERFACE>

# Example with specific interface
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live -i eth0
```

#### HTTP-Only Analysis
```
# Build HTTP example
cargo build --release --examples -p huginn-net-http

# Live HTTP capture (focuses only on HTTP traffic analysis)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l <HTTP_LOG_FILE.LOG> live -i <INTERFACE>

# Example with specific interface
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live -i eth0
```

#### Differences between examples:
- **`capture`**: Full analysis (TCP fingerprinting, HTTP analysis, TLS JA4, database matching)
- **`capture-tls`**: TLS-only analysis (JA4 fingerprinting, supports sequential and parallel modes)
- **`capture-tcp`**: TCP-only analysis (OS fingerprinting, MTU detection, uptime calculation, requires database)
- **`capture-http`**: HTTP-only analysis (browser fingerprinting, web server detection, language detection, requires database)
