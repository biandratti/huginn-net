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
# Build TLS example
cargo build --release --examples -p huginn-net-tls

# Live capture - Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded)
# -w: number of worker threads
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live parallel -i <INTERFACE> -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log live parallel -i <INTERFACE> -w 8 -q 200

# PCAP file analysis
./target/release/examples/capture-tls -l tls-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (HTTPS only)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -p 443 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tls -l tls-capture.log -p 443 -I 192.168.1.100 live parallel -i <INTERFACE> -w 4

# PCAP with filtering
./target/release/examples/capture-tls -l tls-capture.log -p 443 pcap -f <PCAP_FILE>
```

#### TCP-Only Analysis
```
# Build TCP example
cargo build --release --examples -p huginn-net-tcp

# Live capture - Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded, hash-based worker assignment)
# -w: number of worker threads
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live parallel -i <INTERFACE> -w 4 -q 100

# Example for high load scenarios (more workers, larger queues)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log live parallel -i <INTERFACE> -w 8 -q 200

# PCAP file analysis
./target/release/examples/capture-tcp -l tcp-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (e.g., SSH on port 22)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -p 22 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-tcp -l tcp-capture.log -p 443 -I 192.168.1.100 live parallel -i <INTERFACE> -w 4

# PCAP with filtering
./target/release/examples/capture-tcp -l tcp-capture.log -p 22 pcap -f <PCAP_FILE>
```

#### HTTP-Only Analysis
```
# Build HTTP example
cargo build --release --examples -p huginn-net-http

# Live capture - Sequential mode (single-threaded)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live single -i <INTERFACE>

# Live capture - Parallel mode (multi-threaded, flow-based routing)
# -w: number of worker threads (recommended: 2 for optimal performance)
# -q: queue size per worker (default: 100, lower = lower latency)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live parallel -i <INTERFACE> -w 2 -q 100

# Example for 10 Gbps traffic (2 workers recommended)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log live parallel -i <INTERFACE> -w 2 -q 100

# PCAP file analysis
./target/release/examples/capture-http -l http-capture.log pcap -f <PCAP_FILE>

# Filtering examples
# Filter by destination port (HTTP on port 80)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -p 80 live single -i <INTERFACE>

# Filter by IP address
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -I 192.168.1.100 live single -i <INTERFACE>

# Filter by both port and IP (both conditions must match)
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture-http -l http-capture.log -p 80 -I 192.168.1.100 live parallel -i <INTERFACE> -w 2

# PCAP with filtering
./target/release/examples/capture-http -l http-capture.log -p 80 pcap -f <PCAP_FILE>
```

#### Differences between examples:
- **`capture`**: Full analysis (TCP fingerprinting, HTTP analysis, TLS JA4, database matching)
- **`capture-tls`**: TLS-only analysis (JA4 fingerprinting, supports sequential and parallel modes with round-robin dispatch)
- **`capture-tcp`**: TCP-only analysis (OS fingerprinting, MTU detection, uptime estimation, requires database, supports sequential and parallel modes with hash-based worker assignment)
- **`capture-http`**: HTTP-only analysis (browser fingerprinting, web server detection, language detection, requires database, supports sequential and parallel modes with flow-based routing)
