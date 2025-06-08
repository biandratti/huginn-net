###  Get network Interface
```
ip link show
```

### Process packages
```
# Build package
cargo build --release --examples

# Live capture
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/p0f -l <LOG_FILE.LOG> live -i <INTERFACE>                       

# PCAP analysis
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/p0f -l <LOG_FILE.LOG> pcap -f <TCP_TRAFFIC>.pcap
```