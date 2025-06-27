###  Get network Interface
```
ip link show
```

### Enable TLS packages 
```
cargo build --release --examples --features tls
```

### Enable other features
```
cargo build --release --examples
```

### Live capture
```
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l <LOG_FILE.LOG> live -i <INTERFACE>                       
```

### PCAP analysis
```
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/capture -l <LOG_FILE.LOG> pcap -f <TCP_TRAFFIC>.pcap
```