###  Get network Interface
```
ip link show
```

### Process packages
```
cargo build --release --examples
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/p0f -i <INTERFACE> -l <LOG_FILE.LOG>
```
