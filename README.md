###  Get network Interface
```
ip link show
```

### Process packages
```
cargo build --release
sudo RUST_BACKTRACE=1 ./target/release/p0f --interface <INTERFACE>
```