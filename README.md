###  Get network Interface
```
ip link show
```

### Process packages
```
cargo build --release --examples
sudo RUST_BACKTRACE=1 ./target/release/examples/p0f --interface wlp0s20f3
```
