<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # huginn-net

  [![Crates.io](https://img.shields.io/crates/v/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![Documentation](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)

  **Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.**
</div>

This is the main orchestrator crate that combines all protocol analyzers into a unified interface.

## Quick Start

```rust
use huginn_net::{HuginnNet, Database};

let db = Database::load_default()?;
let mut analyzer = HuginnNet::new(Some(&db), 1000, None)?;

// Analyze live network traffic
analyzer.analyze_network("eth0", sender, None)?;
```

## Protocol Crates

For individual protocol analysis, you can use the specific crates:

- [`huginn-net-tcp`](https://crates.io/crates/huginn-net-tcp) - TCP fingerprinting (p0f-style)
- [`huginn-net-http`](https://crates.io/crates/huginn-net-http) - HTTP analysis  
- [`huginn-net-tls`](https://crates.io/crates/huginn-net-tls) - TLS fingerprinting (JA4)

## Documentation

For complete documentation, examples, and usage guides, see the [main repository](https://github.com/biandratti/huginn-net).

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE) or [MIT license](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) at your option.
