# huginn-net-tcp

TCP fingerprinting and OS detection for Huginn Net.

## Overview

This crate provides TCP-based passive fingerprinting capabilities using p0f-style signatures. It analyzes TCP SYN/SYN+ACK packets to identify operating systems, calculate MTU, and estimate system uptime.

## Features

- **OS Fingerprinting** - Identify operating systems from TCP signatures
- **MTU Detection** - Calculate Maximum Transmission Unit from packet analysis  
- **Uptime Calculation** - Estimate system uptime from TCP timestamps
- **Quality Scoring** - Confidence metrics for all matches

## Usage

```rust
use huginn_net_tcp::{HuginnNetTcp, Database};

let db = Database::load_default()?;
let mut analyzer = HuginnNetTcp::new(Some(&db))?;

// Analyze network interface
analyzer.analyze_network("eth0", sender, None)?;
```

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
