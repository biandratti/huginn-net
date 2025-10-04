<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.svg" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-tcp

  [![Crates.io](https://img.shields.io/crates/v/huginn-net-tcp.svg)](https://crates.io/crates/huginn-net-tcp)
  [![Documentation](https://docs.rs/huginn-net-tcp/badge.svg)](https://docs.rs/huginn-net-tcp)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)

  **TCP fingerprinting and OS detection for Huginn Net.**
</div>

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
let mut analyzer = HuginnNetTcp::new(Some(&db), 1000)?;

// Analyze network interface
analyzer.analyze_network("eth0", sender, None)?;
```

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
