<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-tcp

  [![docs](https://docs.rs/huginn-net-tcp/badge.svg)](https://docs.rs/huginn-net-tcp)
  [![crates.io](https://img.shields.io/crates/v/huginn-net-tcp.svg)](https://crates.io/crates/huginn-net-tcp)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-tcp.svg)](https://crates.io/crates/huginn-net-tcp)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **TCP fingerprinting and OS detection for Huginn Net.**
</div>

## Overview

This crate provides TCP-based passive fingerprinting capabilities using p0f-style signatures. It analyzes TCP SYN/SYN+ACK packets to identify operating systems, calculate MTU, and estimate system uptime.

### Why choose huginn-net-tcp?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Same accuracy as p0f** - Validated against extensive device testing
- **Pure Rust implementation** - No system libraries required
- **Exceptional performance** - 1.25M pps for full analysis, 166.7M pps detection
- **Comprehensive testing** - Full unit and integration test coverage
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Typed observable data access** - Access to typed TCP signatures, MTU values, uptime data, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableTcp`, `ObservableMtu`, `ObservableUptime`) without being limited to predefined p0f signatures

## Features

- **OS Fingerprinting** - Identify operating systems from TCP signatures
- **MTU Detection** - Calculate Maximum Transmission Unit from packet analysis  
- **Uptime Estimation** - Best-effort uptime calculation from TCP timestamps
  - ⚠️ **Limited on modern systems**: Most modern operating systems (Windows 10+, Linux 4.10+, macOS 10.12+) randomize TCP timestamps for privacy/security, making uptime estimation unreliable or impossible
  - Works best on: Legacy systems, embedded devices, IoT hardware, and some server distributions
- **Quality Scoring** - Confidence metrics for all matches
- **Parallel Processing** - Multi-threaded worker pool for live network capture (high-throughput scenarios)
- **Sequential Mode** - Single-threaded processing (for PCAP files and low-resource environments)

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-tcp = "1.7.2"
huginn-net-db = "1.7.2"
```

### Basic Usage

```rust
use huginn_net_db::Database;
use huginn_net_tcp::{FilterConfig, HuginnNetTcp, HuginnNetTcpError, IpFilter, PortFilter, TcpAnalysisResult};
use std::sync::{Arc, mpsc};

fn main() -> Result<(), HuginnNetTcpError> {
    // Load database for OS fingerprinting
    let db = match Database::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load database: {e}");
            return Err(HuginnNetTcpError::Parse(format!("Database error: {e}")));
        }
    };
    
    // Create analyzer
    let mut analyzer = match HuginnNetTcp::new(Some(db), 1000) {
        Ok(analyzer) => analyzer,
        Err(e) => {
            eprintln!("Failed to create analyzer: {e}");
            return Err(e);
        }
    };
    
    // Optional: Configure filters (can be combined)
    if let Ok(ip_filter) = IpFilter::new().allow("192.168.1.0/24") {
        let filter = FilterConfig::new()
            .with_port_filter(PortFilter::new().destination(443))
            .with_ip_filter(ip_filter);
        analyzer = analyzer.with_filter(filter);
    }
    
    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();
    
    // Live capture (use parallel mode for high throughput)
    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });
    
    // Or PCAP analysis (always use sequential mode)
    // std::thread::spawn(move || {
    //     if let Err(e) = analyzer.analyze_pcap("capture.pcap", sender, None) {
    //         eprintln!("Analysis error: {e}");
    //     }
    // });
    
    for result in receiver {
        if let Some(syn) = result.syn { println!("{syn}"); }
        if let Some(syn_ack) = result.syn_ack { println!("{syn_ack}"); }
        if let Some(mtu) = result.mtu { println!("{mtu}"); }
        if let Some(client_uptime) = result.client_uptime { println!("{client_uptime}"); }
        if let Some(server_uptime) = result.server_uptime { println!("{server_uptime}"); }
    }
    
    Ok(())
}
```

For a complete working example with signal handling, error management, and CLI options, see [`examples/capture-tcp.rs`](../examples/capture-tcp.rs).

### Filtering

The library supports packet filtering to reduce processing overhead and focus on specific traffic. Filters can be combined using AND logic (all conditions must match):

**Filter Types:**
- **Port Filter**: Filter by TCP source/destination ports (supports single ports, lists, and ranges)
- **IP Filter**: Filter by specific IPv4/IPv6 addresses (supports source-only, destination-only, or both)
- **Subnet Filter**: Filter by CIDR subnets (supports IPv4 and IPv6)

All filters support both Allow (allowlist) and Deny (denylist) modes. See the [filter documentation](https://docs.rs/huginn-net-tcp/latest/huginn_net_tcp/filter/index.html) for complete details.

### Example Output

```text
[TCP SYN] 1.2.3.4:1524 → 4.3.2.1:80
  OS:     Windows XP
  Dist:   8
  Params: none
  Sig:    4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0

[TCP SYN+ACK] 4.3.2.1:80 → 1.2.3.4:1524
  OS:     Linux 3.x
  Dist:   0
  Params: none
  Sig:    4:64+0:0:1460:mss*10,0:mss,nop,nop,sok:df:0

[TCP MTU] 1.2.3.4:1524 → 4.3.2.1:80
  Link:   DSL
  MTU:    1492

[TCP Uptime - Client] 1.2.3.4:1524 → 4.3.2.1:80
  Uptime: 0 days, 11 hrs, 16 min (modulo 198 days)
  Freq:   250.00 Hz

[TCP Uptime - Server] 4.3.2.1:80 → 1.2.3.4:1524
  Uptime: 15 days, 3 hrs, 42 min (modulo 497 days)
  Freq:   100.00 Hz
```

**Note on Uptime Estimation:** Modern operating systems (Windows 10+, Linux 4.10+, macOS 10.12+) randomize TCP timestamps for privacy, making uptime estimation unreliable. This feature works best on legacy systems, embedded devices, and network equipment.

## Huginn Net Ecosystem

This crate is part of the Huginn Net ecosystem. For multi-protocol analysis, see **[huginn-net](../huginn-net/README.md)**. For protocol-specific analysis:
- **[huginn-net-http](../huginn-net-http/README.md)** - Browser detection, HTTP/1.x & HTTP/2 fingerprinting
- **[huginn-net-tls](../huginn-net-tls/README.md)** - JA4 fingerprinting, TLS version detection

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
