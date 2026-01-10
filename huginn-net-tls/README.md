<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-tls

  [![docs](https://docs.rs/huginn-net-tls/badge.svg)](https://docs.rs/huginn-net-tls)
  [![crates.io](https://img.shields.io/crates/v/huginn-net-tls.svg)](https://crates.io/crates/huginn-net-tls)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-tls.svg)](https://crates.io/crates/huginn-net-tls)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **JA4 TLS client fingerprinting for Huginn Net.**
</div>

## Overview

This crate provides JA4 TLS client fingerprinting capabilities for passive network analysis. It implements the official JA4 specification by FoxIO, LLC for identifying TLS clients through ClientHello analysis.

### Why choose huginn-net-tls?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Official JA4 implementation** - Complete spec compliance for TLS fingerprinting
- **Pure Rust implementation** - No system libraries required
- **High performance** - 84.6K pps sequential, 608.8K pps parallel (8 cores)
- **Parallel processing** - Multi-threaded worker pool for production workloads
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Typed observable data access** - Access to typed TLS extensions, cipher suites, SNI, ALPN, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableTlsClient`) without being limited to predefined JA4 fingerprints

## Features

- **JA4 Fingerprinting** - Complete implementation of the official JA4 specification
- **TLS Version Support** - TLS 1.0, 1.1, 1.2, 1.3, and SSL 3.0/2.0
- **GREASE Filtering** - Proper handling of GREASE values per RFC 8701
- **SNI & ALPN** - Server Name Indication and ALPN parsing
- **Extension Analysis** - Comprehensive TLS extension parsing
- **Parallel Processing** - Multi-threaded worker pool for live network capture (high-throughput scenarios)
- **Sequential Mode** - Single-threaded processing (for PCAP files and low-resource environments)

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-tls = "1.7.1"
```

### Basic Usage

```rust
use huginn_net_tls::{FilterConfig, HuginnNetTls, HuginnNetTlsError, IpFilter, PortFilter, TlsClientOutput};
use std::sync::mpsc;

fn main() -> Result<(), HuginnNetTlsError> {
    // Create analyzer
    let mut analyzer = HuginnNetTls::new(10000);
    
    // Optional: Configure filters (can be combined)
    if let Ok(ip_filter) = IpFilter::new().allow("192.168.1.0/24") {
        let filter = FilterConfig::new()
            .with_port_filter(PortFilter::new().destination(443))
            .with_ip_filter(ip_filter);
        analyzer = analyzer.with_filter(filter);
    }
    
    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();
    
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
    
    for tls in receiver {
        println!("{tls}");
    }
    
    Ok(())
}
```

For a complete working example with signal handling, error management, and CLI options, see [`examples/capture-tls.rs`](../examples/capture-tls.rs).

### Filtering

The library supports packet filtering to reduce processing overhead and focus on specific traffic. Filters can be combined using AND logic (all conditions must match):

**Filter Types:**
- **Port Filter**: Filter by TCP source/destination ports (supports single ports, lists, and ranges)
- **IP Filter**: Filter by specific IPv4/IPv6 addresses (supports source-only, destination-only, or both)
- **Subnet Filter**: Filter by CIDR subnets (supports IPv4 and IPv6)

All filters support both Allow (allowlist) and Deny (denylist) modes. See the [filter documentation](https://docs.rs/huginn-net-tls/latest/huginn_net_tls/filter/index.html) for complete details.

### Example Output

```text
[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
  SNI:     www.google.com
  Version: TLS 1.3
  JA4:     t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
  JA4_o:   t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_or:  t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
```

## Huginn Net Ecosystem

This crate is part of the Huginn Net ecosystem. For multi-protocol analysis, see **[huginn-net](../huginn-net/README.md)**. For protocol-specific analysis:
- **[huginn-net-tcp](../huginn-net-tcp/README.md)** - OS fingerprinting, MTU detection, uptime estimation
- **[huginn-net-http](../huginn-net-http/README.md)** - Browser detection, HTTP/1.x & HTTP/2 fingerprinting

## Documentation

For complete documentation, examples, and JA4 specification details, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## Attribution

This implementation follows the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4). JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).