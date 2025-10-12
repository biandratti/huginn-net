<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-tls

  [![Crates.io](https://img.shields.io/crates/v/huginn-net-tls.svg)](https://crates.io/crates/huginn-net-tls)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-tls.svg)](https://crates.io/crates/huginn-net-tls)
  [![Documentation](https://docs.rs/huginn-net-tls/badge.svg)](https://docs.rs/huginn-net-tls)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)

  **JA4 TLS client fingerprinting for Huginn Net.**
</div>

## Overview

This crate provides JA4 TLS client fingerprinting capabilities for passive network analysis. It implements the official JA4 specification by FoxIO, LLC for identifying TLS clients through ClientHello analysis.

## Features

- **JA4 Fingerprinting** - Complete implementation of the official JA4 specification
- **TLS Version Support** - TLS 1.0, 1.1, 1.2, 1.3, and SSL 3.0/2.0
- **GREASE Filtering** - Proper handling of GREASE values per RFC 8701
- **SNI & ALPN** - Server Name Indication and ALPN parsing
- **Extension Analysis** - Comprehensive TLS extension parsing

## Quick Start

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-tls = "1.5.0"
```

### Basic Usage

#### Live Network Analysis

```rust
use huginn_net_tls::{HuginnNetTls, TlsClientOutput, HuginnNetTlsError};
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetTlsError> {
    let mut analyzer = HuginnNetTls::new();
    
    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();
    
    let handle = thread::spawn(move || {
        analyzer.analyze_network("eth0", sender, None)
    });
    
    for tls in receiver {
        println!("{}", tls);
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

#### PCAP File Analysis

```rust
use huginn_net_tls::{HuginnNetTls, TlsClientOutput, HuginnNetTlsError};
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetTlsError> {
    let mut analyzer = HuginnNetTls::new();
    
    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();
    
    let handle = thread::spawn(move || {
        analyzer.analyze_pcap("capture.pcap", sender, None)
    });
    
    for tls in receiver {
        println!("{}", tls);
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

For a complete working example, see [`examples/capture-tls.rs`](../examples/capture-tls.rs).

### Example Output

```text
.-[ 192.168.1.10/45234 -> 172.217.5.46/443 (tls client) ]-
|
| client   = 192.168.1.10/45234
| ja4      = t13d1516h2_8daaf6152771_b0da82dd1658
| ja4_r    = t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
| ja4_o    = t13d1516h2_8daaf6152771_b0da82dd1658
| ja4_or   = t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
| sni      = www.google.com
| version  = 1.3
`----
```

## Documentation

For complete documentation, examples, and JA4 specification details, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## Attribution

This implementation follows the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4). JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).