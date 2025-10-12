<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-tcp

  [![Crates.io](https://img.shields.io/crates/v/huginn-net-tcp.svg)](https://crates.io/crates/huginn-net-tcp)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-tcp.svg)](https://crates.io/crates/huginn-net-tcp)
  [![Documentation](https://docs.rs/huginn-net-tcp/badge.svg)](https://docs.rs/huginn-net-tcp)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)

  **TCP fingerprinting and OS detection for Huginn Net.**
</div>

## Overview

This crate provides TCP-based passive fingerprinting capabilities using p0f-style signatures. It analyzes TCP SYN/SYN+ACK packets to identify operating systems, calculate MTU, and estimate system uptime.

## Features

- **OS Fingerprinting** - Identify operating systems from TCP signatures
- **MTU Detection** - Calculate Maximum Transmission Unit from packet analysis  
- **Uptime Calculation** - Estimate system uptime from TCP timestamps
- **Quality Scoring** - Confidence metrics for all matches

## Quick Start

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-tcp = "1.5.0"
```

### Basic Usage

#### Live Network Analysis

```rust
use huginn_net_tcp::{HuginnNetTcp, TcpAnalysisResult, HuginnNetTcpError};
use huginn_net_db::Database;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetTcpError> {
    let db = Database::load_default()?;
    let mut analyzer = HuginnNetTcp::new(Some(&db), 1000)?;
    
    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();
    
    let handle = thread::spawn(move || {
        analyzer.analyze_network("eth0", sender, None)
    });
    
    for result in receiver {
        if let Some(syn) = result.syn {
            println!("{}", syn);
        }
        if let Some(syn_ack) = result.syn_ack {
            println!("{}", syn_ack);
        }
        if let Some(mtu) = result.mtu {
            println!("{}", mtu);
        }
        if let Some(uptime) = result.uptime {
            println!("{}", uptime);
        }
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

#### PCAP File Analysis

```rust
use huginn_net_tcp::{HuginnNetTcp, TcpAnalysisResult, HuginnNetTcpError};
use huginn_net_db::Database;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetTcpError> {
    let db = Database::load_default()?;
    let mut analyzer = HuginnNetTcp::new(Some(&db), 1000)?;
    
    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();
    
    let handle = thread::spawn(move || {
        analyzer.analyze_pcap("capture.pcap", sender, None)
    });
    
    for result in receiver {
        if let Some(syn) = result.syn {
            println!("{}", syn);
        }
        if let Some(syn_ack) = result.syn_ack {
            println!("{}", syn_ack);
        }
        if let Some(mtu) = result.mtu {
            println!("{}", mtu);
        }
        if let Some(uptime) = result.uptime {
            println!("{}", uptime);
        }
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

For a complete working example, see [`examples/capture-tcp.rs`](../examples/capture-tcp.rs).

### Example Output

```text
.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (syn) ]-
|
| client   = 1.2.3.4/1524
| os       = Windows XP
| dist     = 8
| params   = none
| raw_sig  = 4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (syn+ack) ]-
|
| server   = 4.3.2.1/80
| os       = Linux 3.x
| dist     = 0
| params   = none
| raw_sig  = 4:64+0:0:1460:mss*10,0:mss,nop,nop,sok:df:0
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (mtu) ]-
|
| client   = 1.2.3.4/1524
| link     = DSL
| raw_mtu  = 1492
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (uptime) ]-
|
| client   = 1.2.3.4/1524
| uptime   = 0 days 11 hrs 16 min (modulo 198 days)
| raw_freq = 250.00 Hz
`----
```

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
