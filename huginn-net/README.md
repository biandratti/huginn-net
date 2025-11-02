<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # huginn-net

  [![docs](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![crates.io](https://img.shields.io/crates/v/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![Downloads](https://img.shields.io/crates/d/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.**
</div>

This is the main orchestrator crate that combines all protocol analyzers into a unified interface.

## Why choose huginn-net?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Multi-protocol support** - TCP, HTTP, and TLS analysis in one unified interface
- **Pure Rust implementation** - No system libraries required
- **High performance** - TCP: 1.25M pps, HTTP: 562.1K pps, TLS: 84.6K pps (608.8K with parallel)
- **Same accuracy as p0f** - Validated against extensive device testing
- **Type-safe architecture** - Prevents entire classes of bugs at compile time

## Quick Start

### Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
huginn-net = "1.5.1"
```

### Examples & Tutorials

**[Complete Usage Guide](../examples/README.md)** - Detailed examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

### Basic Usage

#### Live Network Analysis

```rust
use huginn_net::{Database, HuginnNet};
use huginn_net::error::HuginnNetError;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetError> {
    // Load signature database and create analyzer
    let db = Database::load_default()?;
    let mut analyzer = HuginnNet::new(Some(&db), 1000, None)?;
    
    let (sender, receiver) = mpsc::channel();
    
    // Spawn analysis thread
    let handle = thread::spawn(move || {
        analyzer.analyze_network("eth0", sender, None)
    });
    
    // Process results
    for result in receiver {
        if let Some(syn) = result.syn {
            println!("{syn}");
        }
        if let Some(syn_ack) = result.syn_ack {
            println!("{syn_ack}");
        }
        if let Some(mtu) = result.mtu {
            println!("{mtu}");
        }
        if let Some(client_uptime) = result.client_uptime {
            println!("{client_uptime}");
        }
        if let Some(server_uptime) = result.server_uptime {
            println!("{server_uptime}");
        }
        if let Some(http_request) = result.http_request {
            println!("{http_request}");
        }
        if let Some(http_response) = result.http_response {
            println!("{http_response}");
        }
        if let Some(tls_client) = result.tls_client {
            println!("{tls_client}");
        }
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

#### PCAP File Analysis

```rust
use huginn_net::{Database, HuginnNet};
use huginn_net::error::HuginnNetError;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), HuginnNetError> {
    // Load signature database and create analyzer
    let db = Database::load_default()?;
    let mut analyzer = HuginnNet::new(Some(&db), 1000, None)?;
    
    let (sender, receiver) = mpsc::channel();
    
    // Spawn PCAP analysis thread
    let handle = thread::spawn(move || {
        analyzer.analyze_pcap("traffic.pcap", sender, None)
    });
    
    // Process results
    for result in receiver {
        if let Some(syn) = result.syn {
            println!("{syn}");
        }
        if let Some(syn_ack) = result.syn_ack {
            println!("{syn_ack}");
        }
        if let Some(mtu) = result.mtu {
            println!("{mtu}");
        }
        if let Some(client_uptime) = result.client_uptime {
            println!("{client_uptime}");
        }
        if let Some(server_uptime) = result.server_uptime {
            println!("{server_uptime}");
        }
        if let Some(http_request) = result.http_request {
            println!("{http_request}");
        }
        if let Some(http_response) = result.http_response {
            println!("{http_response}");
        }
        if let Some(tls_client) = result.tls_client {
            println!("{tls_client}");
        }
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

For complete working examples, see [`examples/capture.rs`](../examples/capture.rs).

### Package Analysis Output
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

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (http request) ]-
|
| client   = 1.2.3.4/1524
| app      = Firefox:10.x or newer
| lang     = English
| params   = none
| raw_sig  = 1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
`----

.-[ 192.168.1.22/58494 -> 91.189.91.21/80 (http response) ]-
|
| server   = 91.189.91.21/80
| app      = nginx/1.14.0 (Ubuntu)
| params   = anonymous
| raw_sig  = server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
`----

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

## Protocol Crates

For individual protocol analysis, you can use the specific crates:

- **[huginn-net-tcp](../huginn-net-tcp/README.md)** - TCP fingerprinting (p0f-style)
- **[huginn-net-http](../huginn-net-http/README.md)** - HTTP analysis  
- **[huginn-net-tls](../huginn-net-tls/README.md)** - TLS fingerprinting (JA4)

## Documentation

For complete documentation, examples, and usage guides, see the [main repository](https://github.com/biandratti/huginn-net).

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE) or [MIT license](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) at your option.
