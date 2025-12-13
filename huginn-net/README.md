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
- **High performance** - TCP: 1.25M pps, HTTP: 562.1K pps, TLS: 84.6K pps
- **Same accuracy as p0f** - Validated against extensive device testing
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Production-ready parallel processing** - Use protocol-specific crates with multi-threaded worker pools for high-throughput live capture
- **Typed observable data access** - Access to typed TCP signatures, HTTP headers, TLS extensions, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableTcp`, `ObservableHttpRequest/Response`, `ObservableTlsClient`) without being limited to predefined signatures

## Quick Start

### Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
huginn-net = "1.7.0"
huginn-net-db = "1.7.0"
```

### Examples & Tutorials

**[Complete Usage Guide](../examples/README.md)** - Detailed examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

### Basic Usage

```rust
use huginn_net::{Database, FilterConfig, HuginnNet, HuginnNetError, IpFilter, PortFilter};
use std::sync::{Arc, mpsc};

fn main() -> Result<(), HuginnNetError> {
    // Load database for fingerprinting
    let db = match Database::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load database: {e}");
            return Err(HuginnNetError::Parse(format!("Database error: {e}")));
        }
    };
    
    // Create analyzer
    let mut analyzer = match HuginnNet::new(Some(db), 1000, None) {
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
    
    let (sender, receiver) = mpsc::channel();
    
    // Live capture
    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });
    
    // Or PCAP analysis
    // std::thread::spawn(move || {
    //     if let Err(e) = analyzer.analyze_pcap("traffic.pcap", sender, None) {
    //         eprintln!("Analysis error: {e}");
    //     }
    // });
    
    for result in receiver {
        if let Some(tcp_syn) = result.tcp_syn { println!("{tcp_syn}"); }
        if let Some(tcp_syn_ack) = result.tcp_syn_ack { println!("{tcp_syn_ack}"); }
        if let Some(tcp_mtu) = result.tcp_mtu { println!("{tcp_mtu}"); }
        if let Some(tcp_client_uptime) = result.tcp_client_uptime { println!("{tcp_client_uptime}"); }
        if let Some(tcp_server_uptime) = result.tcp_server_uptime { println!("{tcp_server_uptime}"); }
        if let Some(http_request) = result.http_request { println!("{http_request}"); }
        if let Some(http_response) = result.http_response { println!("{http_response}"); }
        if let Some(tls_client) = result.tls_client { println!("{tls_client}"); }
    }
    
    Ok(())
}
```

For complete working examples with signal handling, error management, and CLI options, see [`examples/capture.rs`](../examples/capture.rs).

### Filtering

The library supports packet filtering to reduce processing overhead and focus on specific traffic. Filters can be combined using AND logic (all conditions must match):

**Filter Types:**
- **Port Filter**: Filter by TCP source/destination ports (supports single ports, lists, and ranges)
- **IP Filter**: Filter by specific IPv4/IPv6 addresses (supports source-only, destination-only, or both)
- **Subnet Filter**: Filter by CIDR subnets (supports IPv4 and IPv6)

All filters support both Allow (allowlist) and Deny (denylist) modes. See the [filter documentation](https://docs.rs/huginn-net/latest/huginn_net/filter/index.html) for complete details.

> **Note:** This crate provides sequential (single-threaded) analysis for all protocols. For production high-throughput scenarios, use the protocol-specific crates (`huginn-net-tcp`, `huginn-net-http`, `huginn-net-tls`) with their optimized parallel processing modes.

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
  Uptime: 12 days, 5 hrs, 32 min (modulo 198 days)
  Freq:   100.00 Hz

[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox:10.x or newer
  Lang:    English
  Params:  none
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/

[HTTP Response] 192.168.1.22:58494 → 91.189.91.21:80
  Server:  nginx/1.14.0 (Ubuntu)
  Params:  anonymous
  Sig:     server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:

[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
  SNI:     www.google.com
  Version: TLS 1.3
  JA4:     t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
  JA4_o:   t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_or:  t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
```

## Protocol-Specific Crates

For production deployments or high-throughput scenarios, use the protocol-specific crates with optimized parallel processing:

| Crate | Purpose | Parallel Support | Best For |
|-------|---------|------------------|----------|
| **[huginn-net-tcp](../huginn-net-tcp/README.md)** | TCP/OS fingerprinting (p0f-style) | Source IP hash routing | Live capture, connection tracking |
| **[huginn-net-http](../huginn-net-http/README.md)** | HTTP browser/server detection | Flow-based hash routing | Live capture, request/response matching |
| **[huginn-net-tls](../huginn-net-tls/README.md)** | TLS/JA4 fingerprinting | Round-robin dispatch | Live capture, stateless processing |

**Performance Notes:**
> **When to use `huginn-net`:** Quick prototyping, general analysis, PCAP file analysis, or when you need all protocols analyzed simultaneously. For production systems analyzing live network traffic at high rates (1+ Gbps), use the protocol-specific crates with parallel mode.

## Documentation

For complete documentation, examples, and usage guides, see the [main repository](https://github.com/biandratti/huginn-net).

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE) or [MIT license](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) at your option.
