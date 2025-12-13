<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-http

  [![docs](https://docs.rs/huginn-net-http/badge.svg)](https://docs.rs/huginn-net-http)
  [![crates.io](https://img.shields.io/crates/v/huginn-net-http.svg)](https://crates.io/crates/huginn-net-http)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-http.svg)](https://crates.io/crates/huginn-net-http)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **HTTP fingerprinting and browser detection for Huginn Net.**
</div>

## Overview

This crate provides HTTP-based passive fingerprinting capabilities. It analyzes HTTP/1.x and HTTP/2 headers to identify browsers, web servers, and detect preferred languages.

### Why choose huginn-net-http?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Comprehensive analysis** - Browser, server, and language detection
- **Pure Rust implementation** - No system libraries required
- **High performance** - 562.1K pps for full analysis, 200M pps detection
- **HTTP/1.x & HTTP/2** - Support for both major protocol versions
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Typed observable data access** - Access to typed HTTP headers, header ordering, language preferences, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableHttpRequest`, `ObservableHttpResponse`) without being limited to predefined p0f signatures

## Features

- **Browser Detection** - Identify browsers from HTTP request headers
- **Web Server Detection** - Identify servers from HTTP response headers
- **Language Detection** - Extract preferred languages from Accept-Language headers
- **HTTP/1.x & HTTP/2** - Support for both major HTTP versions
- **Quality Scoring** - Confidence metrics for all matches
- **Parallel Processing** - Multi-threaded worker pool for live network capture (high-throughput scenarios)
- **Sequential Mode** - Single-threaded processing (for PCAP files and low-resource environments)

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-http = "1.7.0"
huginn-net-db = "1.7.0"
```

### Basic Usage

```rust
use huginn_net_db::Database;
use huginn_net_http::{FilterConfig, HuginnNetHttp, HuginnNetHttpError, IpFilter, PortFilter, HttpAnalysisResult};
use std::sync::{Arc, mpsc};

fn main() -> Result<(), HuginnNetHttpError> {
    // Load database for browser/server fingerprinting
    let db = match Database::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load database: {e}");
            return Err(HuginnNetHttpError::Parse(format!("Database error: {e}")));
        }
    };
    
    // Create analyzer
    let mut analyzer = match HuginnNetHttp::new(Some(db), 1000) {
        Ok(analyzer) => analyzer,
        Err(e) => {
            eprintln!("Failed to create analyzer: {e}");
            return Err(e);
        }
    };
    
    // Optional: Configure filters (can be combined)
    if let Ok(ip_filter) = IpFilter::new().allow("192.168.1.0/24") {
        let filter = FilterConfig::new()
            .with_port_filter(PortFilter::new().destination(80))
            .with_ip_filter(ip_filter);
        analyzer = analyzer.with_filter(filter);
    }
    
    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();
    
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
        if let Some(http_request) = result.http_request { println!("{http_request}"); }
        if let Some(http_response) = result.http_response { println!("{http_response}"); }
    }
    
    Ok(())
}
```

For a complete working example with signal handling, error management, and CLI options, see [`examples/capture-http.rs`](../examples/capture-http.rs).

### Filtering

The library supports packet filtering to reduce processing overhead and focus on specific traffic. Filters can be combined using AND logic (all conditions must match):

**Filter Types:**
- **Port Filter**: Filter by TCP source/destination ports (supports single ports, lists, and ranges)
- **IP Filter**: Filter by specific IPv4/IPv6 addresses (supports source-only, destination-only, or both)
- **Subnet Filter**: Filter by CIDR subnets (supports IPv4 and IPv6)

All filters support both Allow (allowlist) and Deny (denylist) modes. See the [filter documentation](https://docs.rs/huginn-net-http/latest/huginn_net_http/filter/index.html) for complete details.

### Example Output

```text
[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox:10.x or newer
  Lang:    English
  Params:  none
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/

[HTTP Response] 192.168.1.22:58494 → 91.189.91.21:80
  Server:  nginx/1.14.0 (Ubuntu)
  Params:  anonymous
  Sig:     server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
```

## Huginn Net Ecosystem

This crate is part of the Huginn Net ecosystem. For multi-protocol analysis, see **[huginn-net](../huginn-net/README.md)**. For protocol-specific analysis:
- **[huginn-net-tcp](../huginn-net-tcp/README.md)** - OS fingerprinting, MTU detection, uptime estimation
- **[huginn-net-tls](../huginn-net-tls/README.md)** - JA4 fingerprinting, TLS version detection

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
