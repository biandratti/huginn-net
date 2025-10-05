<div align="center">
  <img src="huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # Huginn Net - Multi-Protocol Passive Fingerprinting

  [![docs](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![crates.io](https://img.shields.io/crates/v/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE-APACHE)
  [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE-MIT)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Dependency Status](https://deps.rs/repo/github/biandratti/huginn-net/status.svg)](https://deps.rs/repo/github/biandratti/huginn-net)
  [![codecov](https://codecov.io/github/biandratti/huginn-net/graph/badge.svg?token=ZPZKFIR4YL)](https://codecov.io/github/biandratti/huginn-net)
</div>

**Huginn Net combines p0f TCP fingerprinting with JA4 TLS client analysis**, achieving the same detection accuracy as the original p0f tool while adding modern TLS fingerprinting capabilities. This Rust implementation has been thoroughly validated against real-world traffic and consistently delivers reliable fingerprinting results.

#### Why choose Huginn Net?

- **Same accuracy as p0f** - Validated against extensive device testing  
- **Modern Rust implementation** - Memory safety and zero-cost abstractions  
- **Production performance** - Processes packets in ~3.1ms with comparable speed to original p0f  
- **Type-safe architecture** - Prevents entire classes of bugs at compile time  
- **Comprehensive testing** - Full unit and integration test coverage  
- **Easy integration** - Clean APIs and modular design  
- **Active development** - Continuously improved and maintained  

#### What is Passive Traffic Fingerprinting?
Passive Traffic Fingerprinting is a technique that allows you to infer information about remote hosts and applications without sending any probes. By analyzing characteristics of the TCP/IP packets and TLS handshakes that are exchanged during normal network conversations, Huginn Net provides insights into:

- **Operating Systems** - Using p0f-inspired TCP fingerprinting to identify OS type, version, and network stack
- **Applications & Browsers** - Using HTTP headers and JA4 TLS client fingerprinting for precise application identification
- **Network Infrastructure** - Detecting intermediary devices, proxies, and load balancers
- **Client Capabilities** - TLS versions, cipher suites, and supported extensions

### Network Stack analysis supported by Huginn Net (OSI Model)

| Layer | Protocol / Feature        | Huginn Net Analysis                         |
|-------|---------------------------|---------------------------------------------|
| 7     | TLS                       | JA4 (FoxIO-style)                           |
| 7     | HTTP                      | HTTP/1 & HTTP/2 - Headers, User-Agent, Lang |
| 4     | TCP                       | OS Fingerprinting (p0f-style)               |



#### Real-world applications:
- **Network Security Analysis** - Identify devices, applications, and TLS clients without active scanning
- **Asset Discovery** - Map network infrastructure and application stack passively and safely  
- **Threat Detection** - Detect hidden systems, suspicious TLS clients, and malicious applications
- **Application Monitoring** - Track browser types, versions, and TLS capabilities across networks
- **Research & Forensics** - Analyze traffic patterns, TLS usage, and improve security posture
- **Compliance Monitoring** - Track device types, OS versions, and TLS configurations

## 📚 Huginn Net Libraries

| Crate | Description | Use Case |
|-------|-------------|----------|
| **huginn-net** | **Main orchestrator** - Complete multi-protocol network fingerprinting | Full network analysis, production deployments |
| **huginn-net-tcp** | **TCP Analysis** - OS fingerprinting, MTU detection, uptime calculation | TCP-only analysis, OS detection, network diagnostics |
| **huginn-net-http** | **HTTP Analysis** - Browser detection, HTTP/1.x & HTTP/2 fingerprinting | Web traffic analysis, browser identification |
| **huginn-net-tls** | **TLS Analysis** - JA4 fingerprinting, TLS version detection | TLS security analysis, client identification |


### **Which library should I use?**

- **Full scanning**: Use `huginn-net` for complete network analysis
- **TCP only**: Use `huginn-net-tcp` for OS detection and TCP analysis  
- **HTTP only**: Use `huginn-net-http` for browser and web server detection
- **TLS only**: Use `huginn-net-tls` for JA4 fingerprinting and TLS analysis
- **Advanced**: Use `huginn-net-db` directly for custom signature parsing

## 🚀 Quick Start

### Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
huginn-net = "1.5.0"
```

### Examples & Tutorials

**[Complete Usage Guide](examples/README.md)** - Detailed examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

### Basic Usage

```rust
use huginn_net::{Database, HuginnNet};
use std::sync::mpsc;

// Load signature database and create analyzer
let db = match Database::load_default() {
    Ok(db) => db,
    Err(e) => {
        error!("Failed to load default database: {}", e);
        return;
    }
};
let (sender, receiver) = mpsc::channel();
let mut analyzer = match HuginnNet::new(Some(&db), 100, None) {
    Ok(analyzer) => analyzer,
    Err(e) => {
        error!("Failed to create HuginnNet analyzer: {}", e);
        return;
    }
};

// Analyze network traffic (choose one)
std::thread::spawn(move || {
    // Live network capture
    analyzer.analyze_network("eth0", sender, None);
    
    // OR PCAP file analysis
    // analyzer.analyze_pcap("traffic.pcap", sender, None);
});

// Process results
for output in receiver {
    if let Some(syn) = output.syn {
        info!("{}", syn);
    }
    if let Some(syn_ack) = output.syn_ack {
        info!("{}", syn_ack);
    }
    if let Some(mtu) = output.mtu {
        info!("{}", mtu);
    }
    if let Some(uptime) = output.uptime {
        info!("{}", uptime);
    }
    if let Some(http_request) = output.http_request {
        info!("{}", http_request);
    }
    if let Some(http_response) = output.http_response {
        info!("{}", http_response);
    }
    if let Some(tls_client) = output.tls_client {
        info!("{}", tls_client);
    }
}
```

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

## 📊 Performance & Accuracy

### Benchmark Results
- **Processing Speed**: ~3.1ms per packet on real-world datasets
- **Accuracy**: **Matches original p0f precision** across tested device categories

*See [benches/README.md](benches/README.md) for detailed performance analysis.*

### Validated Device Categories
- **Desktop Operating Systems** - Windows (XP/7/8/10), Linux distributions, macOS  
- **Mobile Devices** - Android devices, iPhone/iPad  
- **Gaming Consoles** - Nintendo 3DS, Nintendo Wii  
- **Web Browsers** - Chrome, Firefox, Safari, Edge, Opera  
- **Web Servers** - Apache, nginx, IIS, lighttpd  
- **Network Tools** - wget, curl, various crawlers and bots  
- **Legacy Systems** - Older Windows versions, Unix variants  

*Based on signatures available in the p0f database. See [huginn-net-db/config/p0f.fp](huginn-net-db/config/p0f.fp) for complete signature list.*

### Database Coverage
The current signature database includes patterns for:
- **Major Operating Systems** (Windows, Linux, macOS, BSD variants)
- **Popular Web Browsers** (Chrome, Firefox, Safari, etc.)
- **Common Web Servers** (Apache, nginx, IIS)
- **Gaming Devices** (Nintendo consoles)
- **Network Analysis Tools** (crawlers, bots, command-line tools)

## Advanced Features

### Multi-Protocol Support
- **TCP SYN/SYN+ACK** fingerprinting for OS detection
- **HTTP Request/Response** analysis for application identification  
- **TLS ClientHello** analysis with JA4 fingerprinting for client identification
- **MTU Discovery** for link type detection
- **Uptime Calculation** from TCP timestamps
- **Custom Signature Databases** with easy updates

### Matching Quality

Huginn Net provides intelligent quality scoring for all fingerprint matches, helping you assess the reliability of each detection.
The quality score is calculated based on the **distance** between observed network characteristics and known signatures.
To achieve the best quality in matching, a rich database will be needed.

#### Quality Metrics
- **Perfect Match (1.0)**: Exact signature match with zero distance
- **High Quality (0.8-0.95)**: Very close match with minimal differences
- **Medium Quality (0.6-0.8)**: Good match with some variations
- **Low Quality (0.4-0.6)**: Acceptable match but with notable differences
- **Poor Quality (<0.4)**: Weak match, use with caution

### TLS JA4 Fingerprinting

This implementation follows the official [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4) for TLS client fingerprinting. For full attribution and licensing details, please see the [Licensing & Attribution](#-licensing--attribution) section. We do not implement JA4+ components which are under FoxIO License 1.1.

## Interactive Testing

For visual analysis and experimentation, use our companion web application:

**[huginn-net-profiler: Passive Network Profile Analyzer](https://github.com/biandratti/huginn-net-profiler)**

**[Live Demo: https://huginn-net.duckdns.org/](https://huginn-net.duckdns.org/)**

Features:
- Real-time fingerprint visualization
- Interactive signature database exploration
- Custom pattern testing and validation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for detailed information on how to get started.

**Your signature contributions directly improve detection accuracy for the entire community!**

## Next Milestones
-  **Enhanced Database** - Continuous signature updates and community contributions
-  **Advanced Analytics** - Pattern analysis and reporting tools
-  **Real-time Streaming** - High-performance packet processing pipelines

## 📄 License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

### Attribution

`huginn-net` is an independent Rust implementation inspired by the methodologies of `p0f` and `JA4`.

- **p0f**: The TCP fingerprinting is inspired by the original p0f by Michał Zalewski. The logic has been rewritten from scratch in Rust to ensure memory safety and performance.
- **JA4**: The TLS fingerprinting adheres to the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4), which is available under the BSD 3-Clause license. Our implementation was written from scratch for `huginn-net` and does not use any code from the original JA4 repository. JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.
