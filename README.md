<div align="center">
  <img src="huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # Huginn Net - Multi-Protocol Passive Fingerprinting

  [![docs](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![crates.io](https://img.shields.io/crates/v/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![Downloads](https://img.shields.io/crates/d/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)
  [![codecov](https://codecov.io/github/biandratti/huginn-net/graph/badge.svg?token=ZPZKFIR4YL)](https://codecov.io/github/biandratti/huginn-net)
</div>

**Huginn Net combines p0f TCP fingerprinting with JA4 TLS client analysis**, achieving the same detection accuracy as the original p0f tool while adding modern TLS fingerprinting capabilities. This Rust implementation has been thoroughly validated against real-world traffic and consistently delivers reliable fingerprinting results.

#### Why choose Huginn Net?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Same accuracy as p0f** - Validated against extensive device testing  
- **Modern Rust implementation** - Memory safety and zero-cost abstractions  
- **Production performance** - Processes packets in ~3.1ms with comparable speed to original p0f  
- **Type-safe architecture** - Prevents entire classes of bugs at compile time  
- **Comprehensive testing** - Full unit and integration test coverage  
- **Simple integration** - Pure Rust implementation, no system libraries required
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

## 📚 Huginn Net Crates

| Crate | Description | Documentation |
|-------|-------------|---------------|
| **[huginn-net](huginn-net/README.md)** | **TCP-HTTP-TLS Analysis** - Complete multi-protocol network fingerprinting | [📖 Usage Guide](huginn-net/README.md) |
| **[huginn-net-tcp](huginn-net-tcp/README.md)** | **TCP Analysis** - OS fingerprinting, MTU detection, uptime estimation | [📖 TCP Guide](huginn-net-tcp/README.md) |
| **[huginn-net-http](huginn-net-http/README.md)** | **HTTP Analysis** - Browser detection, HTTP/1.x & HTTP/2 fingerprinting | [📖 HTTP Guide](huginn-net-http/README.md) |
| **[huginn-net-tls](huginn-net-tls/README.md)** | **TLS Client Analysis** - JA4 fingerprinting, TLS version detection | [📖 TLS Guide](huginn-net-tls/README.md) |


### **Which library should I use?**

- **Multi protocol scanning**: Use **[huginn-net](huginn-net/README.md)** for complete network analysis
- **TCP only**: Use **[huginn-net-tcp](huginn-net-tcp/README.md)** for OS detection and TCP analysis  
- **HTTP only**: Use **[huginn-net-http](huginn-net-http/README.md)** for browser and web server detection
- **TLS only**: Use **[huginn-net-tls](huginn-net-tls/README.md)** for JA4 fingerprinting and TLS analysis
- **Advanced**: Use `huginn-net-db` directly for custom signature parsing

## 🚀 Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Choose Your Approach

**For multi-protocol analysis:**
```toml
[dependencies]
huginn-net = "1.6.0"  # Complete analysis suite
```

**For specific protocols:**
```toml
[dependencies]
huginn-net-tcp = "1.6.0"   # TCP/OS fingerprinting only
huginn-net-http = "1.6.0"  # HTTP analysis only  
huginn-net-tls = "1.6.0"   # TLS/JA4 analysis only
```

### Usage & Examples

For detailed usage examples, installation guides, and complete code samples:

**📖 [Complete Usage Guide - huginn-net module](huginn-net/README.md)**

**📚 [Examples & Tutorials](examples/README.md)** - Working examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

## 📊 Performance & Benchmarks

### Multi-Protocol Performance Summary

| Protocol | Detection Speed | Full Analysis | Primary Use Case |
|----------|-----------------|---------------|------------------|
| **TCP** | 166.7M pps | 1.11M pps | OS fingerprinting, MTU detection |
| **HTTP** | 142.9M pps | 526.6K pps | Browser/server detection |
| **TLS** | 43.5M pps | 50.8K pps | JA4 fingerprinting, TLS analysis |

### Key Performance Highlights
- **Ultra-fast detection**: TCP leads with 166.7M pps, HTTP at 142.9M pps for pre-filtering
- **Robust analysis**: TCP provides 1.11M pps, HTTP 526.6K pps for complete fingerprinting
- **Parallel support**: TCP scales to 3.56M pps (4 workers), HTTP to 1.54M pps (2 workers), TLS to 623.4K pps (4 workers)
- **Comprehensive coverage**: All protocols optimized for real-time network monitoring

### Accuracy & Compatibility
- **TCP**: Matches original p0f precision across tested device categories
- **TLS**: JA4 methodology for modern TLS fingerprinting
- **HTTP**: Browser and server detection with comprehensive signature database

### Performance Optimization
For maximum performance, use protocol-specific libraries:
- `huginn-net-tcp` for TCP-only analysis
- `huginn-net-tls` for TLS-only analysis  
- `huginn-net-http` for HTTP-only analysis

*See [benches/README.md](benches/README.md) for comprehensive benchmark analysis and capacity planning guidelines.*

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
- **Uptime Estimation** from TCP timestamps (limited accuracy on modern systems)
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
