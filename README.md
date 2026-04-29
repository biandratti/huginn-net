<div align="center">
  <img src="huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # Huginn Net - Multi-Protocol Passive Fingerprinting

  [![docs](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)
  [![codecov](https://codecov.io/github/biandratti/huginn-net/graph/badge.svg?token=ZPZKFIR4YL)](https://codecov.io/github/biandratti/huginn-net)
  [![huginn-net](https://img.shields.io/crates/d/huginn-net.svg?label=huginn-net)](https://crates.io/crates/huginn-net)
  [![huginn-net-db](https://img.shields.io/crates/d/huginn-net-db.svg?label=huginn-net-db)](https://crates.io/crates/huginn-net-db)
  [![huginn-net-tcp](https://img.shields.io/crates/d/huginn-net-tcp.svg?label=huginn-net-tcp)](https://crates.io/crates/huginn-net-tcp)
  [![huginn-net-http](https://img.shields.io/crates/d/huginn-net-http.svg?label=huginn-net-http)](https://crates.io/crates/huginn-net-http)
  [![huginn-net-tls](https://img.shields.io/crates/d/huginn-net-tls.svg?label=huginn-net-tls)](https://crates.io/crates/huginn-net-tls)
</div>

**Huginn Net fingerprints TCP, HTTP, and TLS traffic passively.** No active probes, no tshark, no wireshark. Pure Rust, built entirely on open-source specifications: p0f for TCP and FoxIO's JA4 for TLS. Validated against the original p0f accuracy with ~3.1ms end-to-end per packet.

#### What is Passive Traffic Fingerprinting?
Passive fingerprinting infers information about remote hosts without sending any probes. By analyzing TCP/IP packets and TLS handshakes, Huginn Net identifies:

- **Operating Systems** - Using p0f-inspired TCP fingerprinting to identify OS type, version, and network stack
- **Applications & Browsers** - Using HTTP headers and JA4 TLS client fingerprinting for precise application identification
- **Network Infrastructure** - Detecting intermediary devices, proxies, and load balancers
- **Client Capabilities** - TLS versions, cipher suites, and supported extensions

### Network Stack analysis supported by Huginn Net (OSI Model)

| Layer | Protocol / Feature        | Huginn Net Analysis                         |
|-------|---------------------------|---------------------------------------------|
| 7     | TLS                       | JA4 (FoxIO-style) + stable signature        |
| 7     | HTTP                      | HTTP/1 & HTTP/2 - Headers, User-Agent, Lang |
| 4     | TCP                       | OS Fingerprinting (p0f-style)               |


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
huginn-net = "1.7.5"  # Complete analysis suite
```

**For specific protocols:**
```toml
[dependencies]
huginn-net-tcp = "1.7.5"   # TCP/OS fingerprinting only
huginn-net-http = "1.7.5"  # HTTP analysis only
huginn-net-tls = "1.7.5"   # TLS/JA4 analysis only
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
| **TCP** | 83.3M pps | 975.6K pps | OS fingerprinting, MTU detection |
| **HTTP** | 142.9M pps | 526.6K pps | Browser/server detection |
| **TLS** | 48M pps | 45K pps | JA4 fingerprinting, TLS analysis |

All protocols scale with multiple workers: TCP to 2.11M pps (4 workers), HTTP to 1.54M pps (2 workers), TLS to 97K pps (2–4 workers). See [benches/README.md](benches/README.md) for methodology and capacity planning.

### Validated Device Categories
- **Desktop Operating Systems** - Windows (XP/7/8/10), Linux distributions, macOS  
- **Mobile Devices** - Android devices, iPhone/iPad  
- **Gaming Consoles** - Nintendo 3DS, Nintendo Wii  
- **Web Browsers** - Chrome, Firefox, Safari, Edge, Opera  
- **Web Servers** - Apache, nginx, IIS, lighttpd  
- **Network Tools** - wget, curl, various crawlers and bots  
- **Legacy Systems** - Older Windows versions, Unix variants  

*Based on signatures available in the p0f database. See [huginn-net-db/config/p0f.fp](huginn-net-db/config/p0f.fp) for complete signature list.*

## Advanced Features

### Multi-Protocol Support
- **TCP SYN/SYN+ACK** fingerprinting for OS detection
- **HTTP Request/Response** analysis for application identification
- **TLS ClientHello** analysis with JA4 fingerprinting for client identification, including the stable variant `JA4_s1` / `JA4_s1r`
- **MTU Discovery** for link type detection
- **Uptime Estimation** from TCP timestamps (limited accuracy on modern systems)
- **Custom Signature Databases** - bring your own signatures or contribute to the shared database

### Packet Filtering

Optional packet filtering by port and/or IP address for improved performance. Filters are applied before full packet parsing, reducing CPU overhead. Available across all crates. See [Examples & Tutorials](examples/README.md) for usage.

### Matching Quality

Each match gets a quality score based on the **distance** between the observed packet and the closest known signature. A richer database means better scores.

#### Quality Metrics
- **Perfect Match (1.0)**: Exact signature match with zero distance
- **High Quality (0.8-0.95)**: Very close match with minimal differences
- **Medium Quality (0.6-0.8)**: Good match with some variations
- **Low Quality (0.4-0.6)**: Acceptable match but with notable differences
- **Poor Quality (<0.4)**: Weak match, use with caution

### TLS JA4 Fingerprinting

This implementation follows the official [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4) for TLS client fingerprinting. For full attribution and licensing details, please see the [Attribution](#attribution) section. We do not implement JA4+ components which are under FoxIO License 1.1.

## Companion Projects

### Network Scanning & Testing

For visual analysis and experimentation, use our companion web application:

**[huginn-net-profiler: Passive Network Profile Analyzer](https://github.com/biandratti/huginn-net-profiler)**

Features:
- Real-time fingerprint visualization
- Interactive signature database exploration
- Custom pattern testing and validation

### Reverse Proxy

**Experimental**, Not yet ready for production use:

**[huginn-proxy: High-Performance Reverse Proxy with Fingerprinting](https://github.com/biandratti/huginn-proxy)** *(Currently in active development)*

Features:
- TLS termination with ALPN support
- Automatic fingerprint extraction (JA4, Akamai HTTP/2)
- Fingerprint injection as HTTP headers (`x-huginn-net-ja4`, `x-huginn-net-akamai`)
- Load balancing and path-based routing

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for detailed information on how to get started.

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
