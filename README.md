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

**Huginn Net fingerprints TCP, HTTP, and TLS traffic passively.** No active probes, no tshark, no wireshark. Pure Rust, built entirely on open-source specifications: p0f v3 for TCP, FoxIO's JA4 for TLS, and the Akamai HTTP/2 fingerprinting spec. All signature databases are open source and community-driven.

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
huginn-net = "2.0.0"  # Complete analysis suite
```

**For specific protocols:**
```toml
[dependencies]
huginn-net-tcp = "2.0.0"   # TCP/OS fingerprinting only
huginn-net-http = "2.0.0"  # HTTP analysis only
huginn-net-tls = "2.0.0"   # TLS/JA4 analysis only
huginn-net-db = { version = "2.0.0", features = ["tcp", "http"] }  # signature matching for TCP/HTTP (not needed for TLS)
```

### Usage & Examples

For detailed usage examples, installation guides, and complete code samples:

**📖 [Complete Usage Guide - huginn-net module](huginn-net/README.md)**

**📚 [Examples & Tutorials](examples/README.md)** - Working examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

## Performance

Huginn-net is production-ready. It handles millions of packets per second per core, scales with parallel workers, and adds no overhead from parsers or matchers you do not enable.

Unlike p0f and similar tools, single-threaded, monolithic binaries; huginn-net is a **modular Rust library** with built-in parallel processing. Cargo feature flags eliminate unused parsers at compile time, so you only pay for what you actually use, and a worker pool scales throughput across cores without any extra infrastructure.

See [benches/README.md](benches/README.md) for detailed throughput numbers, 10 Gbps capacity planning, and methodology.

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
- **HTTP/2 Akamai fingerprinting** extracts SETTINGS, WINDOW_UPDATE, PRIORITY, and pseudo-header order; used by huginn-proxy to inject fingerprints as HTTP headers
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

## Companion: huginn-proxy

**[huginn-proxy](https://github.com/biandratti/huginn-proxy)**: High-performance reverse proxy forwarding TLS (JA4), HTTP/2 (Akamai), and TCP-SYN (eBPF-powered) fingerprints as HTTP headers.

Routes incoming connections to backend services while passively extracting TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style) fingerprints and injecting them as headers. TCP SYN fingerprinting runs via an XDP/TC eBPF program.

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

- **p0f v3** ([spec](https://lcamtuf.coredump.cx/p0f3/README)): TCP SYN fingerprinting follows the p0f v3 specification by Michal Zalewski.
- **JA4** ([spec](https://github.com/FoxIO-LLC/ja4)): TLS fingerprinting follows the JA4 specification by FoxIO, LLC (BSD 3-Clause). Written from scratch; no JA4+ components (FoxIO License 1.1) are included. Copyright (c) 2023, FoxIO, LLC.
- **Akamai HTTP/2** ([spec](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)): HTTP/2 fingerprinting follows the Blackhat EU 2017 specification.
