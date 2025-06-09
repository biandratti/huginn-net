# Passive TCP Fingerprint<img align="right" src="passivetcp-rs.svg" height="150px" style="padding-left: 20px"/>
[![docs](https://docs.rs/passivetcp-rs/badge.svg)](https://docs.rs/passivetcp-rs)
[![crates.io](https://img.shields.io/crates/v/passivetcp-rs.svg)](https://crates.io/crates/passivetcp-rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/clippy.svg)](#license)
[![CI](https://github.com/biandratti/passivetcp-rs/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
[![codecov](https://codecov.io/github/biandratti/passivetcp-rs/graph/badge.svg?token=ZPZKFIR4YL)](https://codecov.io/github/biandratti/passivetcp-rs)

## Proven Accuracy - Production Ready

**passivetcp-rs achieves the same detection accuracy as the original p0f tool**, with excellent precision across all tested devices. This Rust implementation has been thoroughly validated against real-world traffic and consistently delivers reliable fingerprinting results.

#### Why choose passivetcp-rs?

- **Same accuracy as p0f** - Validated against extensive device testing  
- **Modern Rust implementation** - Memory safety and zero-cost abstractions  
- **Production performance** - Processes packets in ~3.1ms with comparable speed to original p0f  
- **Type-safe architecture** - Prevents entire classes of bugs at compile time  
- **Comprehensive testing** - Full unit and integration test coverage  
- **Easy integration** - Clean APIs and modular design  
- **Active development** - Continuously improved and maintained  

#### What is Passive TCP Fingerprinting?
Passive TCP Fingerprinting is a technique that allows you to infer information about a remote host's operating system and network stack without sending any probes. By analyzing characteristics of the TCP/IP packets that are exchanged during a normal network conversation, passivetcp-rs provides insights into the remote system's OS type, version, and network stack implementation.

#### Real-world applications:
- **Network Security Analysis** - Identify devices and systems without active scanning
- **Asset Discovery** - Map network infrastructure passively and safely  
- **Threat Detection** - Discover hidden or suspicious systems by their network behavior
- **Research & Forensics** - Analyze traffic patterns and improve security posture
- **Compliance Monitoring** - Track device types and OS versions across networks

## 🚀 Quick Start

### Installation
```toml
[dependencies]
passivetcp-rs = "1.0.2"
```

###  Examples & Tutorials:
[Complete usage guide with](examples/README.md):
  - Live network capture
  - PCAP file analysis

### Code Integration

```rust
use passivetcp_rs::{Database, P0f};
use std::sync::mpsc;

// Load signature database and create analyzer
let db = Box::leak(Box::new(Database::default()));
let (sender, receiver) = mpsc::channel();
let analyzer = P0f::new(db, 100);

// Analyze network traffic (choose one)
std::thread::spawn(move || {
    // Live network capture
    analyzer.analyze_network("eth0", sender);
    
    // OR PCAP file analysis
    // analyzer.analyze_pcap("traffic.pcap", sender);
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

*Based on signatures available in the p0f database. See [config/p0f.fp](config/p0f.fp) for complete signature list.*

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
- **MTU Discovery** for link type detection
- **Uptime Calculation** from TCP timestamps
- **Custom Signature Databases** with easy updates

### Matching Quality

passivetcp-rs provides intelligent quality scoring for all fingerprint matches, helping you assess the reliability of each detection.
The quality score is calculated based on the **distance** between observed network characteristics and known signatures.
To achieve the best quality in matching, a rich database will be needed.

#### Quality Metrics
- **Perfect Match (1.0)**: Exact signature match with zero distance
- **High Quality (0.8-0.95)**: Very close match with minimal differences
- **Medium Quality (0.6-0.8)**: Good match with some variations
- **Low Quality (0.4-0.6)**: Acceptable match but with notable differences
- **Poor Quality (<0.4)**: Weak match, use with caution

## Interactive Testing

For visual analysis and experimentation, use our companion web application:

**[🔗 tcp-profiler: Passive TCP Fingerprint Analyzer](https://github.com/biandratti/tcp-profiler)**

Features:
- Real-time fingerprint visualization
- Interactive signature database exploration
- Custom pattern testing and validation

## 🤝 Contributing

We welcome contributions! Areas where help is especially valuable:

### How to Contribute
1. **Database Contributions**: Add new `.fp` signatures in the `config/` directory
2. **Code Improvements**: Bug fixes, feature additions, optimizations
3. **Testing**: Validate accuracy on new device types
4. **Documentation**: Examples, tutorials, API improvements

**Your signature contributions directly improve detection accuracy for the entire community!**

## Next Milestones
-  **Extended Protocol Support** - TLS/SSL fingerprinting
-  **Enhanced Database** - Continuous signature updates
-  **Advanced Analytics** - Pattern analysis and reporting tools

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
