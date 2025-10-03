# Huginn Net TLS - JA4 TLS Client Fingerprinting

[![docs](https://docs.rs/huginn-net-tls/badge.svg)](https://docs.rs/huginn-net-tls)
[![crates.io](https://img.shields.io/crates/v/huginn-net-tls.svg)](https://crates.io/crates/huginn-net-tls)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](../LICENSE-APACHE)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](../LICENSE-MIT)

**TLS-focused passive fingerprinting analyzer using JA4 methodology** - A specialized component of the Huginn Net ecosystem for TLS ClientHello analysis and JA4 fingerprinting.

## Overview

`huginn-net-tls` is a dedicated crate for TLS client fingerprinting that implements the official [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4). This crate provides focused TLS analysis capabilities that can be used standalone or as part of the broader Huginn Net multi-protocol fingerprinting suite.

### Key Features

- **JA4 TLS Fingerprinting** - Complete implementation of the JA4 specification
- **No External Dependencies** - No need for tshark, Wireshark, or other external tools
- **Passive Analysis** - No active probes, works with existing network traffic
- **High Performance** - Optimized Rust implementation for production use
- **Memory Safe** - Zero-cost abstractions with compile-time safety guarantees
- **Modular Design** - Can be used independently or with other Huginn Net components

### What is JA4?

JA4 is a modern TLS client fingerprinting method that creates unique signatures from TLS ClientHello packets. It provides more reliable client identification compared to older methods like JA3, with better handling of:

- TLS version variations
- Cipher suite ordering
- Extension analysis
- GREASE value filtering

## 🚀 Quick Start

### Installation

```toml
[dependencies]
huginn-net-tls = "0.1.0"
```

### Usage

```rust
use huginn_net_tls::{HuginnNetTls, TlsClientOutput};
use huginn_net::HuginnNet;
use std::sync::mpsc;

let mut tls_analyzer = HuginnNetTls::new();
let (tls_sender, tls_receiver) = mpsc::channel();

std::thread::spawn(move || {
    tls_analyzer.analyze_network("eth0", tls_sender, None).unwrap();
});

for tls_client in tls_receiver {
    info!("{}", tls_client);
}

```

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

## Examples

### Live Network Capture

Run the included TLS-only capture example:

```bash
# Build the example
cargo build --release --examples -p huginn-net-tls

# Run with live network capture (requires root/admin privileges)
sudo ./target/release/examples/capture-tls live -i eth0

# Run with log file output
sudo ./target/release/examples/capture-tls -l tls_analysis.log live -i eth0
```

See [examples/README.md](../examples/README.md) for more detailed usage instructions.

## TLS Analysis Capabilities

### Supported TLS Features

- **TLS Versions**: 1.0, 1.1, 1.2, 1.3
- **Cipher Suites**: Complete analysis of offered cipher suites
- **Extensions**: Comprehensive extension parsing and analysis
- **SNI Extraction**: Server Name Indication field extraction
- **GREASE Handling**: Proper filtering of GREASE values per RFC 8701

### JA4 Components

The JA4 fingerprint consists of three parts:

1. **JA4**: Main fingerprint with GREASE values removed
2. **JA4_r**: Raw fingerprint including all values
3. **JA4_o**: Original order fingerprint
4. **JA4_or**: Original order raw fingerprint


## Performance

- **Processing Speed**: Optimized for high-throughput network analysis
- **Memory Usage**: Minimal memory footprint with efficient packet processing
- **Accuracy**: Implements the complete JA4 specification for reliable fingerprinting

## 📄 License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache 2.0](../LICENSE-APACHE).

### Attribution

The TLS fingerprinting in `huginn-net-tls` adheres to the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4), which is available under the BSD 3-Clause license. Our implementation was written from scratch for `huginn-net` and does not use any code from the original JA4 repository. JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.

## Related Projects

- **[huginn-net](../README.md)** - Complete multi-protocol passive fingerprinting suite
- **huginn-net-http** - HTTP protocol analysis and fingerprinting
- **huginn-net-tcp** - TCP fingerprinting and OS detection
- **huginn-net-db** - Signature database and matching engine
