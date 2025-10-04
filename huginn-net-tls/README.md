# huginn-net-tls

JA4 TLS client fingerprinting for Huginn Net.

## Overview

This crate provides JA4 TLS client fingerprinting capabilities for passive network analysis. It implements the official JA4 specification by FoxIO, LLC for identifying TLS clients through ClientHello analysis.

## Features

- **JA4 Fingerprinting** - Complete implementation of the official JA4 specification
- **TLS Version Support** - TLS 1.0, 1.1, 1.2, 1.3, and SSL 3.0/2.0
- **GREASE Filtering** - Proper handling of GREASE values per RFC 8701
- **SNI & ALPN** - Server Name Indication and ALPN parsing
- **Extension Analysis** - Comprehensive TLS extension parsing

## Usage

```rust
use huginn_net_tls::HuginnNetTls;

let mut analyzer = HuginnNetTls::new();

// Analyze network interface
analyzer.analyze_network("eth0", sender, None)?;
```

## JA4 Output Example

```text
JA4: t13d1516h2_8daaf6152771_b0da82dd1658
SNI: www.google.com
ALPN: h2
Version: TLS 1.3
```

## Documentation

For complete documentation, examples, and JA4 specification details, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## Attribution

This implementation follows the [JA4 specification by FoxIO, LLC](https://github.com/FoxIO-LLC/ja4). JA4 methodology and specification are Copyright (c) 2023, FoxIO, LLC.

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).