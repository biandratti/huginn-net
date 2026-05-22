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
- **Akamai HTTP/2 Fingerprinting** - Extract Akamai fingerprints from HTTP/2 ClientHello frames (see [Akamai Fingerprinting](#akamai-http2-fingerprinting) section)

### Akamai HTTP/2 Fingerprinting

This crate includes an **Akamai HTTP/2 fingerprint parser** that extracts fingerprints from HTTP/2 connection frames (SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS) following the [Blackhat EU 2017 specification](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf).

**Important Design Consideration:**

Unlike p0f HTTP fingerprinting (which normalizes header order), **Akamai fingerprinting requires preserving the original header order** from the HTTP/2 frames. This is because:

1. The pseudo-header order (`:method`, `:path`, `:authority`, `:scheme`) is a critical component of the Akamai fingerprint
2. The order of SETTINGS parameters matters for fingerprint accuracy
3. This original ordering is essential when using Akamai fingerprints in **TLS termination scenarios** where headers must be reconstructed exactly as they appeared in the original connection

**Why it's not integrated into the main processing pipeline:**

Due to this requirement for preserving original header order, the Akamai fingerprint extractor is provided as a **standalone utility** (`Http2FingerprintExtractor`) rather than being integrated into the main HTTP processing pipeline. The main pipeline normalizes and processes headers for p0f-style fingerprinting, which would corrupt the original ordering needed for Akamai fingerprints.

**Usage:**

```rust
use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;

let mut extractor = Http2FingerprintExtractor::new();

// Add HTTP/2 data incrementally (handles connection preface automatically)
extractor.add_bytes(&http2_data)?;

if let Some(fingerprint) = extractor.get_fingerprint() {
    println!("Akamai fingerprint: {}", fingerprint.fingerprint);
    println!("Fingerprint hash: {}", fingerprint.hash);
}
```

This design allows you to extract Akamai fingerprints **before TLS termination** or in scenarios where you need to preserve the exact original frame structure, while still using the main pipeline for standard HTTP/1.x and HTTP/2 analysis with p0f-style fingerprinting.

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-http = "1.7.5"
# Optional: only needed if you want browser/server fingerprint matching.
# Skip it for an observation-only build (raw HTTP signatures, Akamai
# HTTP/2 fingerprints, etc.). With `default-features = false, features =
# ["http"]` you only pull in the HTTP half of the p0f database (no TCP
# parser, no TCP signatures embedded).
huginn-net-db = { version = "1.7.5", default-features = false, features = ["http"] }
```

### Cargo Features

All three HTTP analysis axes are **enabled by default**. Disable any to
strip the matching code paths and the corresponding fields on
`HttpAnalysisResult`:

| Feature        | Default | Description |
|----------------|---------|-------------|
| `p0f-request`  | Yes     | p0f-style fingerprinting of HTTP request side (client → server): header order, `Accept-Language`, User-Agent, browser matching. Gates `HttpRequestOutput`. |
| `p0f-response` | Yes     | p0f-style fingerprinting of HTTP response side (server → client): header order, web-server matching. Gates `HttpResponseOutput`. |
| `akamai`       | Yes     | Akamai HTTP/2 client fingerprinting from SETTINGS/WINDOW_UPDATE/PRIORITY frames. Standalone API surface (`Http2FingerprintExtractor`, `AkamaiFingerprint`, `extract_akamai_fingerprint*`); not invoked by the p0f path. |

Opt-out examples:

```toml
# Client-side only (request fingerprinting), no akamai, no response parsing.
huginn-net-http = { version = "2.0", default-features = false, features = ["p0f-request"] }

# Akamai HTTP/2 fingerprinting only — no p0f path compiled in at all.
huginn-net-http = { version = "2.0", default-features = false, features = ["akamai"] }

# Both p0f sides, no akamai.
huginn-net-http = { version = "2.0", default-features = false, features = ["p0f-request", "p0f-response"] }
```

When neither p0f side is enabled, `process_tcp_packet` short-circuits
before touching the flow cache or reassembling payloads, so an akamai-only
build pays zero per-packet cost for the p0f pipeline. The always-on raw
parsers (`parse_http1_request`, `parse_http2_request`, `Http1Processor`,
`Http2Processor`) and the `HttpMatcher` trait surface stay compiled in
every feature combination so external consumers can keep using them.

Database support is opt-in at the dependency level by adding
`huginn-net-db` and calling
[`HuginnNetHttp::with_matcher`](https://docs.rs/huginn-net-http/latest/huginn_net_http/struct.HuginnNetHttp.html#method.with_matcher).

### Basic Usage — with database (browser/server fingerprinting)

```rust
use huginn_net_db::{HttpDatabase, SharedHttpSignatureMatcher};
use huginn_net_http::{
    FilterConfig, HttpAnalysisResult, HuginnNetHttp, PortFilter, SharedHttpMatcher, SubnetFilter,
};
use std::sync::{mpsc, Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load only the HTTP half of the p0f database and build a shared matcher
    let http_db = Arc::new(HttpDatabase::load_default()?);
    let matcher: SharedHttpMatcher = Arc::new(SharedHttpSignatureMatcher::new(http_db));

    // Create analyzer with matching enabled
    let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher);

    // Optional: Configure filters (can be combined)
    if let Ok(subnet_filter) = SubnetFilter::new().allow("192.168.1.0/24") {
        let filter = FilterConfig::new()
            .with_port_filter(PortFilter::new().destination(80))
            .with_subnet_filter(subnet_filter);
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

### Basic Usage — observation only (no database)

If you don't need browser/server matching (e.g. you only consume the raw
HTTP signature, Akamai HTTP/2 fingerprint, etc.) you can skip
`huginn-net-db` entirely. Match-quality fields will report `Disabled`,
but the observable signatures are still produced.

```rust
use huginn_net_http::{HttpAnalysisResult, HuginnNetHttp, HuginnNetHttpError};
use std::sync::mpsc;

fn main() -> Result<(), HuginnNetHttpError> {
    // No matcher → observation-only mode
    let mut analyzer = HuginnNetHttp::new(1000);

    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();

    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

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
