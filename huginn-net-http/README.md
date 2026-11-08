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
  [![MSRV](https://img.shields.io/crates/msrv/huginn-net-http.svg)](https://crates.io/crates/huginn-net-http)

  **HTTP fingerprinting and browser detection for Huginn Net.**
</div>

## Overview

This crate provides HTTP-based passive fingerprinting capabilities. It analyzes HTTP/1.x and HTTP/2 headers to identify browsers, web servers, and detect preferred languages.

### Why choose huginn-net-http?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Comprehensive analysis** - Browser, server, and language detection
- **Pure Rust implementation** - No system libraries required
- **High performance** - 562.1K pps for full analysis, 200M pps detection (fewer features enabled means higher throughput)
- **HTTP/1.x & HTTP/2** - Support for both major protocol versions
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Typed observable data access** - Access to typed HTTP headers, header ordering, language preferences, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableHttpRequest`, `ObservableHttpResponse`) without being limited to predefined p0f signatures

## Features

- **Browser Detection** - Identify browsers from HTTP request headers
- **Web Server Detection** - Identify servers from HTTP response headers
- **Language Detection** - Extract preferred languages from Accept-Language headers
- **UA vs observed OS** - HTTP only compares if you plug an `ObservedOsSource` (`with_observed_os`). It does not see TCP. The [umbrella](../huginn-net/README.md) (`db` + `tcp-syn`) feeds this connection's SYN into `HttpRequestOutput.ua_os`.
- **HTTP/1.x & HTTP/2** - Support for both major HTTP versions
- **Quality Scoring** - Confidence metrics for all matches
- **Parallel Processing** - Multi-threaded worker pool for live network capture (high-throughput scenarios). Packets are routed by a direction-independent flow hash, so both directions of a connection are processed by the same worker.
- **Sequential Mode** - Single-threaded processing (for PCAP files and low-resource environments)
- **Akamai HTTP/2 Fingerprinting** - Akamai fingerprints from the client's HTTP/2 connection frames: standalone API, cleartext h2c, and HTTP/2 over TLS with a key log (see [Akamai Fingerprinting](#akamai-http2-fingerprinting))

### Akamai HTTP/2 Fingerprinting

This crate computes **Akamai HTTP/2 client fingerprints** from the client's connection frames (SETTINGS, WINDOW_UPDATE, PRIORITY and the pseudo-header order of the first HEADERS frame), following the [Blackhat EU 2017 specification](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf). The fingerprint depends on the original frame and header order, so it is computed from the raw frames, never from the normalized p0f view.

There are three ways to get it:

| Feature | What you get |
|---------|--------------|
| `akamai` | Standalone API (`Http2FingerprintExtractor`, `extract_akamai_fingerprint*`) for callers that already have the HTTP/2 bytes, e.g. a TLS-terminating proxy. |
| `akamai-cleartext` | The packet pipeline emits one `AkamaiOutput` per cleartext HTTP/2 (h2c) connection, prior knowledge or `Upgrade: h2c`, in `HttpAnalysisResult::http_akamai`. No cryptographic dependencies. |
| `akamai-keylog` | The packet pipeline decrypts HTTP/2 over TLS 1.2 / 1.3 with secrets from a TLS key log (`SSLKEYLOGFILE` format) and emits one `AkamaiOutput` per connection. The observer stays passive: it never terminates TLS or touches the traffic. |

Decrypted bytes only feed the Akamai fingerprint. They never reach the p0f HTTP path, and p0f results are identical with or without a key log: p0f browser and server signatures only apply to plain HTTP.

**Standalone extractor:**

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

**Packet pipeline with a key log** (`akamai-keylog`):

```rust
use huginn_net_http::{HttpAnalysisResult, HuginnNetHttp, KeylogConfig, KeylogSource};
use std::sync::mpsc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `File` reads the key log once (capture files). For live capture use
    // `KeylogSource::Follow`, which also picks up lines appended later.
    let keylog = KeylogConfig::new(KeylogSource::File("keys.log".into()))
        .pending_timeout(Duration::from_secs(2));
    let mut analyzer = HuginnNetHttp::new(1000).with_keylog(keylog)?;

    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();
    analyzer.analyze_pcap("capture.pcap", sender, None)?;

    for result in receiver.try_iter() {
        if let Some(akamai) = result.http_akamai {
            println!("{} {}", akamai.transport, akamai.fingerprint.fingerprint);
        }
    }
    println!("{:?}", analyzer.keylog_stats());
    Ok(())
}
```

A connection waits up to `pending_timeout` for its secret to show up in the key log. Connections that can't be decrypted are counted in `KeylogStats` (`no_secret`, `unsupported`, `auth_failed`, ...) and produce no output. Supported suites: TLS 1.3 `AES_128_GCM`, `AES_256_GCM`, `CHACHA20_POLY1305`, and TLS 1.2 ECDHE/RSA AES-GCM and ChaCha20-Poly1305. The accepted key log lines are described in [`keylog-format.md`](../specs/001-akamai-http2-processing/contracts/keylog-format.md).

#### Key log security

The key log contains **live session secrets**: anyone who can read it can decrypt the traffic it covers.

- Restrict the file to the TLS terminator and the observer, e.g. mode `0600` with a shared owner or group.
- Rotate it and delete old files. Follow mode handles truncation and rotation.
- Never ship it with captures you share. Secrets in huginn's memory are wiped when they are no longer needed, and secrets and decrypted bytes never appear in outputs, `Debug` or logs.

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Pick the analyses you want via `features` (see "Cargo Features" below).
# `full` is the convenience alias for "everything this version offers".
huginn-net-http = { version = "2.2.1", features = ["full"] }
# Optional: only needed if you want browser/server fingerprint matching.
# Skip it for an observation-only build (raw HTTP signatures, Akamai
# HTTP/2 fingerprints, etc.). With `features = ["http"]` you only pull in
# the HTTP half of the p0f database (no TCP parser, no TCP signatures
# embedded).
huginn-net-db = { version = "2.2.1", features = ["http"] }
```

### Cargo Features

All features are **opt-in** (default = `[]`). Pick the analyses you actually
consume, or use `full` to opt into everything this version offers:

| Feature        | Default | Description |
|----------------|---------|-------------|
| `full`         | No      | Convenience alias for "everything this version offers" (currently `p0f-request` + `p0f-response` + `akamai` + `akamai-cleartext` + `akamai-keylog`). Stable across version upgrades. |
| `p0f-request`  | No      | p0f-style fingerprinting of HTTP request side (client → server): header order, `Accept-Language`, User-Agent, browser matching. Gates `HttpRequestOutput`. |
| `p0f-response` | No      | p0f-style fingerprinting of HTTP response side (server → client): header order, web-server matching. Gates `HttpResponseOutput`. |
| `akamai`       | No      | Akamai HTTP/2 client fingerprinting from SETTINGS/WINDOW_UPDATE/PRIORITY frames. Standalone API surface (`Http2FingerprintExtractor`, `AkamaiFingerprint`, `extract_akamai_fingerprint*`); not invoked by the p0f path. |
| `akamai-cleartext` | No  | Implies `akamai`. The packet pipeline emits one `AkamaiOutput` per cleartext HTTP/2 (h2c) connection in `HttpAnalysisResult::http_akamai`. |
| `akamai-keylog` | No     | Implies `akamai`. `HuginnNetHttp::with_keylog`: decrypts HTTP/2 over TLS with a TLS key log and emits one `AkamaiOutput` per connection. Adds `aes-gcm`, `chacha20poly1305`, `hkdf`, `hmac`, `zeroize`. |
| `json`          | No      | Derives `serde::Serialize` on all output types (`HttpAnalysisResult`, `HttpRequestOutput`, `HttpResponseOutput`). Opt in explicitly: `features = ["full", "json"]`. |

Common opt-in patterns:

```toml
# Everything this version offers (forward-compatible with future axes).
huginn-net-http = { version = "2.2.1", features = ["full"] }

# Client-side only (request fingerprinting), no akamai, no response parsing.
huginn-net-http = { version = "2.2.1", features = ["p0f-request"] }

# Akamai HTTP/2 fingerprinting only, no p0f path compiled in at all.
huginn-net-http = { version = "2.2.1", features = ["akamai"] }

# Both p0f sides, no akamai.
huginn-net-http = { version = "2.2.1", features = ["p0f-request", "p0f-response"] }
```

When neither p0f side nor `akamai-cleartext` is enabled, `process_tcp_packet`
short-circuits before touching the flow cache or reassembling payloads, so the
per-packet pipeline cost drops to zero. Without `with_keylog`, the key log path
costs nothing either. The plain `akamai` feature only exposes the standalone
`Http2FingerprintExtractor` / `extract_akamai_fingerprint*` API for callers that
parse HTTP/2 frames themselves. The always-on raw parsers (`parse_http1_request`,
`parse_http2_request`, `Http1Processor`, `Http2Processor`) and the
`HttpMatcher` trait surface stay compiled in every feature combination
so external consumers can keep using them.

Database support is opt-in at the dependency level by adding
`huginn-net-db` and calling
[`HuginnNetHttp::with_matcher`](https://docs.rs/huginn-net-http/latest/huginn_net_http/struct.HuginnNetHttp.html#method.with_matcher).
To compare the User-Agent OS against a network-observed OS, plug an
[`ObservedOsSource`](https://docs.rs/huginn-net-http/latest/huginn_net_http/trait.ObservedOsSource.html)
via `with_observed_os`. HTTP does not read SYN itself. Use
[`huginn-net`](../huginn-net/README.md) with `db` + `tcp-syn` if you want
that wiring done for you. Without a source, `ua_os` is `NotChecked`.

### Basic Usage, with database (browser/server fingerprinting)

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

### Basic Usage, observation only (no database)

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

For a complete working example with signal handling, error management, and CLI options, see [`examples/cli-http.rs`](../examples/cli-http.rs).

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
  UA/OS:   not checked (no source)
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
