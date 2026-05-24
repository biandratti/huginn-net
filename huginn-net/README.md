<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="200"/>
  
  # huginn-net

  [![docs](https://docs.rs/huginn-net/badge.svg)](https://docs.rs/huginn-net)
  [![crates.io](https://img.shields.io/crates/v/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![Downloads](https://img.shields.io/crates/d/huginn-net.svg)](https://crates.io/crates/huginn-net)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **Multi-protocol passive fingerprinting library: TCP/HTTP (p0f-style) + TLS (JA4) analysis.**
</div>

This is the main orchestrator crate that combines all protocol analyzers into a unified interface.

## Why choose huginn-net?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Multi-protocol support** - TCP, HTTP, and TLS analysis in one unified interface
- **Pure Rust implementation** - No system libraries required
- **High performance** - TCP: 1.25M pps, HTTP: 562.1K pps, TLS: 84.6K pps (measured with `full`; fewer features enabled means higher throughput)
- **Same accuracy as p0f** - Validated against extensive device testing
- **Type-safe architecture** - Prevents entire classes of bugs at compile time
- **Production-ready parallel processing** - Use protocol-specific crates with multi-threaded worker pools for high-throughput live capture
- **Typed observable data access** - Access to typed TCP signatures, HTTP headers, TLS extensions, and other observable signals for custom fingerprinting and analysis
- **Extensible fingerprinting** - Build custom fingerprints using typed observable data (`ObservableTcp`, `ObservableHttpRequest/Response`, `ObservableTlsClient`) without being limited to predefined signatures

## Quick Start

### Installation

Add to your `Cargo.toml`. Every feature is **opt-in** in v2.0.0; the
fastest path is `features = ["full"]`, which pulls in every analysis this
version offers (and any added in future 2.x releases):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = ["full"] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

### Cargo Features

All features are **opt-in** (default = `[]`). Pick the analyses you actually
consume, or use `full` to opt into everything this version offers:

| Feature | Default | Description |
|---------|---------|-------------|
| `full` | No | Convenience alias for "everything this version offers" (currently `db` + every `tcp-*` + every `http-*` + `tls-stable-v1`). Stable across version upgrades; additions land here automatically. |
| `db` | No | Pulls in `huginn-net-db` and enables p0f signature matching for TCP and HTTP. Combine with any `tcp-*` / `http-*` for labelled output; omit for an observation-only build (raw signatures + JA4, no database). |
| `tcp-syn` | No | Pass-through for `huginn-net-tcp/syn`: TCP SYN fingerprinting (`FingerprintResult::tcp_syn`). |
| `tcp-syn-ack` | No | Pass-through for `huginn-net-tcp/syn-ack`: TCP SYN+ACK fingerprinting (`FingerprintResult::tcp_syn_ack`). |
| `tcp-mtu` | No | Pass-through for `huginn-net-tcp/mtu`: MTU detection (`FingerprintResult::tcp_mtu`). |
| `tcp-uptime` | No | Pass-through for `huginn-net-tcp/uptime`: uptime estimation for both client and server (`FingerprintResult::tcp_client_uptime` / `tcp_server_uptime`). |
| `http-p0f-request` | No | Pass-through for `huginn-net-http/p0f-request`: HTTP request fingerprinting (`FingerprintResult::http_request`, `HttpRequestOutput`, `Browser`, `BrowserQualityMatched`). |
| `http-p0f-response` | No | Pass-through for `huginn-net-http/p0f-response`: HTTP response fingerprinting (`FingerprintResult::http_response`, `HttpResponseOutput`, `WebServer`, `WebServerQualityMatched`). |
| `tls-stable-v1` | No | Adds `JA4_s1` / `JA4_rs1` fingerprints; ephemeral extensions excluded for stable fingerprints. |
| `json` | No | Derives `serde::Serialize` on all output types (`FingerprintResult` and its fields). Enables JSON serialization via `serde_json`. Independent of `full` — opt in explicitly: `features = ["full", "json"]`. |

Each `tcp-*` / `http-*` feature gates the corresponding field on
`FingerprintResult` at compile time. Disabling one shrinks the result
struct and lets the parser skip its work (the TCP layer also early-exits
when no enabled feature consumes a packet's side; the HTTP layer short-
circuits flow tracking when both p0f sides are disabled).

Everything this version offers (forward-compatible; future analyses land
in `full` automatically):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = ["full"] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

Opt into only what you need (example: SYN-only, no MTU / uptime / SYN+ACK, both HTTP sides):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = [
    "db", "tcp-syn", "http-p0f-request", "http-p0f-response",
] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

Drop one of the HTTP sides (example: full TCP + request-only HTTP):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = [
    "db", "tcp-syn", "tcp-syn-ack", "tcp-mtu", "tcp-uptime", "http-p0f-request",
] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

Observation-only build (no database, no p0f matching; useful for TLS terminators, sidecars, or custom matchers):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = [
    "tcp-syn", "tcp-syn-ack", "tcp-mtu", "tcp-uptime",
    "http-p0f-request", "http-p0f-response",
] }
```

With `db` disabled, use `HuginnNet::new_observable(max_connections, None)` instead of `HuginnNet::new(...)`.

When `tls-stable-v1` is enabled (included by the `full` alias), `TlsClient` output gains two extra lines:

```text
  JA4_s1:  t13d1416h2_8daaf6152771_b0da82dd1658
  JA4_s1r: t13d1416h2_002f,0035,009c,009d,1301,1302,1303_000a,000b,000d,0012,002b,0033,002d
```

### Examples & Tutorials

**[Complete Usage Guide](../examples/README.md)** - Detailed examples with:
- **Live network capture** - Real-time analysis
- **PCAP file analysis** - Offline traffic analysis  
- **Protocol-specific examples** - TCP, HTTP, TLS focused analysis

### Basic Usage, with database (TCP + HTTP + TLS)

Because `HuginnNet<'a>` borrows from `Database`, the typical pattern is to
load the database and create the analyzer **inside the capture thread**,
so the borrow lives for the whole capture loop:

```rust
use huginn_net::{Database, FilterConfig, FingerprintResult, HuginnNet, PortFilter, SubnetFilter};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<FingerprintResult>();

    std::thread::spawn(move || {
        // Load p0f database inside the thread; the analyzer borrows from it
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("Failed to load database: {e}");
                return;
            }
        };

        let mut analyzer = match HuginnNet::new(Some(&db), 1000, None) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to create analyzer: {e}");
                return;
            }
        };

        // Optional: Configure filters (can be combined)
        if let Ok(subnet_filter) = SubnetFilter::new().allow("192.168.1.0/24") {
            let filter = FilterConfig::new()
                .with_port_filter(PortFilter::new().destination(443))
                .with_subnet_filter(subnet_filter);
            analyzer = analyzer.with_filter(filter);
        }

        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }

        // Or PCAP analysis:
        // if let Err(e) = analyzer.analyze_pcap("traffic.pcap", sender, None) {
        //     eprintln!("Analysis error: {e}");
        // }
    });

    for result in receiver {
        if let Some(tcp_syn)            = result.tcp_syn            { println!("{tcp_syn}"); }
        if let Some(tcp_syn_ack)        = result.tcp_syn_ack        { println!("{tcp_syn_ack}"); }
        if let Some(tcp_mtu)            = result.tcp_mtu            { println!("{tcp_mtu}"); }
        if let Some(tcp_client_uptime)  = result.tcp_client_uptime  { println!("{tcp_client_uptime}"); }
        if let Some(tcp_server_uptime)  = result.tcp_server_uptime  { println!("{tcp_server_uptime}"); }
        if let Some(http_request)       = result.http_request       { println!("{http_request}"); }
        if let Some(http_response)      = result.http_response      { println!("{http_response}"); }
        if let Some(tls_client)         = result.tls_client         { println!("{tls_client}"); }
    }

    Ok(())
}
```

### Basic Usage, observation only (no database)

If you build without the `db` feature (the v2.0.0 default omits it), the
`HuginnNet::new(...)` constructor is **not compiled**. Use
`HuginnNet::new_observable` instead to get raw TCP/HTTP signatures + JA4
with all `*QualityMatched` fields set to `Disabled`:

```rust
// Requires `huginn-net` to be declared *without* the `db` feature in your
// Cargo.toml, e.g. `features = ["tcp-syn", "http-p0f-request"]`.
use huginn_net::{FingerprintResult, HuginnNet};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<FingerprintResult>();

    std::thread::spawn(move || {
        let mut analyzer = match HuginnNet::new_observable(1000, None) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to create analyzer: {e}");
                return;
            }
        };

        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for result in receiver {
        if let Some(tls_client) = result.tls_client { println!("{tls_client}"); }
    }

    Ok(())
}
```

For complete working examples with signal handling, error management, and CLI options, see [`examples/capture.rs`](../examples/capture.rs).

### Filtering

The library supports packet filtering to reduce processing overhead and focus on specific traffic. Filters can be combined using AND logic (all conditions must match):

**Filter Types:**
- **Port Filter**: Filter by TCP source/destination ports (supports single ports, lists, and ranges)
- **IP Filter**: Filter by specific IPv4/IPv6 addresses (supports source-only, destination-only, or both)
- **Subnet Filter**: Filter by CIDR subnets (supports IPv4 and IPv6)

All filters support both Allow (allowlist) and Deny (denylist) modes. See the [filter documentation](https://docs.rs/huginn-net/latest/huginn_net/filter/index.html) for complete details.

> **Note:** This crate provides sequential (single-threaded) analysis for all protocols. For production high-throughput scenarios, use the protocol-specific crates (`huginn-net-tcp`, `huginn-net-http`, `huginn-net-tls`) with their optimized parallel processing modes.

### Example Output

```text
[TCP SYN] 1.2.3.4:1524 → 4.3.2.1:80
  OS:     Windows XP
  Dist:   8
  Params: none
  Sig:    4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0

[TCP SYN+ACK] 4.3.2.1:80 → 1.2.3.4:1524
  OS:     Linux 3.x
  Dist:   0
  Params: none
  Sig:    4:64+0:0:1460:mss*10,0:mss,nop,nop,sok:df:0

[TCP MTU] 1.2.3.4:1524 → 4.3.2.1:80
  Link:   DSL
  MTU:    1492

[TCP Uptime - Client] 1.2.3.4:1524 → 4.3.2.1:80
  Uptime: 0 days, 11 hrs, 16 min (modulo 198 days)
  Freq:   250.00 Hz

[TCP Uptime - Server] 4.3.2.1:80 → 1.2.3.4:1524
  Uptime: 12 days, 5 hrs, 32 min (modulo 198 days)
  Freq:   100.00 Hz

[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox:10.x or newer
  Lang:    English
  Params:  none
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/

[HTTP Response] 192.168.1.22:58494 → 91.189.91.21:80
  Server:  nginx/1.14.0 (Ubuntu)
  Params:  anonymous
  Sig:     server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:

[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
  SNI:     www.google.com
  Version: TLS 13
  JA4:     t13d1516h2_8daaf6152771_d8a2da3f94cd
  JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
  JA4_o:   t13d1516h2_acb858a92679_b0dc76ca1c15
  JA4_or:  t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0023,0017,001b,0012,000a,0000,fe0d,44cd,000d,ff01,0005,002b,000b,002d,0010,0033_0403,0804,0401,0503,0805,0501,0806,0601
  JA4_s1:  t13d1515h2_8daaf6152771_31ec0a762479
  JA4_s1r: t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

## Protocol-Specific Crates

For production deployments or high-throughput scenarios, use the protocol-specific crates with optimized parallel processing:

| Crate | Purpose | Parallel Support | Best For |
|-------|---------|------------------|----------|
| **[huginn-net-tcp](../huginn-net-tcp/README.md)** | TCP/OS fingerprinting (p0f-style) | Source IP hash routing | Live capture, connection tracking |
| **[huginn-net-http](../huginn-net-http/README.md)** | HTTP browser/server detection | Flow-based hash routing | Live capture, request/response matching |
| **[huginn-net-tls](../huginn-net-tls/README.md)** | TLS/JA4 fingerprinting | Round-robin dispatch | Live capture, stateless processing |

**Performance Notes:**
> **When to use `huginn-net`:** Quick prototyping, general analysis, PCAP file analysis, or when you need all protocols analyzed simultaneously. For production systems analyzing live network traffic at high rates (1+ Gbps), use the protocol-specific crates with parallel mode.

## Documentation

For complete documentation, examples, and usage guides, see the [main repository](https://github.com/biandratti/huginn-net).

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE) or [MIT license](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) at your option.
