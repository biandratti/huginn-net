---
title: Quick Example
description: Quick examples for using Huginn Net ecosystem crates.
---

This page shows quick examples for using **Huginn Net** ecosystem crates for passive fingerprinting and analysis.

Choose the approach that best fits your needs:

- **Complete Analysis** - Use `huginn-net` for multi-protocol analysis
- **TCP Only** - Use `huginn-net-tcp` for OS detection and TCP analysis
- **HTTP Only** - Use `huginn-net-http` for browser and server detection
- **TLS Only** - Use `huginn-net-tls` for JA4 fingerprinting

## Complete Multi-Protocol Analysis

Use `huginn-net` when you need comprehensive analysis across all protocols.

**Cargo.toml** — every feature is opt-in; `full` is the convenience alias for everything this version offers:

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = ["full"] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

Pick only what you need (example: SYN fingerprinting + both HTTP sides, no MTU/uptime/TLS-stable):

```toml
[dependencies]
huginn-net = { version = "2.0.0-rc", features = [
    "db", "tcp-syn", "http-p0f-request", "http-p0f-response",
] }
huginn-net-db = { version = "2.0.0-rc", features = ["full"] }
```

Add `json` to serialize results with `serde_json` (independent of `full`):

```toml
huginn-net = { version = "2.0.0-rc", features = ["full", "json"] }
```

**Usage:**

```rust
use huginn_net::{Database, FilterConfig, FingerprintResult, HuginnNet, PortFilter, SubnetFilter};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<FingerprintResult>();

    std::thread::spawn(move || {
        // Load the p0f database inside the thread (the analyzer borrows from it)
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => { eprintln!("Failed to load database: {e}"); return; }
        };

        let mut analyzer = match HuginnNet::new(Some(&db), 1000, None) {
            Ok(a) => a,
            Err(e) => { eprintln!("Failed to create analyzer: {e}"); return; }
        };

        // Optional: combine filters with AND logic
        if let Ok(subnet_filter) = SubnetFilter::new().allow("192.168.1.0/24") {
            let filter = FilterConfig::new()
                .with_port_filter(PortFilter::new().destination(443))
                .with_subnet_filter(subnet_filter);
            analyzer = analyzer.with_filter(filter);
        }

        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for result in receiver {
        if let Some(tcp_syn)           = result.tcp_syn           { println!("{tcp_syn}"); }
        if let Some(tcp_syn_ack)       = result.tcp_syn_ack       { println!("{tcp_syn_ack}"); }
        if let Some(tcp_mtu)           = result.tcp_mtu           { println!("{tcp_mtu}"); }
        if let Some(tcp_client_uptime) = result.tcp_client_uptime { println!("{tcp_client_uptime}"); }
        if let Some(tcp_server_uptime) = result.tcp_server_uptime { println!("{tcp_server_uptime}"); }
        if let Some(http_request)      = result.http_request      { println!("{http_request}"); }
        if let Some(http_response)     = result.http_response     { println!("{http_response}"); }
        if let Some(tls_client)        = result.tls_client        { println!("{tls_client}"); }
    }

    Ok(())
}
```

### Observation-only mode (no database)

Build without the `db` feature to get raw TCP/HTTP signatures + JA4 with no p0f matching. Use `HuginnNet::new_observable` instead of `HuginnNet::new`:

```rust
use huginn_net::{FingerprintResult, HuginnNet};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<FingerprintResult>();

    std::thread::spawn(move || {
        let mut analyzer = match HuginnNet::new_observable(1000, None) {
            Ok(a) => a,
            Err(e) => { eprintln!("Failed to create analyzer: {e}"); return; }
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

## TCP-Only Analysis (huginn-net-tcp)

Use `huginn-net-tcp` for OS detection, MTU calculation, and uptime estimation.

**Cargo.toml:**

```toml
[dependencies]
huginn-net-tcp = { version = "2.0.0-rc", features = ["full"] }
# Only needed for OS fingerprint matching against the p0f database
huginn-net-db = { version = "2.0.0-rc", features = ["tcp"] }
```

Common opt-in patterns:

```toml
# Fingerprint only connecting clients — no MTU, no uptime, no ttl_cache
huginn-net-tcp = { version = "2.0.0-rc", features = ["syn"] }

# Fingerprint servers you connect to, with MTU detection
huginn-net-tcp = { version = "2.0.0-rc", features = ["syn-ack", "mtu"] }
```

**Usage:**

```rust
use huginn_net_db::{SharedTcpSignatureMatcher, TcpDatabase};
use huginn_net_tcp::{
    FilterConfig, HuginnNetTcp, PortFilter, SharedTcpMatcher, SubnetFilter, TcpAnalysisResult,
};
use std::sync::{mpsc, Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load only the TCP half of the p0f database
    let tcp_db = Arc::new(TcpDatabase::load_default()?);
    let matcher: SharedTcpMatcher = Arc::new(SharedTcpSignatureMatcher::new(tcp_db));

    let mut analyzer = HuginnNetTcp::new(1000).with_matcher(matcher);

    // Optional: Filter by destination port (e.g., SSH on port 22)
    // let filter = FilterConfig::new()
    //     .with_port_filter(PortFilter::new().destination(22));
    // analyzer = analyzer.with_filter(filter);

    let (sender, receiver) = mpsc::channel::<TcpAnalysisResult>();
    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for result in receiver {
        if let Some(syn)          = result.syn          { println!("{syn}"); }
        if let Some(syn_ack)      = result.syn_ack      { println!("{syn_ack}"); }
        if let Some(mtu)          = result.mtu          { println!("{mtu}"); }
        if let Some(client_uptime)= result.client_uptime{ println!("{client_uptime}"); }
        if let Some(server_uptime)= result.server_uptime{ println!("{server_uptime}"); }
    }

    Ok(())
}
```

## HTTP-Only Analysis (huginn-net-http)

Use `huginn-net-http` for browser detection and web server identification.

**Cargo.toml:**

```toml
[dependencies]
huginn-net-http = { version = "2.0.0-rc", features = ["full"] }
# Only needed for browser/server fingerprint matching
huginn-net-db = { version = "2.0.0-rc", features = ["http"] }
```

Common opt-in patterns:

```toml
# Client-side only (request fingerprinting), no Akamai, no response parsing
huginn-net-http = { version = "2.0.0-rc", features = ["p0f-request"] }

# Akamai HTTP/2 fingerprinting only — no p0f path compiled in
huginn-net-http = { version = "2.0.0-rc", features = ["akamai"] }
```

**Usage:**

```rust
use huginn_net_db::{HttpDatabase, SharedHttpSignatureMatcher};
use huginn_net_http::{
    FilterConfig, HttpAnalysisResult, HuginnNetHttp, PortFilter, SharedHttpMatcher, SubnetFilter,
};
use std::sync::{mpsc, Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load only the HTTP half of the p0f database
    let http_db = Arc::new(HttpDatabase::load_default()?);
    let matcher: SharedHttpMatcher = Arc::new(SharedHttpSignatureMatcher::new(http_db));

    let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher);

    // Optional: Filter by HTTP port (port 80)
    // let filter = FilterConfig::new()
    //     .with_port_filter(PortFilter::new().destination(80));
    // analyzer = analyzer.with_filter(filter);

    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();
    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for result in receiver {
        if let Some(http_request)  = result.http_request  { println!("{http_request}"); }
        if let Some(http_response) = result.http_response { println!("{http_response}"); }
    }

    Ok(())
}
```

## TLS-Only Analysis (huginn-net-tls)

Use `huginn-net-tls` for JA4 fingerprinting and TLS client identification.

**Cargo.toml** — no database needed; JA4 is computed algorithmically:

```toml
# Core JA4 fingerprinting
huginn-net-tls = "2.0.0-rc"

# With stable fingerprints (JA4_s1 / JA4_s1r) and everything this version offers
huginn-net-tls = { version = "2.0.0-rc", features = ["full"] }
```

**Usage:**

```rust
use huginn_net_tls::{FilterConfig, HuginnNetTls, HuginnNetTlsError, PortFilter, SubnetFilter, TlsClientOutput};
use std::sync::mpsc;

fn main() -> Result<(), HuginnNetTlsError> {
    let mut analyzer = HuginnNetTls::new(10000);

    // Optional: Filter HTTPS traffic only (port 443)
    // if let Ok(subnet_filter) = SubnetFilter::new().allow("192.168.1.0/24") {
    //     let filter = FilterConfig::new()
    //         .with_port_filter(PortFilter::new().destination(443))
    //         .with_subnet_filter(subnet_filter);
    //     analyzer = analyzer.with_filter(filter);
    // }

    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();
    std::thread::spawn(move || {
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for tls in receiver {
        println!("{tls}");
    }

    Ok(())
}
```

## PCAP File Analysis

All crates support PCAP file analysis. Simply replace `analyze_network` with `analyze_pcap`:

```rust
// For any of the above examples, replace:
analyzer.analyze_network("eth0", sender, None)

// With:
analyzer.analyze_pcap("capture.pcap", sender, None)
```

## Filter Types

All crates share the same filter types and AND-logic combination:

| Filter | Description |
|--------|-------------|
| `PortFilter` | TCP source/destination ports — single ports, lists, and ranges |
| `IpFilter` | Specific IPv4/IPv6 addresses — source-only, destination-only, or both |
| `SubnetFilter` | CIDR subnets — IPv4 and IPv6 |

All filters support **Allow** (allowlist) and **Deny** (denylist) modes.

```rust
use huginn_net_tcp::{FilterConfig, IpFilter, PortFilter, SubnetFilter};

// Allow only traffic to port 443 from a specific subnet
let filter = FilterConfig::new()
    .with_port_filter(PortFilter::new().destination(443))
    .with_subnet_filter(SubnetFilter::new().allow("10.0.0.0/8")?);

// Deny traffic from a specific IP
let filter = FilterConfig::new()
    .with_ip_filter(IpFilter::new().deny_source("1.2.3.4")?);
```

## Key Differences

- **huginn-net-tcp** and **huginn-net-http** use `.with_matcher(matcher)` to enable database OS/browser matching; without it they run in observation-only mode (raw signatures, no labels)
- **huginn-net-tls** never needs a database — JA4 is computed from the ClientHello structure alone
- **huginn-net** combines all protocols; use `HuginnNet::new_observable(...)` when omitting the `db` feature
- Protocol-specific crates offer better performance for targeted analysis and support parallel mode for high-throughput live capture