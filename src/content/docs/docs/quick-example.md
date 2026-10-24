---
title: Quick Example
description: Quick examples for using Huginn Net ecosystem crates.
---

Short programs for each crate. The version tokens are filled from crates.io.

- `huginn-net`: TCP, HTTP, and TLS. The `db` feature pulls `huginn-net-db`.
- `huginn-net-tcp` plus `huginn-net-db`: OS labels.
- `huginn-net-http` plus `huginn-net-db`: browser and server labels.
- `huginn-net-tls`: JA4. No database.

Live capture needs `libpcap`. `analyze_pcap` does not.

## TCP, HTTP, and TLS

`full` is every analysis this version ships, including `db`.

```toml
[dependencies]
huginn-net = { version = "{{huginn-net}}", features = ["full"] }
```

SYN plus both HTTP sides, without MTU, uptime, SYN+ACK, or `JA4_s1`:

```toml
[dependencies]
huginn-net = { version = "{{huginn-net}}", features = [
    "db", "tcp-syn", "http-p0f-request", "http-p0f-response",
] }
```

Add `json` to serialize results with `serde_json` (independent of `full`):

```toml
huginn-net = { version = "{{huginn-net}}", features = ["full", "json"] }
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

Leave `db` out of the feature list. `HuginnNet::new` is not compiled. `HuginnNet::new_observable` returns raw TCP and HTTP signatures and JA4. Label fields stay disabled.

```toml
[dependencies]
huginn-net = { version = "{{huginn-net}}", features = ["tcp-syn", "tls-stable-v1"] }
```

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

## TCP (`huginn-net-tcp`)

OS labels need `huginn-net-db`. Omit the matcher if you only want the signature string.

```toml
[dependencies]
huginn-net-tcp = { version = "{{huginn-net-tcp}}", features = ["full"] }
huginn-net-db  = { version = "{{huginn-net-db}}", features = ["tcp"] }
```

Common opt-in patterns:

```toml
# Connecting clients only. No MTU, no uptime, no ttl_cache.
huginn-net-tcp = { version = "{{huginn-net-tcp}}", features = ["syn"] }

# Fingerprint servers you connect to, with MTU detection
huginn-net-tcp = { version = "{{huginn-net-tcp}}", features = ["syn-ack", "mtu"] }
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

## HTTP (`huginn-net-http`)

Browser and server labels need `huginn-net-db`. Omit the matcher if you only want the signature string.

```toml
[dependencies]
huginn-net-http = { version = "{{huginn-net-http}}", features = ["full"] }
huginn-net-db   = { version = "{{huginn-net-db}}", features = ["http"] }
```

Common opt-in patterns:

```toml
# Client-side only (request fingerprinting), no Akamai, no response parsing
huginn-net-http = { version = "{{huginn-net-http}}", features = ["p0f-request"] }

# Akamai HTTP/2 only. The p0f path is not compiled in.
huginn-net-http = { version = "{{huginn-net-http}}", features = ["akamai"] }
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

## TLS (`huginn-net-tls`)

JA4 is computed from the ClientHello. There is no database.

```toml
# Core JA4 fingerprinting
huginn-net-tls = "{{huginn-net-tls}}"

# With stable fingerprints (JA4_s1 / JA4_rs1) and everything this version offers
huginn-net-tls = { version = "{{huginn-net-tls}}", features = ["full"] }
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
| `PortFilter` | TCP source and destination ports: one port, a list, or a range |
| `IpFilter` | IPv4 or IPv6 addresses. Source, destination, or both. |
| `SubnetFilter` | CIDR subnets, IPv4 and IPv6 |

All filters support **Allow** (allowlist) and **Deny** (denylist) modes.

```rust
use huginn_net_tcp::{FilterConfig, FilterMode, IpFilter, PortFilter, SubnetFilter};

// Allow only traffic to port 443 from a specific subnet
let filter = FilterConfig::new()
    .with_port_filter(PortFilter::new().destination(443))
    .with_subnet_filter(SubnetFilter::new().allow("10.0.0.0/8")?);

// Drop traffic whose source is 1.2.3.4. Deny is a mode on FilterConfig.
// IpFilter lists the addresses; source_only() ignores the destination.
let filter = FilterConfig::new()
    .mode(FilterMode::Deny)
    .with_ip_filter(IpFilter::new().allow("1.2.3.4")?.source_only());
```

## Key Differences

- `huginn-net-tcp` and `huginn-net-http` take a matcher with `.with_matcher(...)`. Without one, the signature is still produced and the OS or browser field stays empty.
- `huginn-net-tls` has no matcher. JA4 comes from the ClientHello.
- `huginn-net` with `db` uses `HuginnNet::new`. Without `db`, use `HuginnNet::new_observable`.
- A protocol crate does not parse the other protocols. `huginn-net-tcp`, `huginn-net-http`, and `huginn-net-tls` take `with_parallel(num_workers, queue_size, batch_size, timeout_ms)` before `analyze_network` or `analyze_pcap`. `huginn-net` has no worker pool.