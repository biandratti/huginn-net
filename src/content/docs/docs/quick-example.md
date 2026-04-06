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

Use `huginn-net` when you need comprehensive analysis across all protocols:

```rust
use huginn_net::{Database, FilterConfig, HuginnNet, IpFilter, PortFilter};
use std::sync::mpsc;

fn main() {
    let db = Database::load_default().unwrap();
    let mut analyzer = HuginnNet::new(Some(&db), 1000, None).unwrap();

    // Optional: Configure filters (can be combined)
    // if let Ok(ip_filter) = IpFilter::new().allow("192.168.1.0/24") {
    //     let filter = FilterConfig::new()
    //         .with_port_filter(PortFilter::new().destination(443))
    //         .with_ip_filter(ip_filter);
    //     analyzer = analyzer.with_filter(filter);
    // }

    let (sender, receiver) = mpsc::channel();

    // Live capture
    std::thread::spawn(move || analyzer.analyze_network("eth0", sender, None));

    // Or PCAP analysis
    // std::thread::spawn(move || analyzer.analyze_pcap("traffic.pcap", sender, None));

    for result in receiver {
        if let Some(tcp_syn) = result.tcp_syn { println!("{}", tcp_syn); }
        if let Some(tcp_syn_ack) = result.tcp_syn_ack { println!("{}", tcp_syn_ack); }
        if let Some(tcp_mtu) = result.tcp_mtu { println!("{}", tcp_mtu); }
        if let Some(tcp_client_uptime) = result.tcp_client_uptime { println!("{}", tcp_client_uptime); }
        if let Some(tcp_server_uptime) = result.tcp_server_uptime { println!("{}", tcp_server_uptime); }
        if let Some(http_request) = result.http_request { println!("{}", http_request); }
        if let Some(http_response) = result.http_response { println!("{}", http_response); }
        if let Some(tls_client) = result.tls_client { println!("{}", tls_client); }
    }
}
```

## TCP-Only Analysis (huginn-net-tcp)

Use `huginn-net-tcp` for OS detection, MTU calculation, and uptime estimation:

```rust
use huginn_net_tcp::{FilterConfig, HuginnNetTcp, PortFilter};
use huginn_net_db::Database;
use std::sync::mpsc;

fn main() {
    let db = Database::load_default().unwrap();
    let mut analyzer = HuginnNetTcp::new(Some(&db), 1000).unwrap();

    // Optional: Filter by destination port (e.g., SSH on port 22)
    // let filter = FilterConfig::new()
    //     .with_port_filter(PortFilter::new().destination(22));
    // analyzer = analyzer.with_filter(filter);

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || analyzer.analyze_network("eth0", sender, None));

    for result in receiver {
        if let Some(syn) = result.syn { println!("{}", syn); }
        if let Some(syn_ack) = result.syn_ack { println!("{}", syn_ack); }
        if let Some(mtu) = result.mtu { println!("{}", mtu); }
        if let Some(client_uptime) = result.client_uptime { println!("{}", client_uptime); }
        if let Some(server_uptime) = result.server_uptime { println!("{}", server_uptime); }
    }
}
```

## HTTP-Only Analysis (huginn-net-http)

Use `huginn-net-http` for browser detection and web server identification:

```rust
use huginn_net_http::{FilterConfig, HuginnNetHttp, PortFilter};
use huginn_net_db::Database;
use std::sync::mpsc;

fn main() {
    let db = Database::load_default().unwrap();
    let mut analyzer = HuginnNetHttp::new(Some(&db), 1000).unwrap();

    // Optional: Filter by HTTP port (port 80)
    // let filter = FilterConfig::new()
    //     .with_port_filter(PortFilter::new().destination(80));
    // analyzer = analyzer.with_filter(filter);

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || analyzer.analyze_network("eth0", sender, None));

    for result in receiver {
        if let Some(http_request) = result.http_request { println!("{}", http_request); }
        if let Some(http_response) = result.http_response { println!("{}", http_response); }
    }
}
```

## TLS-Only Analysis (huginn-net-tls)

Use `huginn-net-tls` for JA4 fingerprinting and TLS client identification:

```rust
use huginn_net_tls::{FilterConfig, HuginnNetTls, PortFilter};
use std::sync::mpsc;

fn main() {
    let mut analyzer = HuginnNetTls::new();

    // Optional: Filter HTTPS traffic only (port 443)
    // let filter = FilterConfig::new()
    //     .with_port_filter(PortFilter::new().destination(443));
    // analyzer = analyzer.with_filter(filter);

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || analyzer.analyze_network("eth0", sender, None));

    for tls in receiver {
        println!("{}", tls);
    }
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

## Key Differences

- **huginn-net-tcp** and **huginn-net-http** require a database for signature matching
- **huginn-net-tls** works without a database (JA4 is computed algorithmically)
- **huginn-net** combines all protocols and provides unified results
- Protocol-specific crates offer better performance for targeted analysis
