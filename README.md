# Passive traffic fingerprinting
[![docs](https://docs.rs/passivetcp-rs/badge.svg)](https://docs.rs/passivetcp-rs)
[![crates.io](https://img.shields.io/crates/v/passivetcp-rs.svg)](https://crates.io/crates/passivetcp-rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/clippy.svg)](#license)
[![CI](https://github.com/biandratti/passivetcp-rs/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
[![codecov](https://codecov.io/github/biandratti/passivetcp-rs/graph/badge.svg?token=ZPZKFIR4YL)](https://codecov.io/github/biandratti/passivetcp-rs)

An experimental Rust library inspired by p0f, the well-known passive OS fingerprinting tool originally written in C. This library aims to bring the power of passive TCP/IP fingerprinting to the Rust ecosystem while offering a more modern, efficient, and extensible implementation.

#### What is Passive TCP Fingerprinting?
Passive TCP fingerprinting is a technique that allows you to infer information about a remote host's operating system and network stack without sending any probes. By analyzing characteristics of the TCP/IP packets that are exchanged during a normal network conversation, passivetcp-rs provides insights into the remote system’s OS type, version, and network stack implementation.

#### This technique is useful for a variety of purposes, including:
- Network analysis: Identifying the types of devices and systems on a network without active scanning.
- Security: Discovering hidden or obscure systems by their network behavior.
- Fingerprinting for research: Understanding patterns in network traffic and improving security posture.
About passivetcp-rs

This Rust implementation of passive TCP fingerprinting is still in its experimental phase, and while it builds upon the established ideas of p0f, it is not yet feature-complete. The library currently provides basic functionality, but we plan to expand its capabilities as the project matures.

### Example
```
cargo build --release --examples
sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/p0f -i <INTERFACE> -l <LOG_FILE.LOG>
```

```text
.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (syn) ]-
|
| client   = 1.2.3.4/1524
| os       = Windows XP
| dist     = 8
| params   = none
| raw_sig  = 4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0
|
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (syn+ack) ]-
|
| server   = 4.3.2.1/80
| os       = Linux 3.x
| dist     = 0
| params   = none
| raw_sig  = 4:64+0:0:1460:mss*10,0:mss,nop,nop,sok:df:0
|
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (mtu) ]-
|
| client   = 1.2.3.4/1524
| link     = DSL
| raw_mtu  = 1492
|
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (uptime) ]-
|
| client   = 1.2.3.4/1524
| uptime   = 0 days 11 hrs 16 min (modulo 198 days)
| raw_freq = 250.00 Hz
|
`----

.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (http request) ]-
|
| client   = 1.2.3.4/1524
| app      = Firefox:10.x or newer
| lang     = English
| params   = none
| raw_sig  = 1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
|
`----

.-[ 192.168.1.22/58494 -> 91.189.91.21/80 (http response) ]-
|
| server   = 91.189.91.21/80
| app      = nginx/1.14.0 (Ubuntu)
| params   = anonymous
| raw_sig  = server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
|
`----
```

### Installation
To use passivetcp-rs in your Rust project, add the following dependency to your `Cargo.toml`:
```toml
[dependencies]
passivetcp-rs = "0.1.0-beta.1"
```

### Usage
Here’s a basic example of how to use passivetcp-rs:
```rust
use passivetcp_rs::db::Database;
use passivetcp_rs::P0f;

let args = Args::parse();
let db = Box::leak(Box::new(Database::default()));
let (sender, receiver) = mpsc::channel();

thread::spawn(move || {
    P0f::new(db, 100).analyze_network(&args.interface, sender);
});

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

### Contributing
This library is in its early stages, and contributions are very welcome. If you have ideas for additional features, bug fixes, or optimizations, please feel free to open issues or submit pull requests. We are particularly looking for help with extending the feature set and improving the performance of the library.

### License
This project is licensed under the MIT License.
