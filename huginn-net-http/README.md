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

This crate fingerprints HTTP traffic passively in two ways:

- **p0f-style signatures** from HTTP/1.x and HTTP/2 headers: browser, web server and
  preferred language. They only apply to plain HTTP: p0f signatures are HTTP/1, and
  encrypted traffic can't be read.
- **Akamai HTTP/2 fingerprints** from the client's connection frames (SETTINGS,
  WINDOW_UPDATE, PRIORITY and pseudo-header order), following the
  [Blackhat EU 2017 paper](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf).
  For HTTPS this needs the TLS keys, from a key log or inside a proxy.

### Why choose huginn-net-http?

- **No third-party tools** - No tshark, wireshark, or external tools required
- **Pure Rust implementation** - No system libraries required
- **High performance** - 562.1K pps for full analysis, 200M pps detection (fewer features enabled means higher throughput)
- **Typed observable data** - Headers, header order and languages (`ObservableHttpRequest`, `ObservableHttpResponse`) for your own fingerprints

## Features

- **Browser and web server detection** - p0f signatures on request and response headers
- **Language detection** - From `Accept-Language`
- **UA vs observed OS** - Compares the User-Agent OS with an `ObservedOsSource` you plug in (`with_observed_os`). The [umbrella crate](../huginn-net/README.md) with `db` + `tcp-syn` feeds it the connection's SYN.
- **Akamai HTTP/2** - Standalone extractor, cleartext h2c, and HTTP/2 over TLS with a key log
- **Parallel processing** - Worker pool for live capture; both directions of a connection go to the same worker
- **Sequential mode** - For PCAP files and low-resource environments

## Quick Start

> **Note:** Live packet capture requires `libpcap` (usually pre-installed on Linux/macOS).

### Installation

```toml
[dependencies]
huginn-net-http = { version = "2.2.1", features = ["full"] }
# Optional: browser/server matching with the bundled p0f database (HTTP half only).
huginn-net-db = { version = "2.2.1", features = ["http"] }
```

### Cargo Features

All features are opt-in (default = `[]`). A disabled feature removes its code and its field
on `HttpAnalysisResult`.

| Feature            | Description |
|--------------------|-------------|
| `full`             | Everything this version offers. New features are added here. |
| `p0f-request`      | Request signatures and browser matching (`http_request`). |
| `p0f-response`     | Response signatures and web server matching (`http_response`). |
| `akamai`           | Standalone Akamai API (`Http2FingerprintExtractor`, `extract_akamai_fingerprint*`) for callers that already have the HTTP/2 bytes, e.g. a TLS-terminating proxy. |
| `akamai-cleartext` | Akamai fingerprint for each cleartext HTTP/2 (h2c) connection in the packet pipeline (`http_akamai`). |
| `akamai-keylog`    | Akamai fingerprint for HTTP/2 over TLS, decrypted with a TLS key log (`with_keylog`). Adds `aes-gcm`, `chacha20poly1305`, `hkdf`, `hmac`, `zeroize`. |
| `json`             | `serde::Serialize` on all output types. |

```toml
# Only client-side p0f signatures
huginn-net-http = { version = "2.2.1", features = ["p0f-request"] }

# Only the standalone Akamai extractor, no packet pipeline cost
huginn-net-http = { version = "2.2.1", features = ["akamai"] }
```

### Basic Usage

```rust
use huginn_net_db::{HttpDatabase, SharedHttpSignatureMatcher};
use huginn_net_http::{
    FilterConfig, HttpAnalysisResult, HuginnNetHttp, PortFilter, SharedHttpMatcher,
};
use std::sync::{mpsc, Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_db = Arc::new(HttpDatabase::load_default()?);
    let matcher: SharedHttpMatcher = Arc::new(SharedHttpSignatureMatcher::new(http_db));

    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();
    std::thread::spawn(move || {
        // Without `with_matcher` you still get the signatures; match quality is `Disabled`.
        let mut analyzer = HuginnNetHttp::new(1000)
            .with_matcher(matcher)
            .with_filter(FilterConfig::new().with_port_filter(PortFilter::new().destination(80)));
        // Or analyzer.analyze_pcap("capture.pcap", sender, None)
        if let Err(e) = analyzer.analyze_network("eth0", sender, None) {
            eprintln!("Analysis error: {e}");
        }
    });

    for result in receiver {
        if let Some(request) = result.http_request { println!("{request}"); }
        if let Some(response) = result.http_response { println!("{response}"); }
        if let Some(akamai) = result.http_akamai { println!("{akamai}"); }
    }
    Ok(())
}
```

A complete example with signal handling and CLI options: [`examples/cli-http.rs`](../examples/cli-http.rs).

### Akamai HTTP/2

If you already have the decrypted HTTP/2 bytes (for example in a proxy), feed them to the
extractor as they arrive. It returns the fingerprint once the first request HEADERS is in:

```rust
use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;

let mut extractor = Http2FingerprintExtractor::new();
if let Some(fp) = extractor.add_bytes(&bytes)? {
    println!("{}", fp.fingerprint);
}
```

From captured traffic, enable `akamai-cleartext` for h2c, and for HTTPS give the analyzer a
TLS key log (`SSLKEYLOGFILE` format, [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html)):

```rust
use huginn_net_http::{HuginnNetHttp, KeylogConfig, KeylogSource};

// File: read once (PCAP). Follow: keep reading new lines (live capture).
let config = KeylogConfig::new(KeylogSource::Follow("/var/run/proxy/keys.log".into()));
let mut analyzer = HuginnNetHttp::new(1000).with_keylog(config)?;
// ... results arrive in `http_akamai`; counters in `analyzer.keylog_stats()`.
```

Many reverse proxies can write a key log (Envoy, HAProxy, Caddy, Apache; nginx only with a
patch), so huginn can run next to the proxy as a sidecar: it captures the same traffic and
reads the key log the proxy writes. If you would rather not deal with a key log,
[huginn-proxy](https://github.com/biandratti/huginn-proxy) computes the Akamai fingerprint
itself, since it terminates TLS.

Supported: TLS 1.2 and 1.3 with AES-GCM or ChaCha20-Poly1305. Decrypted bytes only feed the
Akamai fingerprint, never the p0f signatures.

**The key log holds live session secrets.** Anyone who can read it can decrypt that traffic:
keep it readable only by the proxy and huginn (`0600`), rotate it, and never share it with
captures. huginn wipes secrets from memory when done and never prints them.

### Filtering

Filters run before full parsing and can be combined (all must match): ports, IP addresses
and CIDR subnets, each as allow or deny list. See the
[filter documentation](https://docs.rs/huginn-net-http/latest/huginn_net_http/filter/index.html).

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

[HTTP Akamai Request] 10.0.0.2:50000 → 10.0.0.1:8443
Transport: tls1.3 decrypted (0x1301)
Sig:       1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

## Huginn Net Ecosystem

This crate is part of the Huginn Net ecosystem. For multi-protocol analysis, see **[huginn-net](../huginn-net/README.md)**. For protocol-specific analysis:
- **[huginn-net-tcp](../huginn-net-tcp/README.md)** - OS fingerprinting, MTU detection, uptime estimation
- **[huginn-net-tls](../huginn-net-tls/README.md)** - JA4 fingerprinting, TLS version detection

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
