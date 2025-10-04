<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-http

  [![Crates.io](https://img.shields.io/crates/v/huginn-net-http.svg)](https://crates.io/crates/huginn-net-http)
  [![Documentation](https://docs.rs/huginn-net-http/badge.svg)](https://docs.rs/huginn-net-http)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)

  **HTTP fingerprinting and browser detection for Huginn Net.**
</div>

## Overview

This crate provides HTTP-based passive fingerprinting capabilities. It analyzes HTTP/1.x and HTTP/2 headers to identify browsers, web servers, and detect preferred languages.

## Features

- **Browser Detection** - Identify browsers from HTTP request headers
- **Web Server Detection** - Identify servers from HTTP response headers
- **Language Detection** - Extract preferred languages from Accept-Language headers
- **HTTP/1.x & HTTP/2** - Support for both major HTTP versions
- **Quality Scoring** - Confidence metrics for all matches

## Quick Start

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
huginn-net-http = "1.4.6"
```

### Basic Usage

```rust
use huginn_net_http::{HuginnNetHttp, HttpAnalysisResult};
use huginn_net_db::Database;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::load_default()?;
    
    let mut analyzer = HuginnNetHttp::new(Some(&db), 1000)?;
    
    let (sender, receiver) = mpsc::channel::<HttpAnalysisResult>();
    
    let handle = thread::spawn(move || {
        analyzer.analyze_network("eth0", sender, None)
    });
    
    for result in receiver {
        if let Some(http_request) = result.http_request {
            println!("{}", http_request);
        }
        if let Some(http_response) = result.http_response {
            println!("{}", http_response);
        }
    }
    
    handle.join().unwrap()?;
    Ok(())
}
```

### Example Output

```text
.-[ 1.2.3.4/1524 -> 4.3.2.1/80 (http request) ]-
|
| client   = 1.2.3.4/1524
| app      = Firefox:10.x or newer
| lang     = English
| params   = none
| raw_sig  = 1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
`----

.-[ 192.168.1.22/58494 -> 91.189.91.21/80 (http response) ]-
|
| server   = 91.189.91.21/80
| app      = nginx/1.14.0 (Ubuntu)
| params   = anonymous
| raw_sig  = server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
`----
```

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
