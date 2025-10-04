# huginn-net-http

HTTP fingerprinting and browser detection for Huginn Net.

## Overview

This crate provides HTTP-based passive fingerprinting capabilities. It analyzes HTTP/1.x and HTTP/2 headers to identify browsers, web servers, and detect preferred languages.

## Features

- **Browser Detection** - Identify browsers from HTTP request headers
- **Web Server Detection** - Identify servers from HTTP response headers
- **Language Detection** - Extract preferred languages from Accept-Language headers
- **HTTP/1.x & HTTP/2** - Support for both major HTTP versions
- **Quality Scoring** - Confidence metrics for all matches

## Usage

```rust
use huginn_net_http::{HuginnNetHttp, Database};

let db = Database::load_default()?;
let mut analyzer = HuginnNetHttp::new(Some(&db), 1000)?;

// Analyze network interface
analyzer.analyze_network("eth0", sender, None)?;
```

## Documentation

For complete documentation, examples, and integration guides, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
