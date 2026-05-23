<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-db

  [![docs](https://docs.rs/huginn-net-db/badge.svg)](https://docs.rs/huginn-net-db)
  [![crates.io](https://img.shields.io/crates/v/huginn-net-db.svg)](https://crates.io/crates/huginn-net-db)
  [![Downloads](https://img.shields.io/crates/d/huginn-net-db.svg)](https://crates.io/crates/huginn-net-db)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)
  [![CI](https://github.com/biandratti/huginn-net/actions/workflows/ci.yml/badge.svg?branch=master)](#ci)
  [![Security](https://github.com/biandratti/huginn-net/actions/workflows/audit.yml/badge.svg?branch=master)](#security)
  [![Pure Rust](https://img.shields.io/badge/pure-Rust-brightgreen.svg)](https://deps.rs/repo/github/biandratti/huginn-net)

  **P0f database parser and matching engine for Huginn Net.**
</div>

## Overview

This crate provides p0f database parsing and signature matching capabilities. It handles parsing of p0f signature databases and provides efficient matching algorithms for TCP and HTTP fingerprinting.

**Note**: `huginn-net-db` depends on `huginn-net-tcp` and `huginn-net-http`
(via Cargo features) and provides the bridge between them and a p0f-style
signature database. When using the umbrella `huginn-net` crate, this is
pulled in automatically through its `db` feature (included in the
umbrella's `full` alias). You only need to depend on `huginn-net-db`
directly if you use `huginn-net-tcp` / `huginn-net-http` standalone and
want database-backed matching.

## Features

- **P0f Database Parsing** - Complete parser for p0f signature format
- **TCP & HTTP Matching** - Efficient signature matching algorithms  
- **Quality Scoring** - Distance-based quality metrics for matches
- **Extensible Design** - Easy to add new signature types

## Cargo Features

All features are **opt-in** (default = `[]`). Pick the protocol(s) you
actually consume, or use `full` to opt into everything this version offers.

| Feature | Default | Description |
|---------|---------|-------------|
| `full`  | No      | Convenience alias for "everything this version offers" (currently `tcp` + `http`). Stable across version upgrades. |
| `tcp`   | No      | Pulls in `huginn-net-tcp` and exposes `TcpDatabase`, `TcpSignatureMatcher`, `SharedTcpSignatureMatcher`, the `[tcp:*]` p0f parser branch, and TCP signal matching impls. |
| `http`  | No      | Pulls in `huginn-net-http` and exposes `HttpDatabase`, `HttpSignatureMatcher`, `SharedHttpSignatureMatcher`, the `[http:*]` p0f parser branch, and HTTP signal matching impls. |

The composite `Database` type and the `from_database(&db)` helpers on
`SharedTcpSignatureMatcher` / `SharedHttpSignatureMatcher` are only
available when **both** features are enabled. Partial builds (e.g.
`features = ["tcp"]`) expose only the single-protocol `TcpDatabase` /
`HttpDatabase` and the matching `new(Arc<...>)` constructors.

Both protocols (composite `Database` available):

```toml
[dependencies]
huginn-net-db = { version = "2.0.0", features = ["full"] }
```

TCP-only build:

```toml
[dependencies]
huginn-net-db = { version = "2.0.0", features = ["tcp"] }
```

## Usage

Typical use is to build a `SharedTcpSignatureMatcher` /
`SharedHttpSignatureMatcher` from the bundled p0f database and plug it
into a standalone analyzer via `.with_matcher(...)`:

```rust
use huginn_net_db::{Database, SharedTcpSignatureMatcher};
use huginn_net_tcp::{HuginnNetTcp, SharedTcpMatcher};
use std::sync::Arc;

let db = Database::load_default()?;
let matcher: SharedTcpMatcher = Arc::new(SharedTcpSignatureMatcher::from_database(&db));
let analyzer = HuginnNetTcp::new(1000).with_matcher(matcher);
# Ok::<_, Box<dyn std::error::Error>>(())
```

## Documentation

For complete documentation and usage examples, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).