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

This crate provides p0f database parsing and signature matching. It is the
default implementation of the [`TcpMatcher`] / [`HttpMatcher`] traits exposed
by `huginn-net-tcp` and `huginn-net-http`, but those crates are
**database-agnostic**: you can swap in your own matcher without depending on
this crate.

**Note**: When using the umbrella `huginn-net` with the default `db` feature
on, this crate is pulled in automatically. Most users do not need to depend
on it directly.

## Cargo features

| Feature | Default | Description |
|---------|---------|-------------|
| `tcp`   | Yes     | TCP signature parsing + `SharedTcpSignatureMatcher` (`TcpMatcher` impl). |
| `http`  | Yes     | HTTP signature parsing + `SharedHttpSignatureMatcher` (`HttpMatcher` impl). |

When **both** features are on, the crate also exposes a composed
[`Database`](https://docs.rs/huginn-net-db/latest/huginn_net_db/struct.Database.html)
wrapping the per-protocol databases. Disable a feature to slim the
dependency footprint when you only need one protocol.

[`TcpMatcher`]: https://docs.rs/huginn-net-tcp/latest/huginn_net_tcp/matcher_api/trait.TcpMatcher.html
[`HttpMatcher`]: https://docs.rs/huginn-net-http/latest/huginn_net_http/matcher_api/trait.HttpMatcher.html

## Features

- **P0f Database Parsing** - Complete parser for p0f signature format
- **TCP & HTTP Matching** - Efficient signature matching algorithms
- **Quality Scoring** - Distance-based quality metrics for matches
- **Extensible Design** - Easy to add new signature types

## Usage

Most consumers depend on `huginn-net`, `huginn-net-tcp`, or `huginn-net-http`
and let those crates pull `huginn-net-db` in transitively. Direct usage is
appropriate when you want raw access to the p0f parser or the
borrowed/shared matchers.

## Documentation

For complete documentation and usage examples, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).