# huginn-net-db

P0f database parser and matching engine for Huginn Net (internal crate).

## Overview

This internal crate provides p0f database parsing and signature matching capabilities. It handles parsing of p0f signature databases and provides efficient matching algorithms for TCP and HTTP fingerprinting.

**Note**: This is an internal crate and is not published to crates.io.

## Features

- **P0f Database Parsing** - Complete parser for p0f signature format
- **TCP & HTTP Matching** - Efficient signature matching algorithms  
- **Quality Scoring** - Distance-based quality metrics for matches
- **Extensible Design** - Easy to add new signature types

## Usage

This crate is used internally by other huginn-net crates and is not intended for direct use.

## Documentation

For complete documentation and usage examples, see the main [huginn-net README](https://github.com/biandratti/huginn-net#readme).

## License

Dual-licensed under [MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).