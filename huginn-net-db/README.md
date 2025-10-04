<div align="center">
  <img src="https://raw.githubusercontent.com/biandratti/huginn-net/master/huginn-net.png" alt="Huginn Net Logo" width="150"/>
  
  # huginn-net-db

  [![Crates.io](https://img.shields.io/crates/v/huginn-net-db.svg)](https://crates.io/crates/huginn-net-db)
  [![Documentation](https://docs.rs/huginn-net-db/badge.svg)](https://docs.rs/huginn-net-db)
  [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/biandratti/huginn-net#license)

  **P0f database parser and matching engine for Huginn Net.**
</div>

## Overview

This crate provides p0f database parsing and signature matching capabilities. It handles parsing of p0f signature databases and provides efficient matching algorithms for TCP and HTTP fingerprinting.

**Note**: This crate is automatically included when using `huginn-net-tcp` or `huginn-net-http`. Most users don't need to use it directly.

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