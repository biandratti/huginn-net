# Huginn Net DB

Internal database parser and matching engine for Huginn Net.

## Overview

`huginn-net-db` is an internal crate that provides p0f signature database parsing and matching functionality for the Huginn Net ecosystem. This crate is not published separately and is only used as a dependency by other Huginn Net components.

## Features

- **P0f Database Parser** - Parses p0f signature files (`p0f.fp`)
- **Signature Matching** - Provides traits and utilities for fingerprint matching
- **Quality Scoring** - Implements quality-based matching algorithms
- **Display Formatting** - Common display traits for network analysis output

## Components

### Database Parsing
- Parses p0f signature database format
- Supports TCP, HTTP, and MTU signatures
- Handles signature labels, types, and matching rules

### Matching Engine
- Quality-based matching with distance calculations
- Configurable matching thresholds
- Support for multiple signature types

### Utilities
- Common types like `MatchQualityType`
- Display formatting traits
- Error handling for database operations

## Usage

This crate is designed for internal use within the Huginn Net workspace:

```rust
use huginn_net_db::{Database, MatchQualityType};

// Load p0f database
let db = Database::load_default()?;

// Use matching functionality
let quality = MatchQualityType::Matched(0.95);
```

## Dependencies

- **nom** - Parser combinator library for p0f file parsing
- **thiserror** - Error handling
- **tracing** - Logging and diagnostics

## License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache 2.0](../LICENSE-APACHE).
