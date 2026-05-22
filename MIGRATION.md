# Migration Guide

This document helps you migrate between versions of the `huginn-net` ecosystem that introduce breaking changes.

---

## v1.x → v2.0.0

### Summary

Architectural refactor: `huginn-net-tcp`, `huginn-net-http`, and `huginn-net-tls` no longer depend on `huginn-net-db`. The database is now an **optional layer** that depends on the protocol crates. The single `Database` is split into `TcpDatabase` and `HttpDatabase` (composed by `Database` when both are loaded). The `SignatureMatcher` types move from the protocol crates into `huginn-net-db`.

### Most users (umbrella crate `huginn-net`)

If you depend on `huginn-net` as a single crate, **most code keeps working** thanks to compatibility re-exports. The `HuginnNet::new(Some(&db), max_connections, config)` signature is unchanged:

```rust
use huginn_net::{Database, HuginnNet};

let db = Database::load_default()?;
let mut analyzer = HuginnNet::new(Some(&db), 1000, None)?; // same as v1.x
```

The most likely thing you need to update is direct imports from `huginn_net_db::tcp` / `huginn_net_db::http`:

```diff
-use huginn_net_db::tcp::{IpVersion, Ttl};
+use huginn_net_tcp::tcp::{IpVersion, Ttl};

-use huginn_net_db::http::Version;
+use huginn_net_http::http::Version;
```

Or via the umbrella (unchanged):

```rust
use huginn_net::tcp::{IpVersion, Ttl};   // still works
use huginn_net::http::Version;           // still works
```

### Direct users of `huginn-net-tcp` / `huginn-net-http`

`HuginnNetTcp::new` and `HuginnNetHttp::new` no longer accept a `Database`. Matching is configured via the new `with_matcher()` builder method.

**Before (v1.x):**

```rust
use huginn_net_tcp::HuginnNetTcp;
use huginn_net_db::Database;
use std::sync::Arc;

let db = Arc::new(Database::load_default()?);
let mut tcp = HuginnNetTcp::new(Some(db), 1000)?;
```

**After (v2.0) — full database (TCP + HTTP), with matching:**

```rust
use huginn_net_tcp::{HuginnNetTcp, SharedTcpMatcher};
use huginn_net_db::{Database, SharedTcpSignatureMatcher};
use std::sync::Arc;

let db = Database::load_default()?;
let matcher: SharedTcpMatcher = Arc::new(SharedTcpSignatureMatcher::from_database(&db));
let mut tcp = HuginnNetTcp::new(1000).with_matcher(matcher);
```

> `SharedTcpSignatureMatcher::from_database(&db)` is only available when
> `huginn-net-db` is built with both `tcp` and `http` features (the default).
> For partial builds use `SharedTcpSignatureMatcher::new(Arc<TcpDatabase>)`
> as shown below.

**After (v2.0) — TCP-only database (no HTTP signatures loaded):**

```rust
use huginn_net_tcp::{HuginnNetTcp, SharedTcpMatcher};
use huginn_net_db::{SharedTcpSignatureMatcher, TcpDatabase};
use std::sync::Arc;

let tcp_db = Arc::new(TcpDatabase::load_default()?);
let matcher: SharedTcpMatcher = Arc::new(SharedTcpSignatureMatcher::new(tcp_db));
let mut tcp = HuginnNetTcp::new(1000).with_matcher(matcher);
```

To turn off the HTTP signatures entirely (no parsing cost, no embedded data),
build `huginn-net-db` with `--no-default-features --features tcp`.

**After (v2.0) — raw signatures only, no matching, no `huginn-net-db`:**

```rust
use huginn_net_tcp::HuginnNetTcp;
let mut tcp = HuginnNetTcp::new(1000);
```

The same pattern applies to `HuginnNetHttp` — full database, HTTP-only or no
matching at all:

```rust
use huginn_net_http::{HuginnNetHttp, SharedHttpMatcher};
use huginn_net_db::{HttpDatabase, SharedHttpSignatureMatcher};
use std::sync::Arc;

let http_db = Arc::new(HttpDatabase::load_default()?);
let matcher: SharedHttpMatcher = Arc::new(SharedHttpSignatureMatcher::new(http_db));
let mut http = HuginnNetHttp::new(1000).with_matcher(matcher);
```

### Type paths moved

| Old path (v1.x) | New path (v2.0) |
|---|---|
| `huginn_net_db::tcp::{IpVersion, Ttl, WindowSize, TcpOption, Quirk, PayloadSize}` | `huginn_net_tcp::tcp::*` |
| `huginn_net_db::http::{Version, Header, HttpDiagnosis}` | `huginn_net_http::http::*` |
| `huginn_net_db::observable_signals::TcpObservation` | `huginn_net_tcp::observable::TcpObservation` |
| `huginn_net_db::observable_signals::HttpRequestObservation` | `huginn_net_http::observable::HttpRequestObservation` |
| `huginn_net_db::observable_signals::HttpResponseObservation` | `huginn_net_http::observable::HttpResponseObservation` |
| `huginn_net_tcp::SignatureMatcher` | `huginn_net_db::TcpSignatureMatcher` |
| `huginn_net_http::SignatureMatcher` | `huginn_net_db::HttpSignatureMatcher` |
| `huginn_net_tcp::db` (re-export) | removed — depend on `huginn-net-db` directly |
| `huginn_net_http::db` (re-export) | removed — depend on `huginn-net-db` directly |

### Database split

When `huginn-net-db` is built with both `tcp` and `http` features (the
default — what `huginn-net` always uses), `Database` is a composition of
`TcpDatabase` and `HttpDatabase`. Field access requires one extra hop:

| Old field (v1.x) | New path (v2.0) |
|---|---|
| `db.tcp_request`, `db.tcp_response` | `db.tcp.tcp_request`, `db.tcp.tcp_response` |
| `db.mtu` | `db.tcp.mtu` |
| `db.http_request`, `db.http_response` | `db.http.http_request`, `db.http.http_response` |
| `db.ua_os` | `db.http.ua_os` |

Load only what you need:

```rust
let tcp_db  = huginn_net_db::TcpDatabase::load_default()?;
let http_db = huginn_net_db::HttpDatabase::load_default()?;
let full_db = huginn_net_db::Database::load_default()?;  // requires both features
```

If you depend on `huginn-net-db` directly and disable one of the features
(`--no-default-features --features tcp` or `--features http`), only the
corresponding standalone database type is compiled — the composite
`Database` type and `from_database(&db)` helpers are not available. Use
`SharedTcpSignatureMatcher::new(Arc<TcpDatabase>)` /
`SharedHttpSignatureMatcher::new(Arc<HttpDatabase>)` instead.

### Constructor changes — `new()` no longer returns `Result`

`HuginnNetTcp::new` and `HuginnNetHttp::new` now return `Self` directly. They
never failed in practice, so the `Result` wrapper was misleading. (The umbrella
`HuginnNet::new` and `HuginnNet::new_observable` still return `Result` because
they validate the `database` argument against the `matcher_enabled` flag.)

```diff
-let mut tcp = HuginnNetTcp::new(Some(db), 1000)?;
+let mut tcp = HuginnNetTcp::new(1000).with_matcher(matcher);

-let mut http = HuginnNetHttp::new(Some(db), 1000)?;
+let mut http = HuginnNetHttp::new(1000).with_matcher(matcher);
```

`HuginnNetTls::new` was already infallible — no change there.

### Constructor changes — parallel mode

The old parallel-mode constructors are removed. All analyzers now follow the same
builder pattern: `new(max_connections)` for sequential mode, then optionally
`.with_parallel(...)` to enable multi-threaded processing. `.with_parallel(...)`
and `.with_matcher(...)` are independent and chainable in any order.

**`huginn-net-tcp`**

```diff
-HuginnNetTcp::with_config(num_workers, queue_size, batch_size, timeout_ms, max_connections)?
+HuginnNetTcp::new(max_connections)
+    .with_parallel(num_workers, queue_size, batch_size, timeout_ms)
+    .with_matcher(matcher) // optional
```

**`huginn-net-http`**

```diff
-HuginnNetHttp::with_config(num_workers, queue_size, batch_size, timeout_ms, max_connections)?
+HuginnNetHttp::new(max_connections)
+    .with_parallel(num_workers, queue_size, batch_size, timeout_ms)
+    .with_matcher(matcher) // optional
```

**`huginn-net-tls`**

```diff
-HuginnNetTls::with_config_and_max_connections(num_workers, queue_size, batch_size, timeout_ms, max_connections)
+HuginnNetTls::new(max_connections).with_parallel(num_workers, queue_size, batch_size, timeout_ms)
```

Sequential mode is unchanged — `new(max_connections)` alone is sufficient.

### Removed methods

The following inherent methods on TCP fingerprint types are removed in v2.0:

- `Ttl::distance_ttl(other)`
- `IpVersion::distance_ip_version(other)`
- `WindowSize::distance_window_size(other, mss)`
- `PayloadSize::distance_payload_size(other)`

If you were calling these directly, use `TcpSignatureMatcher` instead — it wraps the full matching pipeline and returns the matched OS label. If you only need the distance score for a custom matcher, the matching logic now lives as free functions inside `huginn-net-db` (internal use).

### New: optional matching in `huginn-net`

`huginn-net` gains a `db` feature, **enabled by default** for backward
compatibility. Opt out to ship a binary without the database (raw signatures
only — useful for TLS terminators, sidecars, custom matchers):

```toml
huginn-net = { version = "2.0", default-features = false }
```

With `db` disabled, the database-aware constructor `HuginnNet::new` is *not
compiled*. Use the observation-only constructor instead:

```rust
use huginn_net::HuginnNet;

let mut analyzer = HuginnNet::new_observable(1000, None)?;
```

All `*QualityMatched` fields in the resulting `FingerprintResult` will report
`MatchQuality::Disabled`, and the observable signatures (raw TCP signature,
JA4, Akamai, etc.) are produced as usual.

`huginn-net-db` itself also exposes `tcp` and `http` features (both default).
The umbrella's `db` feature pulls in **both** to preserve the v1.x feature
set; downstream consumers depending on `huginn-net-db` directly may opt into
just one.

### Cargo features summary

| Crate | New features (v2.0) |
|---|---|
| `huginn-net-tcp` | `syn` (default), `syn-ack` (default), `mtu` (default), `uptime` (default) |
| `huginn-net-http` | none (always standalone) |
| `huginn-net-tls` | `stable-v1` (unchanged) |
| `huginn-net-db` | `tcp` (default), `http` (default) |
| `huginn-net` | `db` (default), `tls-stable-v1` |

### New: optional TCP analysis features in `huginn-net-tcp`

`huginn-net-tcp` now exposes four opt-out features — all enabled by default, so existing
`Cargo.toml` entries require no change.

| Feature | What it enables | Extra dependency |
|---|---|---|
| `syn` | TCP SYN OS fingerprinting (client → server, request side) | — |
| `syn-ack` | TCP SYN+ACK OS fingerprinting (server → client, response side) | — |
| `mtu` | MTU extraction from MSS option | — |
| `uptime` | uptime estimation from TCP timestamps | `ttl_cache` |

Builds that disable `uptime` drop the `ttl_cache` dependency entirely. To opt out of one or more
features:

```toml
# Only fingerprint clients connecting to you, no MTU, no uptime, no ttl_cache dependency
huginn-net-tcp = { version = "2.0", default-features = false, features = ["syn"] }

# Recon: only fingerprint servers you connect to, with MTU detection
huginn-net-tcp = { version = "2.0", default-features = false, features = ["syn-ack", "mtu"] }

# Full OS fingerprinting, no MTU/uptime
huginn-net-tcp = { version = "2.0", default-features = false, features = ["syn", "syn-ack"] }
```

The fields on `TcpAnalysisResult` (`syn`, `syn_ack`, `mtu`, `client_uptime`, `server_uptime`) are
**gated by their respective features**. When you disable a feature, the field disappears from the
struct entirely (rather than always being `None`), reducing struct size and improving cache
locality. Consumers that construct `TcpAnalysisResult` literals or destructure exhaustively must
`#[cfg]` their code to match the enabled features.

Internally, when a build disables every feature that consumes a packet's side, `visit_tcp` returns
immediately without parsing TCP options — so SYN-only builds pay zero per-packet cost for SYN+ACK
packets, and the bare `--no-default-features` build pays only the IP-header quirks cost.

---

## v1.6.x → v1.7.0

### Summary

Added optional packet filtering system that allows filtering packets before analysis. New public APIs include `FilterConfig`, `FilterMode`, `PortFilter`, `IpFilter`, `SubnetFilter`, and the `with_filter()` method on all analyzer types.

This is an **additive change** - existing code continues to work without modification.

### Migration Steps

No migration required. Filters are optional and disabled by default. To use the new filtering features, see the README files for each crate.

---

## v1.5.2 → v1.6.0

### Summary

Renamed fields in `FingerprintResult` for consistency across all protocols. All TCP fields now use the `tcp_` prefix to match HTTP and TLS naming conventions.

**Note:** This change **only affects** the unified `huginn-net` crate. Protocol-specific crates (`huginn-net-tcp`, `huginn-net-http`, `huginn-net-tls`) remain unchanged.

### Breaking Changes

| Old Field (v1.5.2) | New Field (v1.6.0) |
|--------------------|-------------------|
| `syn` | `tcp_syn` |
| `syn_ack` | `tcp_syn_ack` |
| `mtu` | `tcp_mtu` |
| `client_uptime` | `tcp_client_uptime` |
| `server_uptime` | `tcp_server_uptime` |

### Migration Steps

**Before (v1.5.2):**
```rust
for result in receiver {
    if let Some(syn) = result.syn { println!("{syn}"); }
    if let Some(mtu) = result.mtu { println!("{mtu}"); }
    if let Some(client_uptime) = result.client_uptime { println!("{client_uptime}"); }
}
```

**After (v1.6.0):**
```rust
for result in receiver {
    if let Some(tcp_syn) = result.tcp_syn { println!("{tcp_syn}"); }
    if let Some(tcp_mtu) = result.tcp_mtu { println!("{tcp_mtu}"); }
    if let Some(tcp_client_uptime) = result.tcp_client_uptime { println!("{tcp_client_uptime}"); }
}
```

---
## Need Help?

- **Issues:** https://github.com/biandratti/huginn-net/issues
- **Examples:** https://github.com/biandratti/huginn-net/tree/master/examples
