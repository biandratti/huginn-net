# Migration Guide

This document helps you migrate between versions of the `huginn-net` ecosystem that introduce breaking changes.

---

## v1.x → v2.0.0

### Summary

Architectural refactor: `huginn-net-tcp`, `huginn-net-http`, and `huginn-net-tls` no longer depend on `huginn-net-db`. The database is now an **optional layer** that depends on the protocol crates. The single `Database` is split into `TcpDatabase` and `HttpDatabase` (composed by `Database` when both are loaded). The `SignatureMatcher` types move from the protocol crates into `huginn-net-db`.

### Most users (umbrella crate `huginn-net`)

If you depend on `huginn-net` as a single crate, **most code keeps working** thanks to compatibility re-exports. The most likely thing you need to update is direct imports from `huginn_net_db::tcp` / `huginn_net_db::http`:

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

**After (v2.0) — with matching:**

```rust
use huginn_net_tcp::HuginnNetTcp;
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher};
use std::sync::Arc;

let db = Arc::new(TcpDatabase::load_default()?);
let matcher = TcpSignatureMatcher::new(db);
let mut tcp = HuginnNetTcp::new(1000)?
    .with_matcher(Arc::new(matcher));
```

**After (v2.0) — raw signatures only, no matching, no `huginn-net-db`:**

```rust
use huginn_net_tcp::HuginnNetTcp;
let mut tcp = HuginnNetTcp::new(1000)?;
```

Same pattern for `HuginnNetHttp` with `HttpDatabase` and `HttpSignatureMatcher`.

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

`Database` is now a composition of `TcpDatabase` and `HttpDatabase`. Field access requires one extra hop:

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
let full_db = huginn_net_db::Database::load_default()?;
```

### Removed methods

The following inherent methods on TCP fingerprint types are removed in v2.0:

- `Ttl::distance_ttl(other)`
- `IpVersion::distance_ip_version(other)`
- `WindowSize::distance_window_size(other, mss)`
- `PayloadSize::distance_payload_size(other)`

If you were calling these directly, use `TcpSignatureMatcher` instead — it wraps the full matching pipeline and returns the matched OS label. If you only need the distance score for a custom matcher, the matching logic now lives as free functions inside `huginn-net-db` (internal use).

### New: optional matching in `huginn-net`

`huginn-net` gains a `db` feature, **enabled by default** for backward compatibility. Opt out to ship a binary without the database (raw signatures only — useful for TLS terminators, sidecars, custom matchers):

```toml
huginn-net = { version = "2.0", default-features = false }
```

With `db` disabled, `HuginnNet::new(None, ...)` is the only constructor and all `*QualityMatched` results are `Disabled`.

### Cargo features summary

| Crate | New features (v2.0) |
|---|---|
| `huginn-net-tcp` | none (always standalone) |
| `huginn-net-http` | none (always standalone) |
| `huginn-net-tls` | `stable-v1` (unchanged) |
| `huginn-net-db` | `tcp` (default), `http` (default) |
| `huginn-net` | `db` (default), `tls-stable-v1` |

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
