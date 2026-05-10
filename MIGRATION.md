# Migration Guide

This document helps you migrate between versions of the `huginn-net` ecosystem that introduce breaking changes.

---

## v1.7.x → v2.0.0

### Summary

`huginn-net-db` is no longer a hard dependency of `huginn-net-tcp`, `huginn-net-http`, or `huginn-net`.
It becomes an **opt-in Cargo feature flag** (`features = ["db"]`).

Without the `db` feature, packet capture and fingerprint extraction still work fully.
OS/browser signature matching requires opting in explicitly.

Additionally, protocol-level types that were incorrectly located inside `huginn-net-db`
(e.g. `Ttl`, `IpVersion`, `Quirk`, `Version`, `Header`) have moved to their owning crates.

---

### 1. Update `Cargo.toml`

The most common change. Add `features = ["db"]` wherever you depended on signature matching.

**`huginn-net` (unified crate):**
```toml
# Before
huginn-net = "1.7"

# After — with DB matching (same behaviour as before)
huginn-net = { version = "2.0", features = ["db"] }

# After — TCP + HTTP capture only, no matching
huginn-net = { version = "2.0" }

# After — TLS only
huginn-net = { version = "2.0", default-features = false, features = ["tls"] }
```

**`huginn-net-tcp` (standalone):**
```toml
# Before
huginn-net-tcp = "1.7"

# After — with DB matching
huginn-net-tcp = { version = "2.0", features = ["db"] }

# After — capture only, no matching
huginn-net-tcp = "2.0"
```

**`huginn-net-http` (standalone):**
```toml
# Before
huginn-net-http = "1.7"

# After — with DB matching
huginn-net-http = { version = "2.0", features = ["db"] }

# After — capture only, no matching
huginn-net-http = "2.0"
```

---

### 2. Constructor changes

The `database` parameter has been moved out of the default constructors.
There are now two constructors: one without DB and one gated behind `#[cfg(feature = "db")]`.

#### `HuginnNetTcp`

```rust
// Before (v1.7)
let db = Arc::new(Database::load_default()?);
let tcp = HuginnNetTcp::new(Some(db), 1000)?;
let tcp = HuginnNetTcp::with_config(Some(db), 1000, 4, 100, 32, 10)?;

// Without matching (Before — passing None)
let tcp = HuginnNetTcp::new(None, 1000)?;
```

```rust
// After (v2.0) — with db feature
use huginn_net_db::Database;
let db = Arc::new(Database::load_default()?);
let tcp = HuginnNetTcp::new_with_db(Some(db), 1000)?;
let tcp = HuginnNetTcp::with_config_db(Some(db), 1000, 4, 100, 32, 10)?;

// After (v2.0) — without db feature (or not using matching)
let tcp = HuginnNetTcp::new(1000)?;
let tcp = HuginnNetTcp::with_config(1000, 4, 100, 32, 10)?;
```

#### `HuginnNetHttp`

```rust
// Before (v1.7)
let http = HuginnNetHttp::new(Some(db), 1000)?;
let http = HuginnNetHttp::with_config(Some(db), 1000, 2, 100, 16, 10)?;
```

```rust
// After (v2.0) — with db feature
let http = HuginnNetHttp::new_with_db(Some(db), 1000)?;
let http = HuginnNetHttp::with_config_db(Some(db), 1000, 2, 100, 16, 10)?;

// After (v2.0) — without db feature
let http = HuginnNetHttp::new(1000)?;
let http = HuginnNetHttp::with_config(1000, 2, 100, 16, 10)?;
```

#### `HuginnNet` (unified crate)

```rust
// Before (v1.7)
let db = Database::load_default()?;
let analyzer = HuginnNet::new(Some(&db), 100, None)?;
```

```rust
// After (v2.0) — with db feature
let db = Database::load_default()?;
let analyzer = HuginnNet::new_with_db(Some(&db), 100, None)?;

// After (v2.0) — without db feature
let analyzer = HuginnNet::new(100, None)?;
```

---

### 3. Type import path changes

Protocol-level types have moved from `huginn-net-db` to their owning crates.
`huginn-net-db` still re-exports them for one minor version but they will be removed in v2.1.

#### TCP types

| v1.7 import | v2.0 import |
|---|---|
| `huginn_net_db::tcp::Ttl` | `huginn_net_tcp::Ttl` |
| `huginn_net_db::tcp::IpVersion` | `huginn_net_tcp::IpVersion` |
| `huginn_net_db::tcp::Quirk` | `huginn_net_tcp::Quirk` |
| `huginn_net_db::tcp::TcpOption` | `huginn_net_tcp::TcpOption` |
| `huginn_net_db::tcp::WindowSize` | `huginn_net_tcp::WindowSize` |
| `huginn_net_db::tcp::PayloadSize` | `huginn_net_tcp::PayloadSize` |
| `huginn_net_db::observable_signals::TcpObservation` | `huginn_net_tcp::TcpObservation` |
| `huginn_net_db::MatchQualityType` | `huginn_net_tcp::MatchQualityType` |

#### HTTP types

| v1.7 import | v2.0 import |
|---|---|
| `huginn_net_db::http::Version` | `huginn_net_http::Version` |
| `huginn_net_db::http::Header` | `huginn_net_http::Header` |
| `huginn_net_db::observable_signals::HttpRequestObservation` | `huginn_net_http::HttpRequestObservation` |
| `huginn_net_db::observable_signals::HttpResponseObservation` | `huginn_net_http::HttpResponseObservation` |

#### DB-only types (require `features = ["db"]`)

These stay in `huginn-net-db` and are only available with the `db` feature:

| Type | Notes |
|---|---|
| `huginn_net_db::Database` | Signature database |
| `huginn_net_db::Label` | OS/browser label from DB |
| `huginn_net_db::Type` | Label type (Specified, Generic, etc.) |
| `huginn_net_db::tcp::Signature` | TCP DB signature |
| `huginn_net_db::http::Signature` | HTTP DB signature |

---

### 4. Output struct field changes

`SynTCPOutput`, `SynAckTCPOutput` and their HTTP equivalents no longer have `os_matched` / `browser_matched` fields unless the `db` feature is active.

```rust
// Before (v1.7) — always present
if let Some(syn) = result.tcp_syn {
    if let Some(os) = &syn.os_matched.os {
        println!("OS: {}", os.name);
    }
}
```

```rust
// After (v2.0) — only compiles with features = ["db"]
#[cfg(feature = "db")]
if let Some(syn) = result.tcp_syn {
    if let Some(os) = &syn.os_matched.os {
        println!("OS: {}", os.name);
    }
}

// After (v2.0) — without db feature, only raw fingerprint is available
if let Some(syn) = result.tcp_syn {
    println!("Sig: {}", syn.sig);
}
```

---

### 5. `huginn-net` default features

In v2.0 the default features for `huginn-net` are `["tcp", "http", "tls"]`.
The `db` feature is **not** included by default.

If your project uses `huginn-net` and relied on matching without ever specifying features,
add `features = ["db"]` to your dependency entry (see section 1 above).

---

### Quick migration checklist

- [ ] Add `features = ["db"]` to any crate that uses `Database`, `Label`, or `SignatureMatcher`
- [ ] Replace `HuginnNetTcp::new(Some(db), n)` → `HuginnNetTcp::new_with_db(Some(db), n)`
- [ ] Replace `HuginnNetTcp::new(None, n)` → `HuginnNetTcp::new(n)`
- [ ] Replace `HuginnNetHttp::new(Some(db), n)` → `HuginnNetHttp::new_with_db(Some(db), n)`
- [ ] Replace `HuginnNetHttp::new(None, n)` → `HuginnNetHttp::new(n)`
- [ ] Replace `HuginnNet::new(Some(&db), n, c)` → `HuginnNet::new_with_db(Some(&db), n, c)`
- [ ] Replace `HuginnNet::new(None, n, c)` → `HuginnNet::new(n, c)`
- [ ] Replace `huginn_net_db::tcp::Ttl` and similar imports (see table in section 3)
- [ ] Gate any access to `os_matched` / `browser_matched` behind `#[cfg(feature = "db")]`
- [ ] Remove `use huginn_net_db::Database` if not using DB matching

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
