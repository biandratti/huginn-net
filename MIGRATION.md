# Migration Guide

---

## v1.x → v2.0.0

### What changed

1. **Default features are now empty.** Every crate ships `default = []`. Add `features = ["full"]` to keep v1.x behaviour.
2. **`huginn-net-db` is now the leaf that depends on protocol crates**, not the other way around. Types that lived in `huginn-net-db` moved to the protocol crates.
3. **Constructor API changed.** `new()` no longer takes a database or returns `Result` (for tcp/http). Matching is configured via `.with_matcher()`. Parallel mode uses `.with_parallel()`.
4. **Optional JSON output.** Every crate exposes a `json` feature that derives `serde::Serialize` on all output types. Opt in with `features = ["full", "json"]`. Without this feature, serialization code is not compiled in.

---

### Most users — umbrella crate `huginn-net`

**Cargo.toml:**

```diff
-huginn-net = "1.x"
+huginn-net = { version = "2.0.0", features = ["full"] }
```

**Rust code** — `HuginnNet::new` is unchanged. If you imported types directly from `huginn-net-db`, update the paths:

```diff
-use huginn_net_db::tcp::{IpVersion, Ttl};
-use huginn_net_db::http::Version;
+use huginn_net_tcp::tcp::{IpVersion, Ttl};
+use huginn_net_http::http::Version;
```

Or keep using the umbrella re-exports (unchanged):

```rust
use huginn_net::tcp::{IpVersion, Ttl};
use huginn_net::http::Version;
```

That's it for most users.

---

### Direct users of `huginn-net-tcp` / `huginn-net-http`

**Cargo.toml:**

```diff
-huginn-net-tcp = "1.x"
+huginn-net-tcp = { version = "2.0.0", features = ["full"] }
```

**Constructor — before (v1.x):**

```rust
let db = Arc::new(Database::load_default()?);
let mut tcp = HuginnNetTcp::new(Some(db), 1000)?;
```

**Constructor — after (v2.0):**

```rust
use huginn_net_db::{Database, SharedTcpSignatureMatcher};

let db = Database::load_default()?;
let matcher = Arc::new(SharedTcpSignatureMatcher::from_database(&db));
let mut tcp = HuginnNetTcp::new(1000).with_matcher(matcher);
```

To run without database matching (raw signals only):

```rust
let mut tcp = HuginnNetTcp::new(1000);
```

Same pattern applies to `HuginnNetHttp`.

**Parallel mode — before (v1.x):**

```rust
let tcp = HuginnNetTcp::with_config(workers, queue_size, batch_size, timeout_ms, max_connections)?;
```

**Parallel mode — after (v2.0):**

```rust
let tcp = HuginnNetTcp::new(max_connections)
    .with_parallel(workers, queue_size, batch_size, timeout_ms)
    .with_matcher(matcher);
```

---

### Type paths that moved

| v1.x | v2.0 |
|------|------|
| `huginn_net_db::tcp::{IpVersion, Ttl, WindowSize, TcpOption, Quirk, PayloadSize}` | `huginn_net_tcp::tcp::*` |
| `huginn_net_db::http::{Version, Header, HttpDiagnosis}` | `huginn_net_http::http::*` |
| `huginn_net_db::observable_signals::TcpObservation` | `huginn_net_tcp::observable::TcpObservation` |
| `huginn_net_db::observable_signals::HttpRequestObservation` | `huginn_net_http::observable::HttpRequestObservation` |
| `huginn_net_db::observable_signals::HttpResponseObservation` | `huginn_net_http::observable::HttpResponseObservation` |
| `huginn_net_tcp::SignatureMatcher` | `huginn_net_db::TcpSignatureMatcher` |
| `huginn_net_http::SignatureMatcher` | `huginn_net_db::HttpSignatureMatcher` |
| `huginn_net_tcp::db` / `huginn_net_http::db` re-exports | removed — depend on `huginn-net-db` directly |

### Database field paths that moved

| v1.x | v2.0 |
|------|------|
| `db.tcp_request`, `db.tcp_response` | `db.tcp.tcp_request`, `db.tcp.tcp_response` |
| `db.mtu` | `db.tcp.mtu` |
| `db.http_request`, `db.http_response` | `db.http.http_request`, `db.http.http_response` |
| `db.ua_os` | `db.http.ua_os` |

---

### Removed

The following methods on TCP fingerprint types are gone. Use `TcpSignatureMatcher` for the full matching pipeline instead.

- `Ttl::distance_ttl`
- `IpVersion::distance_ip_version`
- `WindowSize::distance_window_size`
- `PayloadSize::distance_payload_size`

---

### Feature reference

All crates ship `default = []`. Use `features = ["full"]` to opt into everything.

| Crate | `full` includes |
|-------|----------------|
| `huginn-net-tcp` | `syn`, `syn-ack`, `mtu`, `uptime` |
| `huginn-net-http` | `p0f-request`, `p0f-response`, `akamai` |
| `huginn-net-tls` | `stable-v1` |
| `huginn-net-db` | `tcp`, `http` |
| `huginn-net` | `db`, `tcp-syn`, `tcp-syn-ack`, `tcp-mtu`, `tcp-uptime`, `http-p0f-request`, `http-p0f-response`, `tls-stable-v1` |

---

## v1.6.x → v1.7.0

Additive only — new optional packet filtering (`FilterConfig`, `PortFilter`, `IpFilter`, `SubnetFilter`, `.with_filter()`). No migration required.

---

## v1.5.2 → v1.6.0

`FingerprintResult` fields renamed in the `huginn-net` umbrella crate only. Protocol-specific crates unchanged.

| v1.5.2 | v1.6.0 |
|--------|--------|
| `syn` | `tcp_syn` |
| `syn_ack` | `tcp_syn_ack` |
| `mtu` | `tcp_mtu` |
| `client_uptime` | `tcp_client_uptime` |
| `server_uptime` | `tcp_server_uptime` |

---

## Need help?

- Issues: https://github.com/biandratti/huginn-net/issues
- Examples: https://github.com/biandratti/huginn-net/tree/master/examples
