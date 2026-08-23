# Migration Guide

---

## v2.0.0 → v2.1.0

Matching follows p0f: a field that does not fit is a rejection (HTTP has no
error budget). TCP still has a fuzzy tier for the documented TTL/quirk
tolerances. Scores are **tiers**, not a penalty sum:

| Score | Meaning |
|-------|---------|
| `1.0` | Exact, named product |
| `0.8` | Exact, generic catch-all |
| `0.5` | Fuzzy (TCP only) |

First-match-wins within a tier. Userland (`s:!:…`) is never reported as fuzzy.

### Call sites

```rust
// quality
MatchQuality::Matched(q)                          // v2.0
MatchQuality::Matched { quality, fuzzy }          // v2.1; inspect FuzzyReason

// TCP result
OSQualityMatched { os, quality }                  // v2.0
OSQualityMatched { os, quality, dist, random_ttl, excess_dist, tos }
os_matched.params()                               // "generic" | "fuzzy (…)" | "random_ttl" | …

// HTTP notes
output.diagnosis                                  // v2.0 HttpDiagnosis
output.params.dishonest                           // v2.1 HttpParams flags
HttpRequestOutput { … }                           // v2.0
HttpRequestOutput { …, ua_os }                    // v2.1 UaOsAgreement (p0f-request)
process_ipv4_packet(..., matcher)                 // v2.0
process_ipv4_packet(..., matcher, os_source)      // v2.1; pass None if unused
process_ipv6_packet(..., matcher, os_source)      // same extra argument
WorkerPool::new(..., matcher)                     // v2.0
WorkerPool::new(..., matcher, os_source)          // v2.1; pass None if unused
HuginnNetHttp::with_matcher(m)                    // v2.0
HuginnNetHttp::with_matcher(m).with_observed_os(s) // v2.1 optional NAT_APP_UA source

// observation
wsize: WindowSize::Mss(44)                        // v2.0, classified at parse
wsize: 64240, tot_hdr, peer_mss, tos, quirks: QuirkSet  // v2.1
observation.window_multiplier()
```

### `HttpRequestOutput.ua_os`

Required (`p0f-request`). `NotChecked` / `Consistent` / `Divergent`.
`Divergent` is NAT/proxy (`bad_sw=1`), not `params.dishonest`.
`HuginnNet` with `db` + `tcp-syn` fills it from this connection's SYN;
pass `os_source: None` if unused.

Only SYN / SYN+ACK emit a TCP OS signal (not every ACK). `syn-ack` tracks
handshake state (`peer_mss`, one fingerprint per flow).

Matcher methods are the traits: `match_tcp_request` / `match_http_request` / …
(or `db.tcp_request.find_best_match`). Protocol examples load `TcpDatabase` /
`HttpDatabase`.

### Renames

| v2.0 | v2.1 |
|------|------|
| `get_diagnostic` | `build_params` |
| `calculate_distance` / `get_quality_score` | `fit` → `Option<SignatureFit<_>>` |
| `find_best_match` → `(&Label, &DS, f32)` | `DatabaseMatch` |
| `matching_by_*` | `TcpMatcher` / `HttpMatcher` |
| `db` / `db_parse` / `observable_*_signals_matching` | `database` / `parse` (matching is private) |
| `Vec<Quirk>` | `QuirkSet` |
| `TcpIndexKey.olayout_key: String` | `olayout_hash: u32` |
| `distance_ttl` / `detect_win_multiplicator` | `ttl_fit` / `detect_win_multi` |
| `distance_*` (tcp/http) | `*_matches` (`bool`) |

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
+huginn-net-db = { version = "2.0.0", features = ["tcp"] }
```

**Constructor — before (v1.x):**

```rust
let db = Arc::new(Database::load_default()?);
let mut tcp = HuginnNetTcp::new(Some(db), 1000)?;
```

**Constructor — after (v2.0):**

```rust
use huginn_net_db::{SharedTcpSignatureMatcher, TcpDatabase};

let db = TcpDatabase::load_default()?;
let matcher = Arc::new(SharedTcpSignatureMatcher::new(Arc::new(db)));
let mut tcp = HuginnNetTcp::new(1000).with_matcher(matcher);
```

To run without database matching (raw signals only):

```rust
let mut tcp = HuginnNetTcp::new(1000);
```

Same pattern applies to `HuginnNetHttp`, using `HttpDatabase` and `SharedHttpSignatureMatcher` (add `huginn-net-db` with `features = ["http"]` instead).

If you need both TCP and HTTP matching from a single loaded file, use `huginn_net_db::Database` (`features = ["tcp", "http"]`) and `SharedTcpSignatureMatcher::from_database` / `SharedHttpSignatureMatcher::from_database` instead.

**Parallel mode — before (v1.x):**

```rust
let db = Arc::new(Database::load_default()?);
let tcp = HuginnNetTcp::with_config(Some(db), max_connections, workers, queue_size, batch_size, timeout_ms)?;
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
