# Migration Guide

---

## v2.0.0 → v2.1.0

### What changed

The matcher now follows p0f's algorithm instead of summing soft penalties, so
which signatures match changes: TCP gains coverage (p0f's fuzzy tolerances for
quirks and TTL are honoured), HTTP loses it (no error budget — a header that
does not fit is a rejection), and every field that p0f treats as a gate now
rejects instead of costing points.

---

### Quality scores mean something different

A score is no longer a normalised sum of per-field penalties. It reports which
tier the match landed in, following p0f's order of preference:

| Score | Match |
|-------|-------|
| `1.0` | Exact fit against a signature naming a concrete product |
| `0.8` | Exact fit against a catch-all (generic) signature |
| `0.5` | Only holds because a documented tolerance was applied (TCP only) |

Nothing else is produced. If you compared scores against thresholds, note that
the ordering is the contract and the numbers are free to be recalibrated; if you
branched on specific values, switch to comparisons.

Selection follows p0f's first-match-wins rule within each tier: the first
exact specific in `.fp` / bucket order wins immediately; otherwise the first
exact generic; otherwise the first fuzzy. An exact generic still outranks a
fuzzy specific. Application signatures (p0f's `s:!:…`, e.g. NMap) are never
reported on a fuzzy match — and if the *first* fuzzy candidate is userland,
nothing is reported even when a later fuzzy OS signature would also fit.

---

### `TcpMatchQuality::Matched` says what was tolerated

The variant carries a struct instead of a bare float, so a fuzzy match can name
the tolerance it needed rather than only scoring lower for it:

```rust
// v2.0
match os_matched.quality {
    MatchQuality::Matched(quality) => …,
    …
}

// v2.1.0
match os_matched.quality {
    MatchQuality::Matched { quality, fuzzy: None } => …,        // exact fit
    MatchQuality::Matched { quality, fuzzy: Some(reason) } => { // held by a tolerance
        println!("{reason}");                    // "missing id+, extra ecn"
        reason.implausible_hop_distance;         // Option<u32>
        reason.added_quirks;                     // Vec<Quirk>
        reason.missing_quirks;                   // Vec<Quirk>
    }
    …
}
```

`MatchQuality::exact(q)` builds the fuzzy-free case, which is what the MTU match
reports: an MTU either equals a known link's value or it does not.

Whether the match is specific or generic is *not* in here — `os.kind` already
carries it. HTTP is unchanged, since p0f defines no tolerances for it.

The `Params:` line of the TCP output follows p0f's vocabulary now (`generic`,
`fuzzy (…)`, or `none`) instead of printing `Specified`/`Generic`, which matches
what the HTTP output already did.

---

### The observed window is no longer classified

`TcpObservation.wsize` was a `WindowSize`, which meant the window got sorted into
`Mss(n)`, `Mtu(n)`, `Mod(n)` or `Value(n)` as the packet was parsed. That
classification is irreversible, and it made **52 of the 117 signatures with a
literal window unreachable**: a window of 8192 was stored as `Mod(4096)` and
could no longer be compared against the literal `8192` that Windows 7/8/8.1 and
the `NT kernel 6.x` catch-all declare. All the Windows literals, both NMap
signatures, OpenBSD 3.x-5.x, Linux 2.0, Tru64, HP-UX, OpenVMS 7.x and the two
Nintendo consoles were affected. The one `mtu*n` signature could not match either.

The window is now kept exactly as it came off the wire, and a multiple is derived
only when a signature asks for one, which is what p0f does:

```rust
// v2.0
TcpObservation { wsize: WindowSize::Mss(44), … }

// v2.1
TcpObservation {
    wsize: 64240,   // raw, as on the wire
    tot_hdr: 60,    // IP + TCP header bytes, one of the MTU divisors
    …
}

observation.window_multiplier(); // Option<WindowMultiplier> { multiple, of_mtu }
```

`WindowSize` still describes what a *signature* declares, which is where the five
forms belong. `detect_win_multiplicator`, which returned the classification, is
replaced by `detect_win_multi`, which mirrors p0f's divisor list and answers with
the family the multiple belongs to. The rendered signature is unchanged in shape:
`mss*n`/`mtu*n` when the window is a multiple of one, the raw value otherwise,
computed at render time like p0f's `dump_sig`.

Two consequences for output you may be asserting on: a window that is *not* an
exact multiple of the MSS is no longer reported as one (65535 with an MSS of 1460
used to round down to `mss*44`, leaving 1295 bytes unaccounted for), and the
divisors derived from a 1500-byte MTU now answer for the `mss*n` family rather
than `mtu*n`, as they do in p0f.

---

### Only the handshake produces a TCP signal

A `SynAckTCPOutput` used to be emitted for **every packet that was not a plain
SYN** — bare ACKs, data segments, `FIN+ACK`, `RST` — because the pipeline routed
anything not coming from the client into the response slot. Now, as in p0f, only
the two packets that open a connection are fingerprinted: the SYN and the
SYN+ACK.

Nothing is lost by it. A mid-stream packet has no MSS and no window scale option,
and its window is already scaled, while all 101 `[tcp:response]` signatures
require the MSS option — so those signals could only ever come back as
`NotMatched`. What you get instead is one signal per handshake rather than one per
packet: in the macOS pcap of the test corpus, 43 signals became 2.

If you were counting signals, or treating `NotMatched` as evidence of an
unrecognised stack, expect both numbers to drop sharply on live traffic, where
most packets are data.

---

### SYN+ACK windows can use the peer's MSS

`TcpObservation` gained `peer_mss: Option<u16>`: the MSS from the client's SYN,
filled in on a SYN+ACK when that SYN was seen on the same flow. It is always
`None` on a SYN.

p0f tries that value (and `peer_mss - 12`) as the last window divisors when
classifying a response (`fp_tcp.c:92-99`). Without it, a SYN+ACK whose window is
a multiple of the *client's* MSS but not of the server's own divisors rendered
the raw window and could not match `mss*n` response signatures. Matching and
`Display` / `raw_signature` both read it through `window_multiplier()`.

```rust
// v2.0: SYN+ACK observation had no peer context
TcpObservation { mss: Some(1460), wsize: 14000, … }

// v2.1
TcpObservation {
    mss: Some(1460),       // server's own MSS
    wsize: 14000,
    peer_mss: Some(1400),  // from the client's SYN; None if the SYN was not seen
    …
}
```

Consequences for feature builds:

- The `syn-ack` feature now pulls in `ttl_cache` and keeps per-flow handshake
  state (`syn_mss`, `acked`). A SYN+ACK is fingerprinted **once** per flow.
- With only `syn-ack` enabled, SYN packets are still inspected far enough to
  store the client's MSS. No `SynTCPOutput` is emitted unless `syn` is also on.
- `ConnectionTracker` is no longer a no-op when `syn-ack` is on without `uptime`.

---

### TCP quirks are a bitmask (`QuirkSet`)

`TcpObservation.quirks` and database `Signature.quirks` are now [`QuirkSet`]
(`u32` bits aligned with p0f `QUIRK_*`), not `Vec<Quirk>`. Matching uses
XOR-style difference + whitelist masks; `Quirk` remains for parse/naming.
`FuzzyReason::{added,missing}_quirks` are `QuirkSet` too. Display order follows
p0f `.fp` declaration order (`df,id+,ecn`, …).

```rust
// v2.0
obs.quirks = vec![Quirk::Df, Quirk::NonZeroID];
reason.missing_quirks == vec![Quirk::NonZeroID]

// v2.1
obs.quirks = QuirkSet::from([Quirk::Df, Quirk::NonZeroID]);
reason.missing_quirks == QuirkSet::from([Quirk::NonZeroID])
quirks.insert(Quirk::Ecn);
```

---

### TCP index key uses `olayout_hash` (no `String` on lookup)

`TcpIndexKey.olayout_key: String` is now `olayout_hash: u32` from
`huginn_net_tcp::tcp::hash_olayout` (FNV-1a over the option sequence). The key
is `Copy`. Matching behaviour is unchanged: the hash only selects the bucket;
`olayout` equality still gates the fit.

```rust
// v2.0
TcpIndexKey { ip_version_key, olayout_key: "mss,sok,ts,nop,ws".into(), pclass_key }

// v2.1
TcpIndexKey { ip_version_key, olayout_hash: hash_olayout(&olayout), pclass_key }
```

---

### TCP `params` / `Dist:` align with p0f (`dump_flags`, `guess_dist`)

`OSQualityMatched` and `TcpMatch` now carry the fields p0f prints beside the OS
label:

| Field | Meaning |
|-------|---------|
| `dist` | Hop count for `Dist:` (signature hops when TTL is usable, else `guess_dist`) |
| `random_ttl` | Winning signature used a randomised TTL (`nnn-`) |
| `excess_dist` | Reported `dist` is above `MAX_DIST` (35) |
| `tos` | IPv4 DSCP / IPv6 traffic-class bits 2–7 (`0` omits `tos:` from params) |

`TcpObservation` gained `tos: u8` (not used for matching).  
`params()` may also emit `random_ttl`, `excess_dist`, and `tos:0xNN`, still
keeping the typed `fuzzy (…)` detail. Without a match, `tos` / `excess_dist`
can still appear (same as p0f).

```rust
// v2.0
OSQualityMatched { os, quality }
println!("{}", os_matched.params()); // "generic" | "fuzzy (…)" | "none"
// Dist: line used calculate_ttl's heuristic on the observation

// v2.1
OSQualityMatched { os, quality, dist, random_ttl, excess_dist, tos }
println!("{}", os_matched.params()); // e.g. "fuzzy (…) random_ttl tos:0x2e"
// Dist: uses os_matched.dist
```

Call sites that construct `OSQualityMatched` or `TcpMatch` by hand must set the
new fields (or use `OSQualityMatched::without_match` when there is no OS hit).

---

### `HttpDiagnosis` → `HttpParams`

`HttpRequestOutput`/`HttpResponseOutput` carry `params: HttpParams` instead of
`diagnosis: HttpDiagnosis`, because p0f reports these as combinable flags
(`dishonest generic`) rather than one verdict.

```rust
// v2.0
match output.diagnosis { HttpDiagnosis::Dishonest => …, … }

// v2.1
if output.params.dishonest { … }
println!("{}", output.params); // "dishonest generic", or "none"
```

`dishonest` now means what p0f means: the `User-Agent`/`Server` string does not
contain the software the matched signature declares.

---

### Removed

There is no distance model anymore, so the helpers that produced or scored one
are gone. Each one is replaced by a check that answers the question directly.

| v2.0 | v2.1 |
|------|------|
| `http_common::get_diagnostic` | `http_common::build_params` |
| `DatabaseSignature::calculate_distance` + `get_quality_score` | `DatabaseSignature::fit`, returning `Option<SignatureFit<Self::Fuzziness>>` |
| `MatchQuality` trait, `TcpMatchQuality`, `HttpMatchQuality` (the database-side traits) | removed; use `MatchRank` |
| `FingerprintDb::find_best_match` returning `(&Label, &DS, f32)` | returns `DatabaseMatch`, whose fields are named |
| `matching_by_tcp_request`/`_response`, `matching_by_http_request`/`_response` returning tuples | the same `DatabaseMatch` |
| `tcp::distance_ttl` | `tcp::ttl_fit` (returns the hop distance) |
| `tcp::detect_win_multiplicator` returning a `WindowSize` | `tcp::detect_win_multi`, returning `Option<WindowMultiplier>` |
| `tcp::distance_ip_version`, `distance_window_size`, `distance_payload_size` | `ip_version_matches`, `window_size_matches`, `payload_size_matches` (`bool`) |
| `http::distance_http_version`, `distance_header`, `distance_habsent` | `http_version_matches`, `headers_match`, `absent_headers_match` (`bool`) |
| `huginn_net_db::http::distance_expsw` | `huginn_net_db::http::expsw_matches` (never part of the match) |
| `HttpDistance::distance_*` methods | `version_matches`, `headers_match`, `horder_matches`, `absent_headers_match` |

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
