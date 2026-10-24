---
title: Passive TCP, HTTP, and TLS fingerprinting
description: Rust library for passive fingerprinting. TCP OS labels (p0f), HTTP browser and server labels, and JA4. PCAP or live capture, no probes.
---

Huginn Net fingerprints traffic you already have. It does not send probes.

## Live demo

The [live demo](https://huginn-proxy.duckdns.org/) shows the fingerprints of the browser that opens it. [huginn-proxy](https://github.com/biandratti/huginn-proxy) terminates TLS, collecting and parsing that visit with huginn-net.

TCP and HTTP follow the p0f v3 signature format (Michal Zalewski). TLS ClientHello on TCP follows [JA4](https://github.com/FoxIO-LLC/ja4) (FoxIO). The Akamai HTTP/2 string ([Black Hat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)) is a separate call in `huginn-net-http` (`akamai` / `Http2FingerprintExtractor`). It is not a field of `FingerprintResult`, and `huginn-net` `full` does not turn that feature on.

There are five crates. `huginn-net` runs TCP, HTTP, and TLS in one analyzer. The other four each do one job: TCP, HTTP, TLS, or the p0f database. Every feature is opt-in (`default = []`). The `full` feature turns on everything that release ships.

Live capture needs `libpcap`. Reading a PCAP file does not.

Parsing uses [pnet](https://crates.io/crates/pnet), [pcap-file](https://crates.io/crates/pcap-file), and [tls-parser](https://crates.io/crates/tls-parser).

## What you get from a packet

| Layer | Protocol | Output |
| ----- | -------- | ------ |
| 4 | TCP SYN / SYN+ACK | OS label from `p0f.fp`, plus MTU and uptime when those features are on |
| 7 | HTTP/1 and HTTP/2 | Browser or server label from `p0f.fp`. The Akamai string is computed separately (see [HTTP](../http/)) |
| 7 | TLS ClientHello on TCP | JA4 (`t` prefix). QUIC and DTLS are not parsed |

A label exists only when a signature in the bundled database fits. The file header records an upstream p0f database from 2012, label edits on 2025-06-01, and extra TCP SYN signatures on 2026-10-09. See [Matching](../matching/).

The printed OS line is `name/family/variant` (`Windows/win/XP`). An empty flavor is `??`. No match prints `???`. The browser and server lines print `label.name` (`Firefox`, `nginx`). The flavor (`10.x or newer`, `1.x`) stays on the struct.

## Crates

- **[huginn-net](https://crates.io/crates/huginn-net)**: TCP, HTTP, and TLS together. `Database` is re-exported when the `db` feature is on.
- **[huginn-net-tcp](https://crates.io/crates/huginn-net-tcp)**: SYN, SYN+ACK, MTU, uptime. OS labels need `huginn-net-db`.
- **[huginn-net-http](https://crates.io/crates/huginn-net-http)**: HTTP request and response, plus Akamai HTTP/2. Browser and server labels need `huginn-net-db`.
- **[huginn-net-tls](https://crates.io/crates/huginn-net-tls)**: JA4 from the ClientHello. No database.
- **[huginn-net-db](https://crates.io/crates/huginn-net-db)**: parses `p0f.fp` and matches TCP and HTTP signatures.

Crate roles and feature flags are on the [Ecosystem](../ecosystem/) page. Short programs are on [Quick example](../quick-example/).

## Cargo

`huginn-net` with `full` already depends on `huginn-net-db` (the `db` feature is part of `full`). Add `huginn-net-db` yourself only when you use `huginn-net-tcp` or `huginn-net-http` on their own.

```toml
[dependencies]
huginn-net = { version = "{{huginn-net}}", features = ["full"] }
```

TCP or HTTP alone, with labels:

```toml
[dependencies]
huginn-net-tcp = { version = "{{huginn-net-tcp}}", features = ["full"] }
huginn-net-db  = { version = "{{huginn-net-db}}", features = ["tcp"] }
```

```toml
[dependencies]
huginn-net-http = { version = "{{huginn-net-http}}", features = ["full"] }
huginn-net-db   = { version = "{{huginn-net-db}}", features = ["http"] }
```

TLS does not use the database:

```toml
[dependencies]
huginn-net-tls = { version = "{{huginn-net-tls}}", features = ["full"] }
```

The version in each snippet is that crate’s current release on [crates.io](https://crates.io/).

Without `db`, `HuginnNet::new` is not compiled. Use `HuginnNet::new_observable`. You still get raw TCP and HTTP signatures and JA4. OS, browser, and server fields stay disabled.

## What you can do with it

You already have the packets. The library names what is in them. It does not scan hosts, and a label is not a verdict that the client is malicious.

- **A capture or a live interface.** `analyze_pcap`, or `analyze_network` on an interface you can read. Each SYN can get an OS label, each HTTP message a browser or server label, each ClientHello a JA4.
- **One connection, two OS claims.** With `db` and `tcp-syn`, `UA/OS` compares the User-Agent to the SYN on that connection. `divergent` means they disagree, which is what you see when a proxy or NAT sits in the middle.
- **Ethernet, DSL, or a tunnel.** The MTU label comes from the MSS. `1492` is `DSL` in the bundled file. Other sizes map to Ethernet, IPsec, or a VPN when the file has that value.
- **An app that only sees HTTP.** A TLS terminator watches the client handshake and passes the fingerprints to the backend as headers. [huginn-proxy](https://github.com/biandratti/huginn-proxy) does this for the TCP SYN signature, JA4, and the Akamai HTTP/2 string. The library computes the values. The proxy writes the headers. The [live demo](https://huginn-proxy.duckdns.org/) is that proxy.

## License

[MIT](https://github.com/biandratti/huginn-net/blob/master/LICENSE-MIT) or [Apache 2.0](https://github.com/biandratti/huginn-net/blob/master/LICENSE-APACHE).
