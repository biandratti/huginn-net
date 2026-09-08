---
title: TLS
description: TLS ClientHello analysis and JA4 fingerprinting.
---

Huginn Net fingerprints TLS **ClientHello on TCP** (JA4 prefix `t`) using the [JA4 specification](https://github.com/FoxIO-LLC/ja4) (FoxIO-style). JA4 over QUIC (`q`) and DTLS are on the roadmap; those packets are not parsed yet.

## TLS Signature (JA4)

Huginn Net is based on JA4 (FoxIO-style) TLS fingerprinting, which encodes the structure of the ClientHello message into a compact signature. This allows for identification of client software and detection of anomalies or evasion techniques.

### JA4 ClientHello layout

<div class="ja4-sig-wrap tcp-sig-wrap">

<p style="margin:0 0 0.45rem 0; opacity:0.92;"><strong>JA4</strong> (FoxIO-LLC) fingerprints the TLS <strong>ClientHello</strong>.</p>

<div class="tcp-sig-formula"><strong>Format:</strong> three segments separated by underscores—first a readable <strong>prefix</strong>, then two <strong>12-character</strong> hex hashes (truncated SHA-256: sorted cipher suites, then sorted extensions plus signature algorithms).<span style="display:block;margin-top:0.35rem;opacity:0.88;font-size:0.88em;line-height:1.35;">The prefix bundles transport, TLS version, SNI mode, GREASE-free cipher and extension counts, and ALPN; the colored boxes below expand each piece.</span></div>

<div class="tcp-sig-example ja4-sig-hl">
<div class="tcp-sig-part c1"><code>t</code><span class="tcp-sig-k">transport</span></div>
<div class="tcp-sig-part c2"><code>13</code><span class="tcp-sig-k">TLS ver</span></div>
<div class="tcp-sig-part c3"><code>d</code><span class="tcp-sig-k">SNI</span></div>
<div class="tcp-sig-part c4"><code>15</code><span class="tcp-sig-k">#ciphers</span></div>
<div class="tcp-sig-part c1"><code>16</code><span class="tcp-sig-k">#exts</span></div>
<div class="tcp-sig-part c2"><code>h2</code><span class="tcp-sig-k">ALPN</span></div>
<span class="tcp-sig-sep">_</span>
<div class="ja4-sig-hashbox"><code>8daaf6152771</code><span class="tcp-sig-k">cipher hash (12)</span></div>
<span class="tcp-sig-sep">_</span>
<div class="ja4-sig-hashbox"><code>02713d6af862</code><span class="tcp-sig-k">ext + sig algs (12)</span></div>
</div>

<p class="tcp-sig-note"><strong>Example:</strong> Chrome on Linux, ClientHello to Cloudflare: <code>t13d1516h2_8daaf6152771_02713d6af862</code></p>

</div>

| Part | Role (JA4 client) |
| ---- | ----------------- |
| `t` / `q` / `d` | Transport: TLS over TCP (`t`, implemented), QUIC (`q`), or DTLS (`d`)—only `t` is parsed today. |
| `13` | TLS version from ClientHello (GREASE stripped)—here TLS 1.3. |
| `d` / `i` | SNI style: hostname vs IP / no SNI. |
| `15` · `16` | Counts of cipher suites and extensions (GREASE excluded). |
| `h2` | ALPN signal (e.g. HTTP/2)—extra context JA3 did not encode. |
| 12-char hashes | Truncated SHA-256 over **sorted** cipher list and over sorted extensions + signature algorithms—stable when order shuffles. |

## TLS Client

Example below matches typical analyzer output: standard JA4 lines are always emitted; **JA4_s1** and **JA4_rs1** appear when `huginn-net-tls` is built with the Cargo feature **`stable-v1`**.

```bash
[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
SNI:     www.google.com
Version: TLS 13
JA4:     t13d1516h2_8daaf6152771_d8a2da3f94cd
JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
JA4_o:   t13d1516h2_acb858a92679_b0dc76ca1c15
JA4_ro:  t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0023,0017,001b,0012,000a,0000,fe0d,44cd,000d,ff01,0005,002b,000b,002d,0010,0033_0403,0804,0401,0503,0805,0501,0806,0601
JA4_s1:  t13d1514h2_8daaf6152771_f835621b68aa
JA4_rs1: t13d1514h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

### Stable fingerprints (`stable-v1`)

Standard **JA4** hashes every non-GREASE extension in the ClientHello. Types that appear only on resumed or 0-RTT handshakes (notably **pre-shared key**) can split the key for the same browser—see [Is JA4 Now Obsolete?](https://www.ntop.org/is-ja4-now-obsolete/) and [FoxIO-LLC/ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303).

**JA4_s1** / **JA4_rs1** are **huginn-only** (`stable-v1`): same algorithm as JA4, but extension types in `S1_SESSION_EXTENSIONS` are removed before the `JA4_a` count and `JA4_c` hash. Official `JA4` / `JA4_r` / `JA4_o` / `JA4_ro` are unchanged. Full rationale, invariants, and curation rule: [JA4S1.md](https://github.com/biandratti/huginn-net/blob/master/huginn-net-tls/JA4S1.md).

Extensions dropped for **`stable-v1`** (filtered **before** hashing):

| Extension          | Type / RFC |
| ------------------ | ---------- |
| `0x0015`           | Padding ([RFC 7685](https://datatracker.ietf.org/doc/html/rfc7685)) |
| `0x0023`           | Session ticket ([RFC 5077](https://datatracker.ietf.org/doc/html/rfc5077)) |
| `0x0029`           | Pre-shared key ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)) |
| `0x002a`           | Early data ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) §4.2.10; only with PSK) |

To widen the denylist locally (not comparable across deployments), use `Signature::generate_ja4_stable_v1_excluding` or `HuginnNetTls::with_s1_excluded_extensions`. Empty `excluded` is the canonical list.

## TLS Key Fields

- **SNI**: Server Name Indication, the hostname the client is connecting to.
- **Version**: TLS protocol version as reported for the handshake (e.g., TLS 13 for TLS 1.3).
- **JA4**: JA4 fingerprint with sorted cipher suites and extensions (hashed). GREASE is stripped from ciphers, extension types, signature algorithms, and curves (RFC 8701 / FoxIO JA4).
- **JA4_r**: JA4 raw fingerprint with sorted cipher suites and extensions (full).
- **JA4_o**: JA4 fingerprint with original order (unsorted, hashed).
- **JA4_ro**: JA4 raw fingerprint with original order (unsorted, full).
- **JA4_s1**: Huginn stable JA4 (hashed), only with **`stable-v1`**; `generate_ja4()` minus `S1_SESSION_EXTENSIONS` (see table above).
- **JA4_rs1**: Stable JA4 raw (full lists), pair of **JA4_s1**; same **`stable-v1`** gate.
