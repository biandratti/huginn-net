---
title: TLS
description: TLS ClientHello analysis and JA4 fingerprinting.
---

**Huginn Net** supports TLS analysis. TLS is a cryptographic protocol used to secure communications over a network. By analyzing the characteristics of TLS handshakes, Huginn Net can identify the client based on the JA4 signature.

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
| `t` / `q` / `d` | Transport: TLS over TCP, QUIC, or DTLS. |
| `13` | TLS version from ClientHello (GREASE stripped)—here TLS 1.3. |
| `d` / `i` | SNI style: hostname vs IP / no SNI. |
| `15` · `16` | Counts of cipher suites and extensions (GREASE excluded). |
| `h2` | ALPN signal (e.g. HTTP/2)—extra context JA3 did not encode. |
| 12-char hashes | Truncated SHA-256 over **sorted** cipher list and over sorted extensions + signature algorithms—stable when order shuffles. |

## TLS Client

Example below matches typical analyzer output: standard JA4 lines are always emitted; **JA4_s1** and **JA4_s1r** appear when `huginn-net-tls` is built with the Cargo feature **`stable-v1`**.

```bash
[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
SNI:     www.google.com
Version: TLS 13
JA4:     t13d1516h2_8daaf6152771_d8a2da3f94cd
JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
JA4_o:   t13d1516h2_acb858a92679_b0dc76ca1c15
JA4_or:  t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0023,0017,001b,0012,000a,0000,fe0d,44cd,000d,ff01,0005,002b,000b,002d,0010,0033_0403,0804,0401,0503,0805,0501,0806,0601
JA4_s1:  t13d1515h2_8daaf6152771_31ec0a762479
JA4_s1r: t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

### Stable fingerprints (`stable-v1`)

Standard **JA4** includes every non-GREASE extension in the ClientHello. Some extensions are reused across TLS 1.3 resumption and similar paths (notably **pre-shared key**) and may appear only on some connections from the same client, so **JA4 can legitimately differ between flows** even when the underlying browser or library is unchanged—a stability issue discussed for modern TLS stacks in [Is JA4 Now Obsolete?](https://www.ntop.org/is-ja4-now-obsolete/) (ntop shows Safari-style variation before ignoring ephemeral extensions). **JA4_s1** / **JA4_s1r** address that by computing JA4 after dropping extensions that commonly vary per connection (see table below), which tends to yield **more comparable fingerprints across sessions** than plain JA4—at the cost of omitting signal those extensions carry.

Extensions treated as ephemeral for **`stable-v1`** (filtered **before** hashing):

| Extension          | Type / RFC |
| ------------------ | ---------- |
| `0x0023`           | Session ticket ([RFC 5077](https://datatracker.ietf.org/doc/html/rfc5077)) |
| `0x0029`           | Pre-shared key ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)) |
| `0x0015`           | Padding ([RFC 7685](https://datatracker.ietf.org/doc/html/rfc7685)) |

## TLS Key Fields

- **SNI**: Server Name Indication, the hostname the client is connecting to.
- **Version**: TLS protocol version as reported for the handshake (e.g., TLS 13 for TLS 1.3).
- **JA4**: JA4 fingerprint with sorted cipher suites and extensions (hashed).
- **JA4_r**: JA4 raw fingerprint with sorted cipher suites and extensions (full).
- **JA4_o**: JA4 fingerprint with original order (unsorted, hashed).
- **JA4_or**: JA4 raw fingerprint with original order (unsorted, full).
- **JA4_s1**: Stable JA4 fingerprint (hashed), only with **`stable-v1`**; computed after removing Session Ticket (`0x0023`), Pre-Shared Key (`0x0029`), and Padding (`0x0015`) from the extension list so fingerprints drift less across sessions than **JA4**.
- **JA4_s1r**: Stable JA4 raw fingerprint (full lists), pair of **JA4_s1**; same extension filtering and **`stable-v1`** gate as **JA4_s1**.
