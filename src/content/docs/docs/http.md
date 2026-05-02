---
title: Http request and response
description: HTTP request and response fingerprinting and signatures.
---

HTTP requests and responses are another critical component analyzed to gather information about client and server interactions. The library analyzes the characteristics of HTTP traffic to reveal useful details about the browser that influenced certain patterns.

Huginn Net collects all TCP packets that are part of HTTP requests and responses and analyzes them to gather information about client and server interactions.

## HTTP signature

For HTTP traffic, signature layout is as follows:

<div class="tcp-sig-formula">sig = ver : horder : habsent : expsw</div>

| Key       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ver`     | 0 for HTTP/1.0, 1 for HTTP/1.1, or '\*' for any.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `horder`  | Comma-separated, ordered list of headers that should appear in matching traffic. Substrings to match within each of these headers may be specified using a name=[value] notation. The signature will be matched even if other headers appear in between, as long as the list itself is matched in the specified sequence. Headers that usually do appear in the traffic, but may go away (e.g. Accept-Language if the user has no languages defined, or Referer if no referring site exists) should be prefixed with '?', e.g. "?Referer". P0f will accept their disappearance, but will not allow them to appear at any other location. |
| `habsent` | Comma-separated list of headers that must \*not\* appear in matching traffic. This is particularly useful for noting the absence of standard headers (e.g. 'Host'), or for differentiating between otherwise very similar signatures.                                                                                                                                                                                                                                                                                                       |
| `expsw`   | Expected substring in 'User-Agent' or 'Server'. This is not used to match traffic, and merely serves to detect dishonest software. If you want to explicitly match User-Agent, you need to do this in the 'horder' section.                                                                                                                                                                                                                                                                                                               |

## HTTP Request

These are sent by the client (typically a web browser) to request resources from a server. The request includes information such as the HTTP method (GET, POST, etc.), headers, and sometimes cookies or other client-specific data.

### HTTP Request Analyzed

```bash
[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox:10.x or newer
  Lang:    English
  Params:  none
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
```

### HTTP Request Key Fields

- **Browser**: The identified browser matched from the database signature.
- **Lang**: The detected language from Accept-Language header.
- **Params**: Additional parameters or optional data included in the headers.
- **Sig**: The HTTP request signature showing header order and values.

## HTTP Response

These are sent by the server in reply to the client's request, containing the requested resource (HTML page, image, etc.) or a status message indicating the success or failure of the request.

### HTTP Response Analyzed

```bash
[HTTP Response] 192.168.1.22:58494 → 91.189.91.21:80
  Server:  nginx/1.14.0 (Ubuntu)
  Params:  anonymous
  Sig:     server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
```

### HTTP Response Key Fields

- **Server**: The identified web server matched from the database signature.
- **Params**: Additional parameters or optional data included in the headers.
- **Sig**: The HTTP response signature showing header order and values.

## p0f HTTP vs Akamai HTTP/2

The p0f HTTP signature described above has a fundamental limitation: **header order does not matter**. The `horder` field matches headers in sequence relative to each other, but the signature still passes even if other headers appear in between. This makes it a coarser fingerprint, more suited to general browser identification than precise client distinction.

**Akamai HTTP/2 fingerprinting** works at a lower level and is considerably more precise. The fingerprint **reflects** four components of the raw HTTP/2 connection setup:

- **SETTINGS frame parameters** and their order
- **WINDOW_UPDATE** value
- **PRIORITY frames** (stream weights and dependencies)
- **Pseudo-header order** (`:method`, `:path`, `:authority`, `:scheme`)

The pseudo-header order is the key distinction. HTTP/2 clients send pseudo-headers in a specific order that is determined by the implementation, not by the application layer. Chrome, Firefox, Safari, and curl each produce a different order, and that order is stable across versions. Because it sits below the application, it cannot be spoofed by simply reordering headers in user code.

### Akamai fingerprint layout

<div class="tcp-sig-wrap">

<p style="margin:0 0 0.45rem 0; opacity:0.92;"><strong>Akamai HTTP/2</strong> (in <strong>huginn-net-http</strong>) is a <strong>parser / library API</strong>: given the connection preface signals (SETTINGS, flow control, PRIORITY behaviour, pseudo-header order), it produces the printable pipe-separated string and a stable <strong>32-character hex</strong> hash. It does <strong>not</strong> capture packets by itself—you call it from tests, a proxy, or any pipeline that already observes client HTTP/2. Golden vectors: <a href="https://github.com/biandratti/huginn-net/blob/master/huginn-net-http/tests/akamai.rs"><code>huginn-net-http/tests/akamai.rs</code></a>.</p>

<div class="tcp-sig-formula"><strong>Shape:</strong> <strong>SETTINGS</strong> | <strong>WINDOW_UPDATE</strong> | <strong>PRIORITY</strong> | <strong>pseudo-headers</strong> — plus optional stable <strong>hash</strong> (32 hex)</div>

<p style="margin:0.5rem 0 0.35rem 0; font-size:0.92em; opacity:0.9;"><strong>Unpacked</strong> — pipe-separated segments:</p>

<div class="tcp-sig-example akamai-sig-flow">
<div class="tcp-sig-part wide c1"><code>1:65536;2:0;3:1000;4:6291456;5:16384;6:262144</code><span class="tcp-sig-k">SETTINGS (id:value;…)</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c2"><code>15663105</code><span class="tcp-sig-k">WINDOW_UPDATE</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c3"><code>0</code><span class="tcp-sig-k">PRIORITY</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c4"><code>m,p,a,s</code><span class="tcp-sig-k">:method :path …</span></div>
</div>

<p style="margin:0.35rem 0 0.25rem 0; font-size:0.88em; opacity:0.88;"><strong>With PRIORITY frames</strong> (<code>test_akamai_fingerprint_with_priorities</code>): when priorities are present, the middle segment encodes streams such as <code>1:0:0:221,3:0:0:201</code> — stream id, dependency, exclusive flag, weight.</p>

</div>

| Segment | Role |
| ------- | ---- |
| SETTINGS | HTTP/2 SETTINGS parameters (`id:value` pairs, semicolon-separated). |
| WINDOW_UPDATE | Initial flow-control / window increment observed on the connection. |
| PRIORITY | `0` if none; otherwise stream dependencies and weights (see tests above). |
| Pseudo-headers | Order of `:method`, `:path`, `:authority`, `:scheme` abbreviated as `m`, `p`, `a`, `s` — implementation-defined and hard to spoof from app-layer reordering alone. |

<p class="tcp-sig-note">Integrators sometimes forward the computed value as HTTP header <code>x-huginn-net-akamai</code> (e.g. a TLS terminator). That header is <strong>not</strong> produced by huginn-net alone—it comes from whatever wires the parser output into your stack. See <a href="#tls-termination-and-the-akamai-fingerprint">TLS termination and the Akamai fingerprint</a>.</p>

### TLS termination and the Akamai fingerprint

**huginn-net-http** only implements the **Akamai fingerprint computation** from HTTP/2 preface inputs you provide. Capture and TLS termination live outside this crate.

The Akamai-style string is meaningless if those inputs were already rewritten—for example after a hop that rebuilds the HTTP/2 connection without preserving the original pseudo-header order.

A **TLS-terminating reverse proxy** — e.g. [huginn-proxy](https://github.com/biandratti/huginn-proxy) — is one integration: it observes client HTTP/2 at the terminator, runs the fingerprint logic, and injects **`x-huginn-net-akamai`** so backends receive the signal.

The key constraint is always **input fidelity**: the parser produces a meaningful fingerprint only when the HTTP/2 preface it receives still reflects what the client originally sent.
