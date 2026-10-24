---
title: Http request and response
description: HTTP request and response fingerprinting and signatures.
---

HTTP fingerprints follow the p0f request and response layout. The matcher compares header order and a few header values to `p0f.fp`. The `User-Agent` or `Server` substring in `expsw` is not part of the match. It only flags a header that disagrees with the signature.

## HTTP signature

For HTTP traffic, signature layout is as follows:

<div class="tcp-sig-formula">sig = ver : horder : habsent : expsw</div>

| Key       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ver`     | `0` HTTP/1.0, `1` HTTP/1.1, `2` HTTP/2, `3` HTTP/3, or `*` for any. The analyzer parses HTTP/1 and HTTP/2.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `horder`  | Comma-separated, ordered list of headers that should appear in matching traffic. Substrings to match within each of these headers may be specified using a name=[value] notation. The signature will be matched even if other headers appear in between, as long as the list itself is matched in the specified sequence. Headers that usually do appear in the traffic, but may go away (e.g. Accept-Language if the user has no languages defined, or Referer if no referring site exists) should be prefixed with '?', e.g. "?Referer". P0f will accept their disappearance, but will not allow them to appear at any other location. |
| `habsent` | Comma-separated list of headers that must \*not\* appear in matching traffic. This is particularly useful for noting the absence of standard headers (e.g. 'Host'), or for differentiating between otherwise very similar signatures.                                                                                                                                                                                                                                                                                                       |
| `expsw`   | Expected substring in 'User-Agent' or 'Server'. This is not used to match traffic, and merely serves to detect dishonest software. If you want to explicitly match User-Agent, you need to do this in the 'horder' section.                                                                                                                                                                                                                                                                                                               |

## HTTP Request

A request fingerprint is the client's header order. The label, when the database has one, is a browser.

### HTTP Request Analyzed

```bash
[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox
  Lang:    English
  Params:  none
  UA/OS:   consistent (Windows)
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
```

### HTTP Request Key Fields

- **Browser**: `label.name` when it is set. This sample matches `s:!:Firefox:10.x or newer`; the line prints `Firefox`, and `10.x or newer` is `browser.variant`. HTTP matching is exact only (`Specific` / `Generic`); there is no fuzzy tier. No match prints `???`.
- **Lang**: The detected language from Accept-Language header.
- **Params**: Match notes (`none`, `dishonest`, `anonymous`, `generic`). `expsw` never rejects; a contradicting User-Agent sets `dishonest`.
- **UA/OS**: Printed `consistent (Windows)`, `divergent (ua=…, net=…)`, or `not checked (…)`. The enum is `Consistent` / `Divergent` / `NotChecked`. See [Matching](../matching/).
- **Sig**: The HTTP request signature showing header order and values.

## HTTP Response

A response fingerprint is the server's header order. The label, when the database has one, is a web server.

### HTTP Response Analyzed

```bash
[HTTP Response] 91.189.91.21:80 → 192.168.1.22:58494
  Server:  nginx
  Params:  none
  Sig:     1:Server,Date,Content-Type,?Content-Length,?Last-Modified,Connection=[close]:Keep-Alive,Accept-Ranges:nginx/
```

The arrow is the host that sent the response, then the client. `Server` is `label.name` (`s:!:nginx:1.x` → `nginx`; flavor `1.x` is `web_server.variant`). The `Server` header text is the `expsw` field (`nginx/`), not the `Server:` line. `anonymous` is a different case: the response had no `Server` header at all.

### HTTP Response Key Fields

- **Server**: The identified web server, when a matcher is attached.
- **Params**: Match notes (`none`, `dishonest`, `anonymous`, `generic`), same rules as requests.
- **Sig**: The HTTP response signature showing header order and values.

## p0f HTTP vs Akamai HTTP/2

The p0f HTTP signature is coarser than the Akamai string. Headers named in `horder` must show up in that order. Headers that are not in the list may sit between them, and a `?` header may be missing. That still identifies a browser family more often than one build.

**Akamai HTTP/2 fingerprinting** works at a lower level and is considerably more precise. The fingerprint **reflects** four components of the raw HTTP/2 connection setup:

- **SETTINGS frame parameters** and their order
- **WINDOW_UPDATE** value
- **PRIORITY frames** (stream weights and dependencies)
- **Pseudo-header order** (`:method`, `:path`, `:authority`, `:scheme`)

The pseudo-header order is the key distinction. HTTP/2 clients send pseudo-headers in a specific order that is determined by the implementation, not by the application layer. Chrome, Firefox, Safari, and curl each produce a different order, and that order is stable across versions. Because it sits below the application, it cannot be spoofed by simply reordering headers in user code.

### Akamai fingerprint layout

<div class="tcp-sig-wrap">

<p style="margin:0 0 0.45rem 0; opacity:0.92;"><strong>Akamai HTTP/2</strong> (in <strong>huginn-net-http</strong>) is a <strong>parser / library API</strong>: given the connection preface signals (SETTINGS, flow control, PRIORITY behaviour, pseudo-header order), it produces the printable pipe-separated string and a stable <strong>32-character hex</strong> hash. It does <strong>not</strong> capture packets by itself. You call it from tests, a proxy, or any pipeline that already sees the client HTTP/2.

<div class="tcp-sig-formula"><strong>Shape:</strong> <strong>SETTINGS</strong> | <strong>WINDOW_UPDATE</strong> | <strong>PRIORITY</strong> | <strong>pseudo-headers</strong>, plus an optional stable <strong>hash</strong> (32 hex)</div>

<p style="margin:0.5rem 0 0.35rem 0; font-size:0.92em; opacity:0.9;"><strong>Unpacked.</strong> Pipe-separated segments:</p>

<div class="tcp-sig-example akamai-sig-flow">
<div class="tcp-sig-part wide c1"><code>1:65536;2:0;3:1000;4:6291456;5:16384;6:262144</code><span class="tcp-sig-k">SETTINGS (id:value;…)</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c2"><code>15663105</code><span class="tcp-sig-k">WINDOW_UPDATE</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c3"><code>0</code><span class="tcp-sig-k">PRIORITY</span></div>
<span class="tcp-sig-sep">|</span>
<div class="tcp-sig-part c4"><code>m,p,a,s</code><span class="tcp-sig-k">:method :path …</span></div>
</div>

<p style="margin:0.35rem 0 0.25rem 0; font-size:0.88em; opacity:0.88;"><strong>With PRIORITY frames</strong> (<code>test_akamai_fingerprint_with_priorities</code>): when priorities are present, the middle segment encodes streams such as <code>1:0:0:221,3:0:0:201</code> (stream id, dependency, exclusive flag, weight).</p>

<p class="tcp-sig-note"><strong>Example</strong> (Chrome): <code style="word-break:break-all;">1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,p,a,s</code></p>

</div>

| Segment | Role |
| ------- | ---- |
| SETTINGS | HTTP/2 SETTINGS parameters (`id:value` pairs, semicolon-separated). |
| WINDOW_UPDATE | Initial flow-control / window increment observed on the connection. |
| PRIORITY | `0` if none; otherwise stream dependencies and weights (see tests above). |
| Pseudo-headers | Order of `:method`, `:path`, `:authority`, `:scheme` abbreviated as `m`, `p`, `a`, `s`. The client picks that order. Reordering headers in application code does not change it. |

<p class="tcp-sig-note">Integrators sometimes forward the computed value as HTTP header <code>x-huginn-net-akamai</code> (e.g. a TLS terminator). That header is <strong>not</strong> produced by huginn-net alone. It comes from whatever wires the parser output into your stack. See <a href="#tls-termination-and-the-akamai-fingerprint">TLS termination and the Akamai fingerprint</a>.</p>

### TLS termination and the Akamai fingerprint

**huginn-net-http** only implements the **Akamai fingerprint computation** from HTTP/2 preface inputs you provide. Capture and TLS termination live outside this crate.

The Akamai-style string is meaningless if those inputs were already rewritten. That happens after a hop that rebuilds the HTTP/2 connection and drops the original pseudo-header order.

A TLS-terminating reverse proxy, for example [huginn-proxy](https://github.com/biandratti/huginn-proxy), is one integration: it observes client HTTP/2 at the terminator, runs the fingerprint logic, and injects **`x-huginn-net-akamai`** so backends receive the signal.

The key constraint is always **input fidelity**: the parser produces a meaningful fingerprint only when the HTTP/2 preface it receives still reflects what the client originally sent.
