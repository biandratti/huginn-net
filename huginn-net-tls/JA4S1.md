# JA4_s1: specification and design decisions

`JA4_s1` / `JA4_rs1` are **huginn-only** fingerprints (`feature = "stable-v1"`).
They are not part of the [FoxIO JA4 specification](https://github.com/FoxIO-LLC/ja4)
and are not interoperable with other JA4 implementations. Official `JA4`, `JA4_r`,
`JA4_o` and `JA4_ro` are untouched by everything below.

## Problem

Official JA4 hashes every extension type present in the ClientHello. Some of those
types are a property of the *connection*, not of the *client*: they appear or
disappear depending on whether the handshake is fresh, resumed, or 0-RTT.

One browser talking to one host over one ALPN therefore produces several JA4
values (the fresh handshake and the resumed one hash differently), which breaks
using JA4 as a database key.

`JA4_s1` answers a narrower question: *what does this stack support?* Same stack,
same ALPN, same SNI presence → **one** row.

## Construction

Same algorithm as `generate_ja4()` (sorted mode), with one change: extension types
are intersected with `S1_EXTENSION_ALLOWLIST` before both the `JA4_a` extension
count and the `JA4_c` hash.

```text
extensions → ∩ allowlist → drop GREASE → count (JA4_a)
                                       → drop SNI + ALPN, sort → JA4_c
```

Unchanged from official JA4:

| Field | Source |
|-------|--------|
| protocol / version | highest non-GREASE `supported_versions`, else legacy version |
| `d` / `i` | `server_name` present in the **raw** ClientHello |
| cipher count, `JA4_b` | non-GREASE cipher suites, sorted |
| ALPN chars | first/last byte of the first ALPN value |
| signature algorithms | non-GREASE, **original order**, appended to `JA4_c` |

So `JA4_s1` still separates HTTP/1.1 from h2 (ALPN) and SNI from no-SNI (`d`/`i`).
That is intentional: those are different observations, not session noise.

## Allowlist, not denylist

The first cut subtracted a fixed set of session extensions (`padding` 0x0015,
`session_ticket` 0x0023, `pre_shared_key` 0x0029). That is a denylist, and a
denylist fails on anything it has not seen: a resumption companion such as
`early_data` (0x002a), a new draft extension, or a vendor-specific ID still changed
the key.

`S1_EXTENSION_ALLOWLIST` inverts it: it enumerates the capability extensions that
are hashed, and **everything not listed is dropped**, including unknown and future
IDs. The failure mode moves from "s1 silently splits" to "a new capability is
ignored until it is added on purpose", which is recoverable and a deliberate
breaking bump.

### Hashed (`S1_EXTENSION_ALLOWLIST`)

`0000` server_name, `0005` status_request, `000a` supported_groups,
`000b` ec_point_formats, `000d` signature_algorithms, `0010` ALPN,
`0012` signed_certificate_timestamp, `0017` extended_master_secret,
`001b` compress_certificate, `001c` record_size_limit, `0022` delegated_credential,
`002b` supported_versions, `0031` post_handshake_auth,
`0032` signature_algorithms_cert, `0033` key_share, `4469`/`44cd` ALPS,
`fe0d` ECH, `ff01` renegotiation_info.

Kept sorted; lookup is a binary search.

### Dropped, and why

| ID | Extension | Reason |
|----|-----------|--------|
| `0015` | padding (RFC 7685) | covaries with ClientHello size |
| `0023` | session_ticket (RFC 5077) | present only with a cached ticket |
| `0029` | pre_shared_key (RFC 8446) | resumption |
| `002a` | early_data (RFC 8446) | 0-RTT, travels with the PSK |
| `002c` | cookie (RFC 8446) | HelloRetryRequest only |
| `002d` | psk_key_exchange_modes (RFC 8446) | some stacks send it only when offering a PSK, which flips s1 between fresh and resumed handshakes |
| GREASE | RFC 8701 | random by design |
| unlisted | e.g. `0xca34`, unparsed IDs | not audited as always-on |

`002d` is the one judgement call: it is always present in some browsers and
conditional in others. Since s1 exists to survive resumption, the conditional case
wins and the extension is excluded, losing a bit of build signal to gain the
invariant.

## Curation rule

An ID is added only if both hold:

1. **Empirical.** Across ≥10 ClientHellos per browser to the same host with the
   same ALPN (fresh + resume + 0-RTT), `∪ − ∩` of the extension sets does not
   contain it. Extraction: `tshark -Y tls.handshake.type==1 -T fields -e tls.handshake.extension.type`.
2. **Normative.** No RFC defines it as a session, resumption, or retry parameter,
   even if a given capture never shows it flipping.

An ID observed flipping is removed. Scope is **browser** traffic; a custom TLS
client that gates a listed extension on session state is out of scope.

## Invariants

- session / resumption types and unknown IDs do not change s1
- fresh, resumed and 0-RTT handshakes from one client collapse to one s1
- ALPN and SNI presence still separate
- s1 equals official JA4 when only allowlisted types are present

Not an invariant: that the allowlist holds for every browser build ever shipped. It
is empirical, so it is versioned: a capture that breaks the collapse removes an ID
and bumps s1.

Observed: the six Safari ClientHellos in `macos_safari_tls_extensions.pcap` produce
two official JA4 values (`t13d1516h2_8daaf6152771_d8a2da3f94cd` four times,
`t13d1517h2_8daaf6152771_b6f405a00624` twice) and one `JA4_s1`
(`t13d1514h2_8daaf6152771_f835621b68aa`).

## References

- [JA4 specification, FoxIO LLC](https://github.com/FoxIO-LLC/ja4): official `JA4`/`JA4_r`/`JA4_o`/`JA4_ro`
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) TLS 1.3: `pre_shared_key`, `early_data`, `cookie`, `psk_key_exchange_modes`
- [RFC 5077](https://www.rfc-editor.org/rfc/rfc5077) session tickets, [RFC 7685](https://www.rfc-editor.org/rfc/rfc7685) padding, [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) GREASE
- [IANA TLS ExtensionType values](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
- [Is JA4 Now Obsolete?](https://www.ntop.org/is-ja4-now-obsolete/): ntop, on JA4 instability
