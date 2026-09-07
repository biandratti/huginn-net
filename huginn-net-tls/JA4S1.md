# JA4_s1: specification and design decisions

`JA4_s1` / `JA4_rs1` are **huginn-only** fingerprints (`feature = "stable-v1"`).
They are not part of the [FoxIO JA4 specification](https://github.com/FoxIO-LLC/ja4)
and are not interoperable with other JA4 implementations. Official `JA4`, `JA4_r`,
`JA4_o` and `JA4_ro` are untouched by everything below.

## Problem

Official JA4 hashes every extension type in the ClientHello. Types that come
and go with fresh / resumed / 0-RTT handshakes are a property of the
*connection*, not the *client*, so one stack talking to one host over one ALPN
gets several keys. That split is documented in
[FoxIO-LLC/ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303).

`JA4_s1` is huginn's matcher: same stack, same ALPN, same SNI presence → **one**
row. Official JA4 is still emitted unchanged.

## Construction

Same algorithm as `generate_ja4()` (sorted mode), with one change: the extension
types in `S1_SESSION_EXTENSIONS` are removed before both the `JA4_a` extension
count and the `JA4_c` hash. Every other type is hashed exactly as official JA4
hashes it.

```text
extensions → drop session types → drop GREASE → count (JA4_a)
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
GREASE is stripped by official JA4, one layer earlier, not by this list.

## `S1_SESSION_EXTENSIONS`

An ID is on the denylist only if all three hold:

1. **Normative.** An RFC defines it as a session, resumption, or retry parameter.
2. **Evidenced.** It has been observed splitting a key, or an RFC makes its
   presence impossible outside session state s1 already strips.
3. **Deployed.** A shipping TLS stack emits it.

Sorted; lookup is a binary search.

| ID | Normative | Evidenced | Deployed |
|----|-----------|-----------|----------|
| `0015` padding | RFC 7685 | flips with ClientHello size | browsers |
| `0023` session_ticket | RFC 5077 | present only with a cached ticket | browsers |
| `0029` pre_shared_key | RFC 8446 | dominant resume splitter | browsers |
| `002a` early_data | RFC 8446 §4.2.10 (only with PSK) | RFC: cannot appear on a fresh Hello | 0-RTT stacks |

`0015` / `0023` / `0029` are what nDPI strips
(`tls,metadata.ja_ignore_ephemeral_tls_extn`) and what
[ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303) proposes: on that
matrix those three collapsed 51 keys to 40. `002a` is the fourth that thread
argues to enable by default; huginn takes it on the RFC clause (no 0-RTT
capture here). Without it, 0-RTT resume would split from non-0-RTT resume.

The corpus checks the list; it does not invent it. Across ≥10 ClientHellos per
browser to the same host with the same ALPN, `∪ − ∩` of the extension sets
must be a subset of these IDs. Extraction:
`tshark -Y tls.handshake.type==1 -T fields -e tls.handshake.extension.type`.
That corpus has two client stacks and no 0-RTT: `0015` and `0029` are the two
seen flipping there; `0023` and `002a` still qualify on the table.

Scope is **browser** traffic.

## Invariants

Same stack, same ALPN, same SNI presence (`d`/`i`):

- IDs in `S1_SESSION_EXTENSIONS` (and GREASE) do not move the key
- fresh, resumed and 0-RTT Hellos collapse to one s1
- different ALPN or SNI presence → different s1
- any other type, including unknown, moves s1, same as official JA4
- if the Hello has none of the denylist IDs, s1 equals official JA4

The list is versioned, not complete forever. A capture that splits s1 adds an ID
and bumps the variant.

## Extra exclusions (workaround, then contribute)

Default capture uses the hardcoded denylist `S1_SESSION_EXTENSIONS`
(`generate_ja4_stable_v1()`). That is the shared `ja4_s1` key.

`generate_ja4_stable_v1_excluding` and `HuginnNetTls::with_s1_excluded_extensions`
add IDs on top of that list. Empty `excluded` is the canonical path. A non-empty
list is still tagged `ja4_s1`, but those values are not comparable across
deployments.

The extra list exists so a new flipping type can be dropped locally without
waiting for a crate release. The useful end state is to **contribute that ID
to `S1_SESSION_EXTENSIONS`** (a breaking s1 bump) so everyone shares the same
key again. A private denylist forever is not the design.

### Cost (`benches/bench_ja4s1.rs`)

First ClientHello of `macos_safari_tls_extensions.pcap` (16 extensions,
15 ciphers, 1 session type dropped). This machine; absolute µs do not travel.

| bench | time |
|-------|------|
| `ja4_official` | 4.19 µs |
| `s1_canonical_hardcoded` | 4.86 µs |
| `s1_excluding_empty` | 4.58 µs |
| `s1_excluding_three` | 4.76 µs |
| `s1_prefilter_canonical_list` | 4.83 µs |
| `s1_prefilter_wider_list` | 4.86 µs |

Official JA4 is cheaper (no denylist). All s1 paths are 4.6–4.9 µs, inside
Criterion noise. Packet TLS is ~5.6 µs; cost is not why the feature exists.

## References

- [JA4 specification, FoxIO LLC](https://github.com/FoxIO-LLC/ja4): official `JA4`/`JA4_r`/`JA4_o`/`JA4_ro`
- [FoxIO-LLC/ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303): ephemeral-extension-invariant proposal (`JA4E`); FoxIO keeps the split in official JA4
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) TLS 1.3: `pre_shared_key`, `early_data`, `cookie`, `psk_key_exchange_modes`
- [RFC 5077](https://www.rfc-editor.org/rfc/rfc5077) session tickets, [RFC 7685](https://www.rfc-editor.org/rfc/rfc7685) padding, [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) GREASE
- [IANA TLS ExtensionType values](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
- [Is JA4 Now Obsolete?](https://www.ntop.org/is-ja4-now-obsolete/): ntop, on JA4 instability
