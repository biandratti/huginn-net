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

This is a known property of JA4, reported to FoxIO as
[issue #303](https://github.com/FoxIO-LLC/ja4/issues/303). Independently of ntop's
writeup, several implementations hit the same split and converged on dropping a
small set of session / resumption types.

FoxIO's position (John Althouse, 2026-07-21) is that the split is **intentional**:
a library doing something different (initial vs resumed) is useful signal, and
lookup tables should hold the few fingerprints per stack rather than collapsing
them. A `JA4_e` sibling that ignores those extensions was left as optional, not
adopted as the spec.

huginn takes the other side of that trade-off. `JA4_s1` is the matcher key:
*what does this stack support?* Same stack, same ALPN, same SNI presence →
**one** row. Official JA4 is still emitted unchanged for anyone who wants the
session-state signal FoxIO keeps.

Because s1 is a denylist, a new session / resumption extension in a future TLS
revision will split the key again until that ID is added to
`S1_SESSION_EXTENSIONS` (a breaking s1 bump). That is accepted: the list is
versioned, not claimed complete forever.

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

### Dropped (`S1_SESSION_EXTENSIONS`)

| ID | Extension | Reason | Basis |
|----|-----------|--------|-------|
| `0015` | padding (RFC 7685) | covaries with ClientHello size | measured flipping |
| `0023` | session_ticket (RFC 5077) | present only with a cached ticket | measured flipping |
| `0029` | pre_shared_key (RFC 8446) | resumption | measured flipping, dominant splitter |
| `002a` | early_data (RFC 8446) | RFC 8446 §4.2.10 permits it only alongside a PSK | protocol only, no capture |

GREASE never reaches s1 either, but that is the JA4 algorithm's doing, one layer
earlier, not this list's.

Kept sorted; lookup is a binary search.

This is not a huginn invention. `0015` / `0023` / `0029` are what nDPI strips
behind `tls,metadata.ja_ignore_ephemeral_tls_extn`, what other implementations
independently converged on, and what
[ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303) proposes to FoxIO.
Reported there: on a controlled capture matrix, stripping those three collapsed
51 distinct (cipher, extension, sigalg) keys to 40. `002a` is a fourth that the
same thread argues for enabling by default.

`002a` is on the list unmeasured on purpose. It cannot appear on a fresh Hello, so
a deployment that turns on 0-RTT would otherwise split resumed-0-RTT Hellos from
resumed-non-0-RTT ones. Where 0-RTT is off, stripping it costs nothing.

### Candidates, currently out

`cookie` (`002c`) appears only in the second Hello of a HelloRetryRequest exchange
(RFC 8446 §4.2.2), and `psk_key_exchange_modes` (`002d`) is mandatory when
offering a PSK (RFC 8446 §4.2.9), so a stack could send it only then. Both
mechanisms are real, but neither ID is part of the converged set above and
neither has been observed splitting a key.

`002d` in particular would cost signal today: in `macos_tcp_flags.pcap` and
`macos_safari_tls_extensions.pcap` it is present on cold Hellos with no ticket or
PSK anywhere, so it is behaving as a capability, not as session state. Dropping it
on the strength of a hypothesis is the wrong trade. Both go on the list when a
capture shows one of them splitting a key, which bumps s1.

### Out for good

`cached_info` (`0019`, RFC 7924), `ticket_pinning` (`0020`, RFC 8672) and
`ticket_request` (`003a`, RFC 9149) are session state per RFC but no shipping
client emits them. Dropping them collapses nothing and only widens the blind spot
for whatever later claims those codepoints.

## Denylist, not allowlist

The inverse design, enumerating the capability types that *are* hashed and
dropping everything else, was implemented and then reverted. Two reasons.

**It cost measurable signal and bought none.** Across the capture corpus, every
split that s1 had to repair came from `pre_shared_key` appearing and `padding`
disappearing, both of which a denylist removes, so the collapse was identical
either way. What differed is what the allowlist discarded on top: Chrome 70 and
Chrome 72, which differ only by the unlisted `7550` channel_id, collapsed into one
key, and `0xca34` vanished from the FoxIO `sigalg-grease` capture. Neither has
anything to do with sessions.

**Its failure mode is untestable.** A denylist fails when a new flipping extension
ships: the key splits, `test_pcap_group_yields_single_ja4_s1` goes red, and the
damage is confined to the one stack that emits it while existing rows keep
working. An allowlist fails when a new always-on capability ships: it is silently
ignored, two genuinely different stacks collapse into one key, and no test can
catch it, because "s1 did not change" is indistinguishable from correct behaviour.
For a fingerprinting library the silent merge is the worse error, since it yields a
wrong attribution rather than a miss.

The base rates point the same way. Session semantics have been essentially closed
since RFC 8446 in 2018, while capability extensions keep arriving (ECH, ALPS and
its codepoint move, `compress_certificate`, `record_size_limit`, post-quantum key
shares). An allowlist taxes the frequent event to insure against the rare one.

## Curation rule

An ID is dropped only if all three hold:

1. **Normative.** An RFC defines it as a session, resumption, or retry parameter.
2. **Evidenced.** Either it has been observed splitting a key, or an RFC makes its
   presence *impossible* outside the session state s1 already strips. `002a`
   qualifies on the second clause alone. `002c` and `002d` fail this test today:
   the mechanism is plausible but no capture or implementation reports it, and for
   `002d` the corpus shows the opposite, so both stay candidates.
3. **Deployed.** A shipping TLS stack actually emits it. This keeps
   `0019` / `0020` / `003a` off: an extension nobody sends cannot split a key, so
   listing it is pure blind spot.

The corpus is a check in the reverse direction, not the source of the list: across
≥10 ClientHellos per browser to the same host with the same ALPN,
`∪ − ∩` of the extension sets must be a subset of this list. Extraction:
`tshark -Y tls.handshake.type==1 -T fields -e tls.handshake.extension.type`.
It holds two client stacks and no 0-RTT, so it confirms only that no ID *outside*
the list flips; `0015` and `0029` are the two seen flipping in it.

An ID observed flipping outside the list is added, which bumps s1. Scope is
**browser** traffic; a custom TLS client that gates a capability extension on
session state is out of scope.

## Invariants

- session / resumption types and GREASE do not change s1
- fresh, resumed and 0-RTT handshakes from one client collapse to one s1
- ALPN and SNI presence still separate
- an unassigned or unknown type still changes s1, exactly as in official JA4
- s1 equals official JA4 when no session type is present

Not an invariant: that the list is complete for every browser build ever shipped.
It is versioned: a capture that breaks the collapse adds an ID and bumps s1.

## Hardcoded list vs excluded extensions

`S1_SESSION_EXTENSIONS` is a `const` denylist. Default capture calls
`generate_ja4_stable_v1()` (hardcoded `binary_search`). That is the comparable
`ja4_s1` key.

Two ways to widen the list (additive: extra IDs on top of the const denylist):

- Parser-only: `Signature::generate_ja4_stable_v1_excluding`. Empty `excluded`
  delegates to the canonical method (no clone).
- Capture (`HuginnNetTls`, sequential and parallel):
  `with_s1_excluded_extensions`. Empty excluded is the canonical path. Not
  part of `FilterConfig` (that drops packets before parse).

Values with a non-empty `excluded` list are tagged `ja4_s1` but are **not**
comparable across deployments. Keep the empty / default list for shared
database keys.

```rust
let canonical = sig.generate_ja4_stable_v1();
let widened = sig.generate_ja4_stable_v1_excluding(&[0xbeef]);

let analyzer = HuginnNetTls::new(10000).with_s1_excluded_extensions([0xbeef]);
```

The clone-and-`retain` workaround that calls `generate_ja4()` still works and
produces the same `value()`. Its payload tag is `ja4`, not `ja4_s1`. The `d`/`i`
indicator is read from `extensions` after the excluded IDs are dropped
(pathological only if `excluded` included SNI).

### Cost (`benches/bench_ja4s1.rs`)

Signature-level, ClientHello from `macos_safari_tls_extensions.pcap` (16
extensions, 2 session types dropped). Criterion `--quick`, this machine.

| bench | time | vs hardcoded s1 |
|-------|------|-----------------|
| `ja4_official` (`generate_ja4`) | 2.28 µs | −5% |
| `s1_canonical_hardcoded` (`generate_ja4_stable_v1`) | 2.41 µs | baseline |
| `s1_excluding_empty` (`excluding(&[])`) | same path as baseline | no clone |
| `s1_excluding_three` (`excluding(&[3 ids])`) | clone + retain + s1 | optional path only |
| `s1_prefilter_canonical_list` | 2.63 µs | +9% |
| `s1_prefilter_wider_list` | 2.51 µs | +4% |

The optional path's extra cost is a clone plus `retain` (~0.1–0.2 µs). Full TLS
packet processing is ~5.6 µs, so the delta is invisible on the capture path. The
canonical method is unchanged, so capture never pays it.

| | Hardcoded (`generate_ja4_stable_v1`) | `excluding` (optional) |
|--|-------------------------------------|------------------------|
| Pros | One meaning of `ja4_s1` on the wire; analyzer never clones | Reacts to a new session type without a crate release; tagged `ja4_s1` |
| Cons | A new flipping extension splits keys until the next s1 bump | Non-empty `excluded` is not comparable across deployments |

## References

- [JA4 specification, FoxIO LLC](https://github.com/FoxIO-LLC/ja4): official `JA4`/`JA4_r`/`JA4_o`/`JA4_ro`
- [FoxIO-LLC/ja4#303](https://github.com/FoxIO-LLC/ja4/issues/303): ephemeral-extension-invariant proposal (`JA4E`); FoxIO keeps the split in official JA4
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) TLS 1.3: `pre_shared_key`, `early_data`, `cookie`, `psk_key_exchange_modes`
- [RFC 5077](https://www.rfc-editor.org/rfc/rfc5077) session tickets, [RFC 7685](https://www.rfc-editor.org/rfc/rfc7685) padding, [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) GREASE
- [IANA TLS ExtensionType values](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
- [Is JA4 Now Obsolete?](https://www.ntop.org/is-ja4-now-obsolete/): ntop, on JA4 instability
