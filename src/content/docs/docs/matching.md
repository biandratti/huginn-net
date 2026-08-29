---
title: Matching
description: How TCP and HTTP signatures are matched against the p0f database.
---

When a matcher is attached (`huginn-net-db`, or the umbrella crate with `db`), each TCP SYN / SYN+ACK and each HTTP request / response is compared to the bundled `p0f.fp` signatures.

Matching follows p0f: **a field that does not fit rejects the signature**. There is no error budget and no penalty sum. The outcome is a **tier** (`MatchRank`), not a continuous score.

| Tier | Score | Meaning |
|------|-------|---------|
| `Specific` | `1.0` | Exact fit against a named product |
| `Generic` | `0.8` | Exact fit against a catch-all |
| `Fuzzy(…)` | `0.5` | TCP only: held with a documented TTL or quirk tolerance |
| No match | - | No signature passed the gates |
| Disabled | - | No matcher was attached |

The matcher only names what the signature file contains. The bundled `p0f.fp` last saw a real update in 2012, so modern stacks often land on a generic, a fuzzy TCP hit, or no label at all. For better labels, load a newer `p0f.fp` (`Database::from_str`, same format) instead of `load_default()`. Improving the algorithm cannot invent products that are not in the file.

## TCP

TCP can still land on `Fuzzy` when p0f would: hop count that is hard to trust, or a few header quirks that are allowed to disagree. Everything else must fit exactly.

`Dist` is hop count from TTL (or a post-match guess). It is **not** a quality score.

`Params` annotates the claim (`none` when there is nothing to say):

| Flag | Meaning |
|------|---------|
| `generic` | Hit a catch-all signature |
| `fuzzy (…)` | The match needed a tolerance (`N hops`, `missing …`, `extra …`) |
| `random_ttl` | Signature used a randomised TTL |
| `excess_dist` | Hop count above p0f's `MAX_DIST` (35) |
| `tos:0xNN` | Non-zero DSCP / traffic class |

Only SYN and SYN+ACK emit a TCP OS label (not every ACK).

## HTTP

HTTP has **no fuzzy tier**. A hit is always exact (`Specific` or `Generic`). `Params` may add `dishonest`, `anonymous`, or `generic`.

`UA/OS` on requests compares the User-Agent to the OS seen on this connection's TCP SYN (`NotChecked` / `Consistent` / `Divergent`). That needs the umbrella crate (`huginn-net` with `db` and `tcp-syn`); without the SYN it stays `NotChecked`. `Divergent` is a NAT/proxy hint, not the same as `dishonest`.

## Without a matcher

Protocol crates run in observation-only mode: you still get TCP/HTTP signatures and JA4, but no OS / browser / server labels. See [Quick example](../quick-example/).
