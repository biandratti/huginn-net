---
name: Unmatched signature
about: A captured TCP or MTU signature did not match the database
labels: signature
---

> A wrong label on a signature that did match is a [bug report](https://github.com/biandratti/huginn-net/issues/new?template=bug_report.md). Use this form when the database has no signature for what you captured (`NotMatched`, or `OS: ???`).

**Checklist**
- [ ] I've searched the issue tracker for this `Sig:` line.
- [ ] I can say what the host actually was (OS or device), not only that the match failed.

**Signature**
Paste the `Sig:` line. That string is what gets added to `p0f.fp`.

```
Sig:
```

**Where it failed**
- Section: TCP SYN (`tcp:request`) / TCP SYN+ACK (`tcp:response`) / MTU
- Reported result (`NotMatched`, `OS: ???`, `Params:`):

**What it actually was**
OS, version, or device. Say how you know (the machine is yours, or a lab host).

**How it was captured**
Example CLI, interface or pcap name, and any filter (`-p`, `-I`). A short pcap helps; the `Sig:` line is enough to start.

**Environment**
- Crate and version (from `Cargo.toml`):
- OS of the host that was fingerprinted:
