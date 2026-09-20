---
name: Bug report
about: Report a bug or unexpected fingerprint / parse result
labels: bug
---

> Security issues: do **not** use this form — see [SECURITY.md](https://github.com/biandratti/huginn-net/blob/master/SECURITY.md).

**Checklist**
- [ ] I've searched the issue tracker for similar bugs.

**Describe the bug**
A clear description of what went wrong (wrong OS/browser label, parse failure, match tier, etc.).

**To reproduce**
What you ran and on what input (example CLI, `analyze_pcap`, a few lines of code). Attach or name the pcap if you have one.

```rust
// minimal example, if useful
```

**Expected behavior**
What you expected (label, signature string, `Params`, `UA/OS`, …).

**Environment**
- Crate and version (from `Cargo.toml`):
- Rust version (`rustc --version`):
- OS:

**Additional context**
Signature line (`Sig:`), `Params`, or a short pcap if you can share one.
