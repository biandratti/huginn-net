# Security Policy

## Supported Versions

Only the latest stable release of each crate receives security fixes.
Older minor versions are not backported.

| Crate | Supported version |
|-------|------------------|
| `huginn-net` | latest |
| `huginn-net-tcp` | latest |
| `huginn-net-http` | latest |
| `huginn-net-tls` | latest |
| `huginn-net-db` | latest |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please use one of the following private channels:

1. **GitHub Private Vulnerability Reporting** *(preferred)*  
   [Report a vulnerability](https://github.com/biandratti/huginn-net/security/advisories/new)  
   This creates a private advisory visible only to maintainers.

2. **Direct contact**  
   Reach out to the maintainer privately through GitHub: [@biandratti](https://github.com/biandratti).

### What to include

- Affected crate(s) and version(s)
- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested fix (optional but appreciated)

### Response timeline

We will acknowledge the report and work toward a fix as quickly as possible. A public advisory will be published once a patch is available.

We follow responsible disclosure: a CVE or GitHub Security Advisory will be published once a fix is available.

## Automated Security Auditing

This project runs automated security checks on every push and on a daily schedule:

- **[`cargo-audit`](https://github.com/rustsec/rustsec)** — scans `Cargo.lock` against the [RustSec Advisory Database](https://rustsec.org/) for known vulnerabilities in dependencies. Open RUSTSEC issues are tracked and auto-closed when resolved.
- **[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)** — enforces license allowlists and detects duplicate dependencies and banned crates.
- **[`cargo-geiger`](https://github.com/geiger-rs/cargo-geiger)** — verifies that no crate in the workspace uses `unsafe` Rust code (`--forbid-only` mode).

See [`.github/workflows/audit.yml`](.github/workflows/audit.yml) and [`.github/workflows/security.yml`](.github/workflows/security.yml) for the full pipeline.

## Scope

Security reports are in scope for:

- Memory safety issues in huginn-net Rust code
- Incorrect or misleading fingerprinting results that could lead to security decisions based on wrong data
- Dependency vulnerabilities not yet caught by the automated audit pipeline
- Supply chain issues (e.g., compromised dependencies)

Out of scope:

- Vulnerabilities in the operating system or `libpcap` itself
- Issues in companion projects ([huginn-net-profiler](https://github.com/biandratti/huginn-net-profiler), [huginn-proxy](https://github.com/biandratti/huginn-proxy)) — report those in their respective repositories
