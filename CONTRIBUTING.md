# Contributing to huginn-net

Thank you for your interest in contributing to huginn-net! This document covers everything you need to get started.

## Table of Contents

- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Quality](#code-quality)
- [Commit & Branch Conventions](#commit--branch-conventions)
- [Pull Requests](#pull-requests)
- [Reporting Issues](#reporting-issues)
- [Security](#security)
- [Code of Conduct](#code-of-conduct)

---

## Project Structure

huginn-net is a Cargo workspace with multiple crates:

| Crate | Purpose |
|-------|---------|
| `huginn-net` | Unified multi-protocol fingerprinting (TCP + HTTP + TLS) |
| `huginn-net-tcp` | TCP/OS fingerprinting (p0f-inspired) |
| `huginn-net-http` | HTTP header analysis |
| `huginn-net-tls` | TLS/JA4 fingerprinting |
| `huginn-net-db` | Signature database parsing |

Changes affecting public APIs should also update the relevant `README.md` inside the crate directory and `MIGRATION.md` if they introduce breaking changes.

---

## Getting Started

1. **Fork** the repository on GitHub and clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/huginn-net.git
   cd huginn-net
   ```

2. **Install Rust** via [rustup.rs](https://rustup.rs/) (stable toolchain):
   ```bash
   rustup toolchain install stable
   ```

3. **Install required system dependency** for live capture:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libpcap-dev
   # macOS
   brew install libpcap
   ```

4. **Verify everything builds and tests pass:**
   ```bash
   cargo build --all
   cargo test --all
   ```

---

## Development Workflow

1. Create a branch from `master` following the [naming conventions](#commit--branch-conventions) below
2. Make your changes in the relevant crate(s)
3. Add or update tests for new or modified functionality
4. Run the [code quality checks](#code-quality)
5. Commit using [conventional commits](#commit--branch-conventions)
6. Open a pull request against `master`

---

## Code Quality

Before opening a PR, ensure all of the following pass locally:

```bash
# Format code
cargo fmt --all

# Run the full test suite
cargo test --all

# Lint — same flags used in CI
cargo clippy --workspace --all-features --all-targets -- \
  -D warnings \
  -D clippy::expect_used \
  -D clippy::unreachable \
  -D clippy::arithmetic_side_effects \
  -D clippy::unwrap_used \
  -D clippy::todo \
  -D clippy::redundant_clone \
  -D clippy::unimplemented \
  -D clippy::missing_panics_doc \
  -D clippy::redundant_field_names

# Check for security advisories and license issues
cargo deny check
```

### Guidelines

- **Error handling**: Use `Result<T, E>` — avoid `panic!`, `unwrap()`, and `expect()` in library code
- **Memory safety**: No unsafe code; all crates are verified with `cargo-geiger --forbid-only`
- **Documentation**: Add doc comments (`///`) for all public types and functions
- **Testing**: Write unit tests for new functionality; integration tests go in `tests/`
- **Performance**: Avoid unnecessary allocations in hot paths; see [benches/README.md](benches/README.md)
- **Functional style**: Prefer iterators and combinators over imperative loops where it aids readability

---

## Commit & Branch Conventions

### Branch naming

```
feature/<short-description>    # new feature
fix/<short-description>        # bug fix
docs/<short-description>       # documentation only
refactor/<short-description>   # code refactoring
chore/<short-description>      # tooling, CI, dependency bumps
```

### Commit messages

Use clear, descriptive messages in the imperative mood (`add`, `fix`, `update`). Reference issues when relevant (`Closes #42`).

---

## Pull Requests

- Keep PRs **focused** — one feature or fix per PR
- Reference related issues with `Closes #<number>` or `Fixes #<number>`
- For **breaking changes**, update `MIGRATION.md` with a before/after example
- Ensure all CI checks pass before requesting review
- Respond to review comments within a reasonable timeframe

### Labels

Apply the appropriate label so the release notes are generated correctly:

| Label | When to use |
|-------|------------|
| `enhancement` | New feature or improvement |
| `bug` | Bug fix |
| `documentation` | Docs-only change |
| `dependencies` | Dependency bump |

---

## Reporting Issues

### Bug reports

Include the following when filing a bug:

- Rust version: `rustc --version`
- Operating system and architecture
- Crate and version affected
- Steps to reproduce
- Expected vs. actual behavior
- Minimal reproducible example (if possible)

### Feature requests

Describe the use case clearly — what problem does it solve? Link to any relevant specs (e.g., p0f fingerprint database format, JA4 spec).

---

## Security

For security vulnerabilities, **do not open a public issue**. Please follow the process described in [SECURITY.md](SECURITY.md).

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.
