# Contributing to huginn-net

Thank you for your interest in contributing!

## Quick Start

1. Fork and clone the repository
2. Install Rust from [rustup.rs](https://rustup.rs/)
3. Run `cargo test` to ensure everything works

## Development

### Making Changes

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/huginn-net.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Add tests for new functionality
6. Run the checks below
7. Submit a pull request

### Code Quality

Before submitting, run these commands:

```bash
# Format code
cargo fmt

# Run tests
cargo test

# Check lints
cargo clippy --all-features --all-targets -- -D warnings -D clippy::expect_used -D clippy::unreachable -D clippy::arithmetic_side_effects -D clippy::unwrap_used -D clippy::todo -D clippy::redundant_clone -D clippy::unimplemented -D clippy::missing_panics_doc -D clippy::redundant_field_names
```

### Guidelines

- **Error Handling**: Use `Result<T, E>` instead of `panic!` in library code
- **Memory Safety**: Avoid `unwrap()` and `expect()` in production code
- **Functional Style**: Prefer functional patterns when appropriate
- **Documentation**: Add doc comments for public APIs
- **Testing**: Write tests for new functionality

## Pull Requests

- Use clear, descriptive titles
- Reference related issues with `#issue-number`
- Ensure all CI checks pass
- Keep changes focused (one feature/fix per PR)

## Reporting Issues

For bugs, include:
- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Minimal code example

For security issues, contact maintainers directly instead of opening public issues.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Questions?

Feel free to open an issue for discussion or contact the maintainers directly.
