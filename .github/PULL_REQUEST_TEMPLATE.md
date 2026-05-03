<!-- Summary of the change and why it's needed. Reference related issues with #number. -->

## How has this been tested?

<!-- Describe what you ran to verify the change: unit tests, integration tests, manual testing, etc. Include OS and Rust version. -->

## Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace --all-features --all-targets -- -D warnings -D clippy::expect_used -D clippy::unwrap_used -D clippy::unreachable -D clippy::todo -D clippy::unimplemented -D clippy::arithmetic_side_effects -D clippy::redundant_clone -D clippy::missing_panics_doc -D clippy::redundant_field_names` passes
- [ ] `cargo test --all` passes
- [ ] Breaking changes documented in `MIGRATION.md`
