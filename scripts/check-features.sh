#!/usr/bin/env bash
#
# Run build + clippy (+ optional tests / bench link) for a single
# (crate, features) combination. Used by `scripts/feature-matrix.json`
# from CI and locally to reproduce a single matrix entry.
#
# Usage:
#   scripts/check-features.sh <crate> <features> [--with-tests] [--with-bench]
#
# Examples:
#   scripts/check-features.sh huginn-net-tcp ""               # default build
#   scripts/check-features.sh huginn-net-tcp full --with-tests --with-bench
#   scripts/check-features.sh huginn-net     full --with-tests
#
# `<features>` is a comma-separated list as accepted by `cargo build --features`.
# Passing an empty string builds with `--no-default-features` and no extras.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <crate> <features> [--with-tests] [--with-bench]" >&2
    exit 2
fi

CRATE="$1"
FEATURES="$2"
shift 2

WITH_TESTS=false
WITH_BENCH=false
for arg in "$@"; do
    case "$arg" in
        --with-tests) WITH_TESTS=true ;;
        --with-bench) WITH_BENCH=true ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

COMMON=(--no-default-features)
if [[ -n "$FEATURES" ]]; then
    COMMON+=(--features "$FEATURES")
fi

# When running under GitHub Actions, group output for collapsible logs.
group_open()  { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::group::$*" || echo ">>> $*"; }
group_close() { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::endgroup::"        || true; }

group_open "Build $CRATE (features='$FEATURES')"
cargo build -p "$CRATE" "${COMMON[@]}" --lib
group_close

group_open "Clippy $CRATE (features='$FEATURES')"
cargo clippy -p "$CRATE" "${COMMON[@]}" --lib -- -D warnings
group_close

if [[ "$WITH_TESTS" == "true" ]]; then
    group_open "Tests $CRATE (features='$FEATURES')"
    cargo test -p "$CRATE" "${COMMON[@]}" --tests
    group_close
fi

if [[ "$WITH_BENCH" == "true" ]]; then
    group_open "Bench link $CRATE (features='$FEATURES')"
    cargo bench -p "$CRATE" "${COMMON[@]}" --no-run
    group_close
fi
