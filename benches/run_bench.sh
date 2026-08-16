#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# run_bench.sh — Run a huginn-net benchmark 5 times and save output to .txt
#
# Usage:
#   ./benches/run_bench.sh <tls|http|tcp>
#
# Output:
#   benches/reports/bench_<type>_<branch>_<commit>_<timestamp>.txt
# ---------------------------------------------------------------------------

BENCH_TYPE="${1:-}"

if [[ -z "$BENCH_TYPE" ]]; then
    echo "Usage: $0 <tls|http|tcp>"
    exit 1
fi

# Bench targets declare required-features; cargo skips them unless enabled.
case "$BENCH_TYPE" in
    tcp)
        PACKAGE="huginn-net-tcp"
        FEATURES="full"
        ;;
    http)
        PACKAGE="huginn-net-http"
        FEATURES="full"
        ;;
    tls)
        PACKAGE="huginn-net-tls"
        FEATURES=""
        ;;
    *)
        echo "Error: unknown bench type '$BENCH_TYPE'. Must be one of: tls, http, tcp"
        exit 1
        ;;
esac

RUNS=5
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
mkdir -p "$REPORTS_DIR"

GIT_BRANCH=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "no-branch")
GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "no-commit")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Sanitize branch name for use in filename (replace / and spaces)
SAFE_BRANCH="${GIT_BRANCH//\//-}"
SAFE_BRANCH="${SAFE_BRANCH// /_}"

OUTPUT_FILE="${REPORTS_DIR}/bench_${BENCH_TYPE}_${SAFE_BRANCH}_${GIT_COMMIT}_${TIMESTAMP}.txt"

CARGO_BENCH=(cargo bench -p "$PACKAGE")
if [[ -n "$FEATURES" ]]; then
    CARGO_BENCH+=(--features "$FEATURES")
fi

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
{
    echo "==============================================================================="
    echo "  huginn-net benchmark report"
    echo "==============================================================================="
    echo "  Type      : ${BENCH_TYPE}"
    echo "  Package   : ${PACKAGE}"
    echo "  Features  : ${FEATURES:-"(none)"}"
    echo "  Branch    : ${GIT_BRANCH}"
    echo "  Commit    : ${GIT_COMMIT}"
    echo "  Date      : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Runs      : ${RUNS}"
    echo "==============================================================================="
    echo ""
} | tee "$OUTPUT_FILE"

# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------
for i in $(seq 1 $RUNS); do
    {
        echo "-------------------------------------------------------------------------------"
        echo "  RUN ${i} / ${RUNS}  —  $(date '+%H:%M:%S')"
        echo "-------------------------------------------------------------------------------"
        echo ""
    } | tee -a "$OUTPUT_FILE"

    "${CARGO_BENCH[@]}" 2>&1 | tee -a "$OUTPUT_FILE"

    echo "" | tee -a "$OUTPUT_FILE"
done

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
{
    echo "==============================================================================="
    echo "  All ${RUNS} runs completed"
    echo "  Report saved to: ${OUTPUT_FILE}"
    echo "==============================================================================="
} | tee -a "$OUTPUT_FILE"
