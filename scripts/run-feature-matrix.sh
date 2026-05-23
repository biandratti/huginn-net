#!/usr/bin/env bash
#
# Run every combo in `scripts/feature-matrix.json` sequentially on a single
# runner. Each combo invokes `scripts/check-features.sh`, whose output is
# already wrapped in `::group::` blocks, so the GitHub Actions log shows
# each feature combination as a collapsible section.
#
# On completion this script:
#   * prints a PASS/FAIL summary table to stdout
#   * appends the same table (in Markdown) to $GITHUB_STEP_SUMMARY when
#     running under GitHub Actions, so the result is visible directly on
#     the PR check page
#   * exits 0 when every combo passed, 1 otherwise
#
# Failures do NOT abort the run — every combo is exercised so the summary
# shows the full picture in a single CI iteration.
#
# Usage:
#   scripts/run-feature-matrix.sh                  # runs everything
#   scripts/run-feature-matrix.sh huginn-net-tcp   # filters by crate (substring match)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX="${SCRIPT_DIR}/feature-matrix.json"
CHECK="${SCRIPT_DIR}/check-features.sh"
FILTER="${1:-}"

if [[ ! -f "$MATRIX" ]]; then
    echo "feature-matrix.json not found at $MATRIX" >&2
    exit 2
fi
if [[ ! -x "$CHECK" ]]; then
    echo "check-features.sh not executable at $CHECK" >&2
    exit 2
fi

results_file=$(mktemp)
trap 'rm -f "$results_file"' EXIT

US=$'\x1f'

total=$(jq --arg f "$FILTER" '[.[] | select($f == "" or (.crate | contains($f)))] | length' "$MATRIX")
if [[ "$total" -eq 0 ]]; then
    echo "no matrix entries matched filter '$FILTER'" >&2
    exit 2
fi

echo "Running $total feature combinations sequentially..."
echo

idx=0
while IFS="$US" read -r crate features label with_tests with_bench; do
    idx=$((idx + 1))

    flags=()
    if [[ "$with_tests" == "true" ]]; then
        flags+=(--with-tests)
    fi
    if [[ "$with_bench" == "true" ]]; then
        flags+=(--with-bench)
    fi

    echo "[$idx/$total] $crate -- $label"

    if "$CHECK" "$crate" "$features" "${flags[@]}"; then
        status=PASS
    else
        status=FAIL
    fi

    display_features="${features:-(default)}"
    printf '%s\t%s\t%s\t%s\n' "$status" "$crate" "$label" "$display_features" >> "$results_file"
done < <(
    jq -r --arg f "$FILTER" --arg d "$US" '
        .[]
        | select($f == "" or (.crate | contains($f)))
        | [.crate, .features, .label, (.with_tests // false | tostring), (.with_bench // false | tostring)]
        | join($d)
    ' "$MATRIX"
)

pass=$(awk -F'\t' '$1=="PASS"' "$results_file" | wc -l)
fail=$(awk -F'\t' '$1=="FAIL"' "$results_file" | wc -l)

echo
echo "================ FEATURE MATRIX SUMMARY ================"
printf 'STATUS\tCRATE\tLABEL\tFEATURES\n%s\n' "$(cat "$results_file")" \
    | column -t -s $'\t'
echo "--------------------------------------------------------"
echo "Passed: $pass / $total"
echo "Failed: $fail / $total"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## Feature matrix"
        echo
        echo "**Total:** $total **·** **Passed:** $pass **·** **Failed:** $fail"
        echo
        echo "| Status | Crate | Label | Features |"
        echo "|--------|-------|-------|----------|"
        awk -F'\t' '{
            features = ($4 == "(default)" ? "_(default)_" : "`" $4 "`")
            printf "| **%s** | `%s` | %s | %s |\n", $1, $2, $3, features
        }' "$results_file"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ $fail -eq 0 ]]; then
    exit 0
fi
exit 1
