#!/usr/bin/env bash
#
# Run every entry in scripts/feature-matrix.json sequentially on a single runner.
# Usage:
#   scripts/feature-matrix.sh                  # run every combo
#   scripts/feature-matrix.sh huginn-net-tcp   # filter by crate substring

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX="${SCRIPT_DIR}/feature-matrix.json"
FILTER="${1:-}"

if [[ ! -f "$MATRIX" ]]; then
    echo "feature-matrix.json not found at $MATRIX" >&2
    exit 2
fi

US=$'\x1f'

group_open()  { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::group::$*" || echo ">>> $*"; }
group_close() { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::endgroup::"        || true; }

check_combo() {
    local crate="$1" features="$2" with_tests="$3" with_bench="$4"

    local common=(--no-default-features)
    if [[ -n "$features" ]]; then
        common+=(--features "$features")
    fi

    local rc=0

    group_open "Build $crate (features='$features')"
    cargo build -p "$crate" "${common[@]}" --lib || rc=$?
    group_close
    if [[ $rc -ne 0 ]]; then return $rc; fi

    group_open "Clippy $crate (features='$features')"
    cargo clippy -p "$crate" "${common[@]}" --lib -- -D warnings || rc=$?
    group_close
    if [[ $rc -ne 0 ]]; then return $rc; fi

    if [[ "$with_tests" == "true" ]]; then
        group_open "Tests $crate (features='$features')"
        cargo test -p "$crate" "${common[@]}" --tests || rc=$?
        group_close
        if [[ $rc -ne 0 ]]; then return $rc; fi
    fi

    if [[ "$with_bench" == "true" ]]; then
        group_open "Bench link $crate (features='$features')"
        cargo bench -p "$crate" "${common[@]}" --no-run || rc=$?
        group_close
    fi

    return $rc
}


total=$(jq --arg f "$FILTER" '
    [.[] | select($f == "" or (.crate | contains($f)))] | length
' "$MATRIX")

if [[ "$total" -eq 0 ]]; then
    echo "no matrix entries matched filter '$FILTER'" >&2
    exit 2
fi

results_file=$(mktemp)
trap 'rm -f "$results_file"' EXIT

echo "Running $total feature combinations sequentially..."
echo

idx=0
while IFS="$US" read -r crate features with_tests with_bench; do
    idx=$((idx + 1))
    display_features="${features:-(default)}"
    echo "[$idx/$total] $crate -- $display_features"

    if check_combo "$crate" "$features" "$with_tests" "$with_bench"; then
        status=PASS
    else
        status=FAIL
    fi

    printf '%s\t%s\t%s\n' "$status" "$crate" "$display_features" >> "$results_file"
done < <(
    jq -r --arg f "$FILTER" --arg d "$US" '
        .[]
        | select($f == "" or (.crate | contains($f)))
        | [.crate, .features,
           (.with_tests // false | tostring),
           (.with_bench // false | tostring)]
        | join($d)
    ' "$MATRIX"
)

pass=$(awk -F'\t' '$1=="PASS"' "$results_file" | wc -l)
fail=$(awk -F'\t' '$1=="FAIL"' "$results_file" | wc -l)

echo
echo "================ FEATURE MATRIX SUMMARY ================"
printf 'STATUS\tCRATE\tFEATURES\n%s\n' "$(cat "$results_file")" \
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
        echo "| Status | Crate | Features |"
        echo "|--------|-------|----------|"
        awk -F'\t' '{
            features = ($3 == "(default)" ? "_(default)_" : "`" $3 "`")
            printf "| **%s** | `%s` | %s |\n", $1, $2, features
        }' "$results_file"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ $fail -eq 0 ]]; then
    exit 0
fi
exit 1
