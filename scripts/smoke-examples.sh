#!/usr/bin/env bash
#
# Smoke-test the example CLIs against checked-in PCAPs (no root).
# Optionally exercise live capture on a network interface.
#
# Usage:
#   scripts/smoke-examples.sh              # PCAP smoke only
#   scripts/smoke-examples.sh -i eth0      # PCAP + short live capture on eth0
#   scripts/smoke-examples.sh --interface lo
#
# Live mode starts each CLI for a few seconds and sends SIGINT. Needs an
# interface the process can open (often root / CAP_NET_RAW). Exit 0 or the
# timeout-after-SIGINT (124) counts as pass if capture started.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

INTERFACE=""
LIVE_SECS="${SMOKE_LIVE_SECS:-3}"

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \?//'
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)
            INTERFACE="${2:?missing interface name after $1}"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            ;;
    esac
done

TMPDIR_SMOKE="$(mktemp -d "${TMPDIR:-/tmp}/huginn-smoke.XXXXXX")"
trap 'rm -rf "$TMPDIR_SMOKE"' EXIT

group_open()  { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::group::$*" || echo ">>> $*"; }
group_close() { [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::endgroup::" || true; }

pass=0
fail=0
results=()

record() {
    local status="$1" name="$2"
    results+=("$status"$'\t'"$name")
    if [[ "$status" == "PASS" ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi
}

# Run a CLI on a PCAP; require exit 0 and stdout matching EXPECT_REGEX.
# Args: name package example features pcap expect_regex
smoke_pcap() {
    local name="$1" package="$2" example="$3" features="$4" pcap="$5" expect="$6"
    local out="$TMPDIR_SMOKE/${name}.json"
    local err="$TMPDIR_SMOKE/${name}.err"
    local log="$TMPDIR_SMOKE/${name}.log"

    group_open "pcap $name"
    set +e
    cargo run -q -p "$package" --example "$example" --features "$features" -- \
        --format json -l "$log" \
        pcap -f "$pcap" \
        >"$out" 2>"$err"
    local rc=$?
    set -e
    group_close

    if [[ $rc -ne 0 ]]; then
        echo "FAIL $name: exit $rc" >&2
        tail -n 40 "$err" >&2 || true
        record FAIL "$name (pcap)"
        return
    fi
    if ! grep -qE "$expect" "$out"; then
        echo "FAIL $name: stdout missing /$expect/" >&2
        head -n 5 "$out" >&2 || true
        tail -n 20 "$err" >&2 || true
        record FAIL "$name (pcap)"
        return
    fi
    record PASS "$name (pcap)"
}

# Short live capture; SIGINT after LIVE_SECS.
# Args: name package example features live_args...
smoke_live() {
    local name="$1" package="$2" example="$3" features="$4"
    shift 4
    local err="$TMPDIR_SMOKE/${name}-live.err"
    local log="$TMPDIR_SMOKE/${name}-live.log"

    group_open "live $name (-i $INTERFACE)"
    set +e
    # timeout(1): 124 = killed by the deadline signal (SIGINT here).
    timeout --signal=INT "${LIVE_SECS}s" \
        cargo run -q -p "$package" --example "$example" --features "$features" -- \
        --format json -l "$log" \
        "$@" \
        >/dev/null 2>"$err"
    local rc=$?
    set -e
    group_close

    if [[ $rc -ne 0 && $rc -ne 124 ]]; then
        echo "FAIL $name live: exit $rc" >&2
        tail -n 40 "$err" >&2 || true
        record FAIL "$name (live $INTERFACE)"
        return
    fi
    if ! grep -qiE 'Starting live capture|live capture on interface|Processing|Starting' "$err" "$log" 2>/dev/null; then
        # Some CLIs only log via tracing to the file; also accept open failures as fail.
        if grep -qiE 'Permission denied|No such device|Failed to|error:' "$err" "$log" 2>/dev/null; then
            echo "FAIL $name live: capture did not start (see log)" >&2
            tail -n 40 "$err" >&2 || true
            record FAIL "$name (live $INTERFACE)"
            return
        fi
    fi
    if grep -qiE 'Permission denied|No such device' "$err" "$log" 2>/dev/null; then
        echo "FAIL $name live: cannot open interface '$INTERFACE'" >&2
        tail -n 40 "$err" >&2 || true
        record FAIL "$name (live $INTERFACE)"
        return
    fi
    record PASS "$name (live $INTERFACE)"
}

echo "PCAP smoke (cwd=$ROOT)"
smoke_pcap cli-tcp  huginn-net-tcp  cli-tcp  "full,json" pcap/macos_tcp_flags.pcap            'Matched|"syn"'
smoke_pcap cli-http huginn-net-http cli-http "full,json" pcap/http-simple-get.pcap             'Matched|"http_request"'
smoke_pcap cli-tls  huginn-net-tls  cli-tls  "full,json" pcap/tls12.pcap                       'ja4'
smoke_pcap cli      huginn-net      cli      "full,json" pcap/http-simple-get.pcap             'tcp_syn|http_request|Matched'

if [[ -n "$INTERFACE" ]]; then
    echo
    echo "Live smoke on interface: $INTERFACE (${LIVE_SECS}s each)"
    smoke_live cli-tcp  huginn-net-tcp  cli-tcp  "full,json" live single -i "$INTERFACE"
    smoke_live cli-http huginn-net-http cli-http "full,json" live single -i "$INTERFACE"
    smoke_live cli-tls  huginn-net-tls  cli-tls  "full,json" live single -i "$INTERFACE"
    smoke_live cli      huginn-net      cli      "full,json" live -i "$INTERFACE"
else
    echo
    echo "Skipping live smoke (pass -i/--interface IFACE to enable)."
fi

echo
echo "================ SMOKE EXAMPLES SUMMARY ================"
printf 'STATUS\tCASE\n'
printf '%s\n' "${results[@]}"
echo "--------------------------------------------------------"
echo "Passed: $pass"
echo "Failed: $fail"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## Example CLI smoke"
        echo
        echo "**Passed:** $pass **·** **Failed:** $fail"
        if [[ -n "$INTERFACE" ]]; then
            echo
            echo "Live interface: \`$INTERFACE\`"
        fi
        echo
        echo "| Status | Case |"
        echo "|--------|------|"
        printf '%s\n' "${results[@]}" | awk -F'\t' '{ printf "| **%s** | `%s` |\n", $1, $2 }'
    } >>"$GITHUB_STEP_SUMMARY"
fi

[[ "$fail" -eq 0 ]]
