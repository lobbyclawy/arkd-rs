#!/usr/bin/env bash
# scripts/psar-scaling.sh — Cohort-scaling sweep for issue #684.
#
# Drives `cargo run -p dark-psar --features demo --bin psar-demo` at
# the four configurations called out by #684 and aggregates the JSON
# reports into a markdown table.
#
# Configurations:
#   1. (K=100,   N=12)  — paper lead row
#   2. (K=1000,  N=12)  — production-shape stress
#   3. (K=10000, N=12)  — stretch (skipped unless --include-stretch)
#   4. (K=1000,  N=50)  — long-horizon spot-check
#
# Usage:
#   scripts/psar-scaling.sh [--include-stretch] [--out PATH]
#
# Output: a markdown table on stdout (or to --out PATH) with one row
# per configuration; columns are (K, N, boarding_ms, epoch_ms_avg,
# total_signatures, all_verify, wall_clock_ms).

set -euo pipefail

INCLUDE_STRETCH=0
OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --include-stretch) INCLUDE_STRETCH=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Build once so the per-run cost excludes compilation.
cargo build --release -p dark-psar --features demo --bin psar-demo >/dev/null

BIN=target/release/psar-demo

run_one() {
  local k="$1" n="$2" seed="$3"
  local report
  report=$("$BIN" --k "$k" --n "$n" --seed "$seed")
  local boarding_ms epoch_ms_avg total_sigs all_verify wall
  boarding_ms=$(echo "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['boarding']['duration_ms'])")
  epoch_ms_avg=$(echo "$report" | python3 -c "import json,sys; e=json.load(sys.stdin)['epochs']; print(round(sum(x['duration_ms'] for x in e)/len(e), 1))")
  total_sigs=$(echo "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['aggregate']['total_signatures'])")
  all_verify=$(echo "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['aggregate']['all_verify'])")
  wall=$(echo "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['totals']['wall_clock_ms'])")
  printf "| %5d | %3d | %10d | %12s | %15d | %10s | %12d |\n" \
    "$k" "$n" "$boarding_ms" "$epoch_ms_avg" "$total_sigs" "$all_verify" "$wall"
}

emit() {
  echo "## Measured wall-clock at four configurations"
  echo
  echo "| K     | N   | boarding_ms | epoch_ms_avg | total_signatures | all_verify | wall_clock_ms |"
  echo "|-------|-----|-------------|--------------|------------------|------------|----------------|"
  run_one 100  12 1
  run_one 1000 12 2
  if [ "$INCLUDE_STRETCH" = "1" ]; then
    run_one 10000 12 3
  fi
  run_one 1000 50 4
}

if [ -n "$OUT" ]; then
  emit > "$OUT"
  echo "wrote $OUT" >&2
else
  emit
fi
