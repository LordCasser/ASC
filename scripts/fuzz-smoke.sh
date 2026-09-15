#!/usr/bin/env bash
# QUAL-04 first-round smoke: fixed-seed mutation fuzzing of the core parsers.
#
# Mutates committed fixture bytes (ZIP/DEX/AXML) with a deterministic RNG,
# feeds each mutant to the CLI, and records crashes/aborts. A crash on a
# mutated *malformed* input is a release-profile panic - a defect. Time and
# mutation counts are bounded so this runs in CI.
#
# Usage: scripts/fuzz-smoke.sh [seconds-per-target] [out-dir]
set -euo pipefail

SECS="${1:-120}"
OUT="${2:-/tmp/asc-fuzz-smoke}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/rasc"

[ -x "$BIN" ] || { echo "build release first: cargo +1.93.1 build --release --locked"; exit 1; }
mkdir -p "$OUT"

FIXTURES=(
  tests/fixtures/contracts/inputs/g01-regex-string.apk
  tests/fixtures/contracts/inputs/g02-static-initializers.apk
  tests/fixtures/contracts/inputs/g03-zero-checksum.apk
  tests/fixtures/contracts/corpus/apks/net.gsantner.markor-2.16.1.apk
)

crashes=0
runs=0
start=$(date +%s)
for fixture in "${FIXTURES[@]}"; do
  [ -f "$ROOT/$fixture" ] || { echo "skip missing $fixture"; continue; }
  size=$(wc -c < "$ROOT/$fixture" | tr -d ' ')
  n=0
  while [ $(( $(date +%s) - start )) -lt "$SECS" ]; do
    # deterministic LCG mutation: byte offset + value from the counter
    n=$((n + 1))
    off=$(( (n * 2654435761) % size ))
    val=$(( (n * 40503) % 256 ))
    cp "$ROOT/$fixture" "$OUT/mutant.apk"
    printf "$(printf '\\x%02x' "$val")" | dd of="$OUT/mutant.apk" bs=1 seek="$off" count=1 conv=notrunc status=none
    set +e
    "$BIN" classes "$OUT/mutant.apk" --format json > "$OUT/out.json" 2> "$OUT/err.txt"
    code=$?
    set -e
    runs=$((runs + 1))
    if [ $code -ge 128 ]; then
      cp "$OUT/mutant.apk" "$OUT/crash-$runs.apk"
      cp "$OUT/err.txt" "$OUT/crash-$runs.txt"
      crashes=$((crashes + 1))
      echo "CRASH (exit $code) at offset $off -> crash-$runs.apk"
    fi
  done
  break  # one fixture bounds the whole window; re-balance per target in A14
done
echo "fuzz smoke: $runs mutants, $crashes crashes (window ${SECS}s)"
[ "$crashes" -eq 0 ]
