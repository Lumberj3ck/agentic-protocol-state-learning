#!/usr/bin/env bash
# Learn every target in parallel: scripts/learn_all.sh <run-label> [instances-per-target] [target ...]
# Results go to results/runs/<target>-<run-label>/. Meant for the big VM; works anywhere with Docker.
set -uo pipefail
cd "$(dirname "$0")/.."
label=$1; inst=${2:-6}; shift 2 || true
targets=("$@"); [ ${#targets[@]} -eq 0 ] && targets=($(ls targets))
for t in "${targets[@]}"; do
  out=results/runs/$t-$label; mkdir -p "$out"
  ( uv run python -m smlearn.learn "$t" --instances "$inst" --timeout 0.4 --quiet 0.1 --out "$out" > "$out/learn.log" 2>&1
    echo "EXIT $?" >> "$out/learn.log" ) &
done
wait
for t in "${targets[@]}"; do
  out=results/runs/$t-$label
  echo "$t: $(grep '^EXIT' $out/learn.log) $(grep -o '"states": [0-9]*' $out/learn.log) $(grep -o '"seconds": [0-9.]*' $out/learn.log) $(grep -o '"nondet_events": [0-9]*' $out/learn.log)"
done
