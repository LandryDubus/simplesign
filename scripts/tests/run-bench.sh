#!/usr/bin/env bash
# SimpleSign - Run Benchmarks Locally
# Usage: ./run-bench.sh [filter]
#   filter: BenchmarkDotNet filter (default: '*' = all)
#   Example: ./run-bench.sh "SigningBenchmarks"

set -euo pipefail

FILTER="${1:-*}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench/SimpleSign.Benchmarks"

info()  { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()    { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()   { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()   { tput setaf 8; echo "$*"; tput sgr0; }

echo
info "SimpleSign - Benchmarks"
echo "======================="
echo
echo "Filter: $FILTER"

pushd "$BENCH_DIR" >/dev/null
dotnet run -c Release -- --filter "$FILTER" --exporters json markdown
popd >/dev/null

ARTIFACTS="$BENCH_DIR/BenchmarkDotNet.Artifacts"
if [ -d "$ARTIFACTS" ]; then
    echo
    ok "Results: $ARTIFACTS"
fi
