#!/usr/bin/env bash
# SimpleSign - Run Fuzz Tests Locally
# Runs SharpFuzz against all fuzzing targets.
# Usage: ./run-fuzz.sh [target] [seconds]
#   target: cms, pdf, dss, timestamp, ocsp (default: all)
#   seconds: duration per target (default: 60)

set -euo pipefail

TARGET="${1:-}"
SECONDS="${2:-60}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FUZZ_DIR="$REPO_ROOT/tests/fuzz/SimpleSign.Fuzz"

info()  { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()    { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()   { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()   { tput setaf 8; echo "$*"; tput sgr0; }

echo
info "SimpleSign - Fuzz Testing"
echo "========================="
echo

# Install SharpFuzz CLI if not present
if ! command -v sharpfuzz &>/dev/null; then
    info "Installing SharpFuzz CLI..."
    dotnet tool install -g SharpFuzz.CommandLine
fi

TARGETS=(cms pdf dss timestamp ocsp)
if [ -n "$TARGET" ]; then
    TARGETS=("$TARGET")
fi

echo "Targets: ${TARGETS[*]}"
echo "Duration: ${SECONDS}s per target"
echo

pushd "$FUZZ_DIR" >/dev/null
for t in "${TARGETS[@]}"; do
    echo -n "[$t] Fuzzing for ${SECONDS}s..."
    dotnet run -c Release -- "$t" "$SECONDS" 2>/dev/null && \
        ok "OK" || \
        err "CRASH FOUND"
done
popd >/dev/null

FINDINGS="$FUZZ_DIR/Findings"
if [ -d "$FINDINGS" ]; then
    CRASHES=$(find "$FINDINGS" -type f | wc -l | tr -d ' ')
    if [ "$CRASHES" -gt 0 ]; then
        echo
        err "$CRASHES crash(es) found in: $FINDINGS"
    fi
else
    echo
    ok "No crashes found."
fi
