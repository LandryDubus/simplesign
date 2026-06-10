#!/usr/bin/env bash
# SimpleSign - Run Interop Tests (Docker required)
# Builds Docker images for external validators and runs interop test suite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INTEROP_DIR="$REPO_ROOT/interop"

info()  { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()    { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()   { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()   { tput setaf 8; echo "$*"; tput sgr0; }

echo
info "SimpleSign - Interop Tests"
echo "=========================="
echo

# Check Docker
if ! command -v docker &>/dev/null; then
    err "Docker not found. Install Docker Desktop first."
    exit 1
fi
ok "$(docker --version 2>/dev/null)"

# Build images
echo
info "Building Docker images..."

declare -A DOCKER_IMAGES
DOCKER_IMAGES["simplesign-dss"]="$INTEROP_DIR/dss-validator"
DOCKER_IMAGES["simplesign-pdfbox"]="$INTEROP_DIR/pdfbox"
DOCKER_IMAGES["simplesign-eu-dss"]="$INTEROP_DIR/eu-dss"
DOCKER_IMAGES["simplesign-itext"]="$INTEROP_DIR/itext"

for name in "${!DOCKER_IMAGES[@]}"; do
    echo -n "  Building $name..."
    docker build -t "$name" "${DOCKER_IMAGES[$name]}" --quiet 2>/dev/null && \
        ok "OK" || \
        err "FAILED (run manually: docker build -t $name ${DOCKER_IMAGES[$name]})"
done

# Run tests
echo
info "Running interop tests..."
echo

pushd "$REPO_ROOT" >/dev/null
dotnet test tests/interop/SimpleSign.Interop.Tests --filter Category=Interop --logger "console;verbosity=normal"
EXIT_CODE=$?
popd >/dev/null

echo
if [ $EXIT_CODE -eq 0 ]; then
    ok "All interop tests passed!"
else
    err "Some tests failed (exit code: $EXIT_CODE)"
fi
