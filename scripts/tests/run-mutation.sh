#!/usr/bin/env bash
# SimpleSign - Run Mutation Tests (Stryker.NET)
# Usage: ./run-mutation.sh [project]
#   project: Core, CAdES, PAdES, Brasil (default: all)

set -euo pipefail

PROJECT="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

info()  { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()    { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()   { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()   { tput setaf 8; echo "$*"; tput sgr0; }

echo
info "SimpleSign - Mutation Testing (Stryker)"
echo "========================================"
echo

pushd "$REPO_ROOT" >/dev/null

# Restore dotnet tools (includes Stryker)
echo "Restoring tools..."
dotnet tool restore 2>/dev/null

PROJECTS=("SimpleSign.Core" "SimpleSign.CAdES" "SimpleSign.PAdES" "SimpleSign.Brasil")
if [ -n "$PROJECT" ]; then
    if [[ "$PROJECT" != SimpleSign.* ]]; then
        PROJECT="SimpleSign.$PROJECT"
    fi
    PROJECTS=("$PROJECT")
fi

echo "Projects: ${PROJECTS[*]}"
echo

for p in "${PROJECTS[@]}"; do
    info "[$p] Running Stryker..."
    CSPROJ="src/$p/$p.csproj"
    if [ ! -f "$CSPROJ" ]; then
        dim "  [SKIP] Project not found: $CSPROJ"
        continue
    fi

    dotnet stryker --project "$CSPROJ" --reporter cleartext --reporter html --output "stryker-out/$p" && \
        ok "Report: stryker-out/$p" || \
        err "Stryker finished with issues"
    echo
done

popd >/dev/null

echo "Reports saved to: $REPO_ROOT/stryker-out/"
