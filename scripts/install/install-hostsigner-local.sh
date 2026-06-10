#!/usr/bin/env bash
# SimpleSign - Install HostSigner Locally (macOS/Linux)
# Builds from source and installs the HostSigner service to ~/.local/share/SimpleSign/HostSigner
# Requires: .NET 8 SDK
# Usage: ./install-hostsigner-local.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_DIR="$REPO_ROOT/src/SimpleSign.HostSigner"
PUBLISH_DIR="$PROJECT_DIR/bin/publish-local"
INSTALL_DIR="$HOME/.local/share/SimpleSign/HostSigner"
EXE_NAME="simplesign-hostsigner"

step() { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()   { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()  { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()  { tput setaf 8; echo "$*"; tput sgr0; }

# Detect runtime identifier
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux)  RID="linux";;
    darwin) RID="osx";;
    *)      err "Unsupported OS: $OS"; exit 1;;
esac
case "$ARCH" in
    x86_64|amd64) RID="$RID-x64";;
    aarch64|arm64) RID="$RID-arm64";;
    *)      err "Unsupported arch: $ARCH"; exit 1;;
esac

echo
step "SimpleSign - Install HostSigner (local build)"
echo "=============================================="
echo
dim "  Source : $PROJECT_DIR"
dim "  RID    : $RID"
echo

if [ ! -d "$PROJECT_DIR" ]; then
    err "Project directory not found: $PROJECT_DIR"
    exit 1
fi

# 1. Publish self-contained single-file
step "Publishing HostSigner (self-contained, single-file)..."
dotnet publish "$PROJECT_DIR" \
    -c Release \
    -f net8.0 \
    -r "$RID" \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -o "$PUBLISH_DIR" \
    -v quiet

if [ $? -ne 0 ]; then
    err "Publish failed."
    exit 1
fi
ok "Published to $PUBLISH_DIR"

# 2. Stop running instance
RUNNING_PID=$(pgrep -x "$EXE_NAME" 2>/dev/null || echo "")
if [ -n "$RUNNING_PID" ]; then
    step "Stopping running HostSigner instance..."
    pkill -x "$EXE_NAME" 2>/dev/null || true
    sleep 2
    ok "Stopped"
fi

# 3. Copy to install dir
step "Installing to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -R "$PUBLISH_DIR/"* "$INSTALL_DIR/"
ok "Installed"

# 4. Clean up publish output
rm -rf "$PUBLISH_DIR"
ok "Cleaned up publish artifacts"

# 5. Verify
step "Verifying installation..."
EXE_PATH="$INSTALL_DIR/$EXE_NAME"
if [ -f "$EXE_PATH" ]; then
    SIZE_MB=$(du -h "$EXE_PATH" | cut -f1)
    ok "Executable found ($SIZE_MB MB)"
else
    err "Executable not found at $EXE_PATH"
    exit 1
fi

# 6. Done
echo
tput setaf 2; echo "  HostSigner installed successfully!"; tput sgr0
echo
dim "  Location: $EXE_PATH"
dim "  API      : http://localhost:21590"
echo
dim "  Start    : $EXE_PATH &"
dim "  Test     : curl -s http://localhost:21590/api/health"
echo
