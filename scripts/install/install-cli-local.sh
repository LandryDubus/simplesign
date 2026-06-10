#!/usr/bin/env bash
# SimpleSign CLI - Local Build & Install (macOS/Linux)
# Usage: ./install-cli-local.sh
# Builds the CLI from source and installs to ~/.local/share/SimpleSign/Cli

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PUBLISH_DIR="$REPO_ROOT/publish-cli-local"
INSTALL_DIR="$HOME/.local/share/SimpleSign/Cli"
LAUNCHER_DIR="$HOME/.local/bin"
LAUNCHER_PATH="$LAUNCHER_DIR/simplesign"

step() { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()   { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()  { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()  { tput setaf 8; echo "$*"; tput sgr0; }

echo
step "SimpleSign CLI - Local Install"
echo "=============================="
echo
dim "  Source : $REPO_ROOT"
dim "  Install: $INSTALL_DIR"
echo

# 1. Clean and publish
step "Building CLI (net8.0)..."
rm -rf "$PUBLISH_DIR"

dotnet publish "$REPO_ROOT/src/SimpleSign.Cli" -c Release -f net8.0 -o "$PUBLISH_DIR" -p:UseAppHost=false
if [ $? -ne 0 ]; then
    err "Build failed."
    exit 1
fi

DLL="$PUBLISH_DIR/simplesign.dll"
if [ ! -f "$DLL" ]; then
    err "simplesign.dll not found in output."
    exit 1
fi
ok "Built: simplesign.dll"

# 2. Copy to install folder
step "Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -R "$PUBLISH_DIR/"* "$INSTALL_DIR/"
ok "Files copied"

# Clean up publish output
rm -rf "$PUBLISH_DIR"
ok "Cleaned publish output"

# Remove stale apphost exe if present
if [ -f "$INSTALL_DIR/simplesign" ]; then
    rm -f "$INSTALL_DIR/simplesign"
    ok "Removed stale simplesign binary (wrapper takes precedence)"
fi

# 3. Create launcher
step "Creating launcher..."
mkdir -p "$LAUNCHER_DIR"
DLL_IN_INSTALL="$INSTALL_DIR/simplesign.dll"
cat > "$LAUNCHER_PATH" << LAUNCHER
#!/usr/bin/env bash
exec dotnet "$DLL_IN_INSTALL" "\$@"
LAUNCHER
chmod +x "$LAUNCHER_PATH"
ok "Created: $LAUNCHER_PATH"

# 4. Add to PATH
step "Checking PATH..."
case ":${PATH}:" in
    *:"$LAUNCHER_DIR":*)
        ok "Already in PATH."
        ;;
    *)
        PROFILE_FILE=""
        case "${SHELL:-}" in
            */zsh) PROFILE_FILE="$HOME/.zshrc";;
            */bash) PROFILE_FILE="$HOME/.bashrc";;
        esac
        if [ -n "$PROFILE_FILE" ]; then
            echo "export PATH=\"\$PATH:$LAUNCHER_DIR\"" >> "$PROFILE_FILE"
            ok "Added to PATH in $PROFILE_FILE"
            dim "  Run 'source $PROFILE_FILE' or open a new terminal."
        else
            err "Add $LAUNCHER_DIR to your PATH manually."
        fi
        ;;
esac

# 5. Done
echo
tput setaf 2; echo "[OK] Install complete!"; tput sgr0
dim "  Run: simplesign --help"
echo
