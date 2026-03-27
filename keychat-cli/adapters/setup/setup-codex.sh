#!/usr/bin/env bash
#
# Keychat Agent + OpenAI Codex — one-click installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-codex.sh | bash
#   curl -fsSL ... | bash -s -- --name MyBot
#
# What this does:
#   1. Downloads keychat binary (if not installed)
#   2. Downloads MCP adapter (same server as Claude Code)
#   3. Installs npm dependencies
#   4. Configures Codex MCP via `codex mcp add`
#   5. Optionally starts agent daemon
#
# Prerequisites: Node.js 18+, codex CLI

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────
GITHUB_REPO="keychat-io/keychat-protocol"
RAW_BASE="https://raw.githubusercontent.com/$GITHUB_REPO/main/keychat-cli/adapters"
INSTALL_DIR="$HOME/.keychat"
MCP_DIR="$INSTALL_DIR/mcp"
BIN_DIR="$INSTALL_DIR/bin"
AGENT_NAME="Keychat Agent"
AGENT_PORT=10443
INSTALL_ONLY=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)          AGENT_NAME="$2"; shift 2 ;;
    --port)          AGENT_PORT="$2"; shift 2 ;;
    --install-only)  INSTALL_ONLY=true; shift ;;
    *)               EXTRA_ARGS+=("$1"); shift ;;
  esac
done

# ─── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'
info()  { echo -e "${GREEN}▸${NC} $*"; }
warn()  { echo -e "${YELLOW}▸${NC} $*"; }
error() { echo -e "${RED}▸${NC} $*" >&2; }

echo -e "${BOLD}Keychat Agent + Codex Setup${NC}"
echo ""

# ─── Step 1: Check prerequisites ────────────────────────────
if ! command -v node &>/dev/null; then
  error "Node.js not found. Install Node.js 18+ first."
  exit 1
fi

if ! command -v codex &>/dev/null; then
  warn "codex CLI not found. Install: npm install -g @openai/codex"
fi

info "Node.js $(node --version)"
mkdir -p "$BIN_DIR" "$MCP_DIR/common"

# ─── Step 2: Install keychat binary ─────────────────────────
if command -v keychat &>/dev/null; then
  info "keychat found: $(keychat --version 2>/dev/null || echo 'installed')"
else
  info "Downloading keychat binary..."

  OS=$(uname -s)
  ARCH=$(uname -m)

  case "$OS-$ARCH" in
    Darwin-arm64)  TARGET="aarch64-apple-darwin" ;;
    Darwin-x86_64) TARGET="aarch64-apple-darwin" ;;
    Linux-x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    Linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)
      error "Unsupported platform: $OS-$ARCH"
      exit 1
      ;;
  esac

  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases?per_page=20" \
    | grep -o '"tag_name": *"cli-v[^"]*"' | head -1 | grep -o 'cli-v[^"]*')

  if [[ -z "$LATEST_TAG" ]]; then
    error "Could not find latest release. Build from source: cargo install --path keychat-cli"
    exit 1
  fi

  DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST_TAG/keychat-$TARGET.tar.gz"
  info "Downloading $LATEST_TAG for $TARGET..."
  curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$BIN_DIR"
  chmod +x "$BIN_DIR/keychat"

  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    export PATH="$BIN_DIR:$PATH"
    SHELL_RC=""
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
    [[ -z "$SHELL_RC" && -f "$HOME/.bashrc" ]] && SHELL_RC="$HOME/.bashrc"
    if [[ -n "$SHELL_RC" ]] && ! grep -q "$BIN_DIR" "$SHELL_RC" 2>/dev/null; then
      echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
      info "Added $BIN_DIR to PATH in $SHELL_RC"
    fi
  fi

  info "Installed: $(keychat --version 2>/dev/null || echo 'keychat')"
fi

# ─── Step 3: Download MCP adapter ───────────────────────────
info "Setting up MCP adapter..."

curl -fsSL "$RAW_BASE/mcp/server.ts"              -o "$MCP_DIR/server.ts"
curl -fsSL "$RAW_BASE/mcp/package.json"            -o "$MCP_DIR/package.json"
curl -fsSL "$RAW_BASE/common/keychat-client.ts"    -o "$MCP_DIR/common/keychat-client.ts"

cd "$MCP_DIR"
npm install --silent 2>/dev/null
info "MCP adapter installed at $MCP_DIR"

# ─── Step 4: Configure Codex MCP ────────────────────────────
SERVER_TS="$MCP_DIR/server.ts"

info "Configuring Codex MCP..."

if command -v codex &>/dev/null; then
  # Use codex CLI to register MCP server
  codex mcp add keychat -- npx tsx "$SERVER_TS" 2>/dev/null || {
    warn "codex mcp add failed. Manual config:"
    echo "  codex mcp add keychat -- npx tsx $SERVER_TS"
  }
  info "Codex MCP configured via CLI"
else
  warn "codex CLI not available. After installing, run:"
  echo "  codex mcp add keychat -- npx tsx $SERVER_TS"
fi

# ─── Done ────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
echo -e "${GREEN} ✓ Installation complete${NC}"
echo "─────────────────────────────────────────────"
echo ""

if $INSTALL_ONLY; then
  echo "  Next steps:"
  echo ""
  echo "  1. Start the agent:"
  echo "     keychat agent --name \"$AGENT_NAME\" --port $AGENT_PORT"
  echo ""
  echo "  2. Configure the API token in MCP config"
  echo ""
  echo "  3. Add the agent's npub in your Keychat app"
  echo ""
  exit 0
fi

echo "  Starting agent..."
echo ""

exec keychat agent --name "$AGENT_NAME" --port "$AGENT_PORT" "${EXTRA_ARGS[@]}"
