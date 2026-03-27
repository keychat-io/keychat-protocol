#!/usr/bin/env bash
#
# Keychat Agent + Claw (OpenClaw/ZeroClaw/NanoClaw) — one-click installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-openclaw.sh | bash
#   curl -fsSL ... | bash -s -- --name MyBot --variant zeroclaw
#
# What this does:
#   1. Downloads keychat binary (if not installed)
#   2. Downloads bridge script + shared client library
#   3. Starts agent daemon (background)
#   4. Starts bridge (foreground)
#
# Prerequisites: jq, claw CLI (openclaw/zeroclaw/nanoclaw)

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────
GITHUB_REPO="keychat-io/keychat-protocol"
RAW_BASE="https://raw.githubusercontent.com/$GITHUB_REPO/main/keychat-cli/adapters"
INSTALL_DIR="$HOME/.keychat"
BIN_DIR="$INSTALL_DIR/bin"
BRIDGE_DIR="$INSTALL_DIR/bridges"
AGENT_NAME="Keychat Agent"
AGENT_PORT=10443
VARIANT="openclaw"
OPENCLAW_AGENT=""
INSTALL_ONLY=false
VERBOSE=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)          AGENT_NAME="$2"; shift 2 ;;
    --port)          AGENT_PORT="$2"; shift 2 ;;
    --variant)       VARIANT="$2"; shift 2 ;;
    --agent)         OPENCLAW_AGENT="$2"; shift 2 ;;
    --install-only)  INSTALL_ONLY=true; shift ;;
    --verbose)       VERBOSE=true; shift ;;
    *)               EXTRA_ARGS+=("$1"); shift ;;
  esac
done

# Map variant to CLI command
case "$VARIANT" in
  openclaw)  CLI_CMD="openclaw agent" ;;
  zeroclaw)  CLI_CMD="zeroclaw agent" ;;
  nanoclaw)  CLI_CMD="nanoclaw agent" ;;
  *)         CLI_CMD="$VARIANT agent" ;;
esac

# ─── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'
info()  { echo -e "${GREEN}▸${NC} $*"; }
warn()  { echo -e "${YELLOW}▸${NC} $*"; }
error() { echo -e "${RED}▸${NC} $*" >&2; }

echo -e "${BOLD}Keychat Agent + ${VARIANT^} Setup${NC}"
echo ""

# ─── Step 1: Check prerequisites ────────────────────────────
if ! command -v jq &>/dev/null; then
  error "jq not found. Install with:"
  echo "  macOS:  brew install jq"
  echo "  Linux:  apt install jq"
  exit 1
fi

if ! $INSTALL_ONLY && ! command -v "${VARIANT}" &>/dev/null; then
  warn "${VARIANT} CLI not found. Bridge will fail without it."
fi

info "jq: $(jq --version 2>/dev/null || echo 'installed')"
mkdir -p "$BIN_DIR" "$BRIDGE_DIR/common"

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

# ─── Step 3: Download bridge + shared client ────────────────
info "Downloading bridge scripts..."

curl -fsSL "$RAW_BASE/claw/bridge.sh"             -o "$BRIDGE_DIR/bridge.sh"
curl -fsSL "$RAW_BASE/common/keychat-client.sh"   -o "$BRIDGE_DIR/common/keychat-client.sh"
chmod +x "$BRIDGE_DIR/bridge.sh" "$BRIDGE_DIR/common/keychat-client.sh"
info "Bridge installed at $BRIDGE_DIR"

# ─── Step 4: Start ──────────────────────────────────────────
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
  echo "  2. Start the bridge:"
  echo "     $BRIDGE_DIR/bridge.sh --token <token-from-step-1> --cli-cmd \"$CLI_CMD\""
  echo ""
  echo "  3. Add the agent's npub in your Keychat app"
  echo ""
  exit 0
fi

info "Starting agent daemon..."

AGENT_OUTPUT=$(mktemp)
trap 'rm -f "$AGENT_OUTPUT"; kill $AGENT_PID 2>/dev/null || true' EXIT

keychat agent --name "$AGENT_NAME" --port "$AGENT_PORT" "${EXTRA_ARGS[@]}" > "$AGENT_OUTPUT" 2>&1 &
AGENT_PID=$!

for i in $(seq 1 15); do
  if grep -q "API token:" "$AGENT_OUTPUT" 2>/dev/null; then break; fi
  if ! kill -0 $AGENT_PID 2>/dev/null; then
    error "Agent failed to start:"
    cat "$AGENT_OUTPUT"
    exit 1
  fi
  sleep 1
done

if ! grep -q "API token:" "$AGENT_OUTPUT" 2>/dev/null; then
  error "Agent didn't start within 15s:"
  cat "$AGENT_OUTPUT"
  exit 1
fi

API_TOKEN=$(grep "API token:" "$AGENT_OUTPUT" | awk '{print $NF}')
NPUB=$(grep "Agent ready:" "$AGENT_OUTPUT" | awk '{print $NF}')

echo ""
info "Agent running (PID: $AGENT_PID)"
info "npub: $NPUB"
info "token: $API_TOKEN"
info "URL: http://127.0.0.1:$AGENT_PORT"
echo ""
echo "  Add this npub in your Keychat app: $NPUB"
echo ""

# ─── Step 5: Start bridge ───────────────────────────────────
info "Starting bridge..."
echo ""

BRIDGE_ARGS=(--token "$API_TOKEN" --url "http://127.0.0.1:$AGENT_PORT" --cli-cmd "$CLI_CMD")
if [[ -n "$OPENCLAW_AGENT" ]]; then
  BRIDGE_ARGS+=(--agent "$OPENCLAW_AGENT")
fi
if $VERBOSE; then
  BRIDGE_ARGS+=(--verbose)
fi

exec "$BRIDGE_DIR/bridge.sh" "${BRIDGE_ARGS[@]}"
