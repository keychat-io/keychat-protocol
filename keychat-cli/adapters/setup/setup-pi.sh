#!/usr/bin/env bash
#
# Keychat Agent — Headless / Pi installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-pi.sh | bash
#   curl -fsSL ... | bash -s -- --name MyBot --port 9000
#
# What this does:
#   1. Downloads keychat binary (auto-detects ARM/x86)
#   2. Creates systemd service (Linux) or launchd plist (macOS)
#   3. Starts agent as a background daemon
#   4. Prints npub + token for remote configuration
#
# Designed for: Raspberry Pi, VPS, headless Linux/macOS servers

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────
GITHUB_REPO="keychat-io/keychat-protocol"
INSTALL_DIR="$HOME/.keychat"
BIN_DIR="$INSTALL_DIR/bin"
AGENT_NAME="Keychat Agent"
AGENT_PORT=10443
INSTALL_ONLY=false
USE_SYSTEMD=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)          AGENT_NAME="$2"; shift 2 ;;
    --port)          AGENT_PORT="$2"; shift 2 ;;
    --systemd)       USE_SYSTEMD=true; shift ;;
    --install-only)  INSTALL_ONLY=true; shift ;;
    *)               EXTRA_ARGS+=("$1"); shift ;;
  esac
done

# Auto-detect systemd on Linux
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &>/dev/null; then
  USE_SYSTEMD=true
fi

# ─── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'
info()  { echo -e "${GREEN}▸${NC} $*"; }
warn()  { echo -e "${YELLOW}▸${NC} $*"; }
error() { echo -e "${RED}▸${NC} $*" >&2; }

echo -e "${BOLD}Keychat Agent — Headless Setup${NC}"
echo ""

# ─── Step 1: Install keychat binary ─────────────────────────
mkdir -p "$BIN_DIR"

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
    Linux-armv7l)  TARGET="armv7-unknown-linux-gnueabihf" ;;
    *)
      error "Unsupported platform: $OS-$ARCH"
      error "Build from source: cargo install --path keychat-cli"
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

KEYCHAT_BIN=$(command -v keychat || echo "$BIN_DIR/keychat")

# ─── Step 2: Install service ────────────────────────────────

if $USE_SYSTEMD; then
  SERVICE_FILE="$HOME/.config/systemd/user/keychat-agent.service"
  mkdir -p "$(dirname "$SERVICE_FILE")"

  info "Creating systemd user service..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Keychat Agent Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$KEYCHAT_BIN agent --name "$AGENT_NAME" --port $AGENT_PORT
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=keychat=info

[Install]
WantedBy=default.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable keychat-agent.service
  info "Systemd service installed: $SERVICE_FILE"

elif [[ "$(uname -s)" == "Darwin" ]]; then
  PLIST_FILE="$HOME/Library/LaunchAgents/io.keychat.agent.plist"
  mkdir -p "$(dirname "$PLIST_FILE")"

  info "Creating launchd service..."
  cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.keychat.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$KEYCHAT_BIN</string>
    <string>agent</string>
    <string>--name</string>
    <string>$AGENT_NAME</string>
    <string>--port</string>
    <string>$AGENT_PORT</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>$INSTALL_DIR/agent.log</string>
  <key>StandardOutPath</key>
  <string>$INSTALL_DIR/agent.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>keychat=info</string>
  </dict>
</dict>
</plist>
EOF

  info "launchd plist installed: $PLIST_FILE"
fi

# ─── Step 3: Start or print instructions ────────────────────
echo ""
echo "─────────────────────────────────────────────"
echo -e "${GREEN} ✓ Installation complete${NC}"
echo "─────────────────────────────────────────────"
echo ""

if $INSTALL_ONLY; then
  if $USE_SYSTEMD; then
    echo "  Start with:"
    echo "    systemctl --user start keychat-agent"
    echo ""
    echo "  View logs:"
    echo "    journalctl --user -u keychat-agent -f"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    echo "  Start with:"
    echo "    launchctl load $PLIST_FILE"
    echo ""
    echo "  View logs:"
    echo "    tail -f $INSTALL_DIR/agent.log"
  else
    echo "  Start with:"
    echo "    keychat agent --name \"$AGENT_NAME\" --port $AGENT_PORT &"
  fi
  echo ""
  echo "  Then check:"
  echo "    curl http://127.0.0.1:$AGENT_PORT/identity"
  echo ""
  exit 0
fi

# Start the service
if $USE_SYSTEMD; then
  systemctl --user start keychat-agent
  sleep 2
  info "systemd service started"

  # Get token from secrets file
  if [[ -f "$INSTALL_DIR/secrets/api-token" ]]; then
    API_TOKEN=$(cat "$INSTALL_DIR/secrets/api-token")
  else
    warn "Waiting for agent to initialize..."
    for i in $(seq 1 15); do
      [[ -f "$INSTALL_DIR/secrets/api-token" ]] && break
      sleep 1
    done
    API_TOKEN=$(cat "$INSTALL_DIR/secrets/api-token" 2>/dev/null || echo "")
  fi

  IDENTITY=$(curl -sf -H "Authorization: Bearer $API_TOKEN" "http://127.0.0.1:$AGENT_PORT/identity" 2>/dev/null || echo '{}')
  NPUB=$(echo "$IDENTITY" | jq -r '.data.npub // empty' 2>/dev/null)

  echo ""
  info "Agent running as systemd service"
  [[ -n "$NPUB" ]] && info "npub: $NPUB"
  [[ -n "$API_TOKEN" ]] && info "token: $API_TOKEN"
  info "URL: http://127.0.0.1:$AGENT_PORT"
  echo ""
  echo "  View logs: journalctl --user -u keychat-agent -f"
  echo "  Stop:      systemctl --user stop keychat-agent"
  echo ""
  [[ -n "$NPUB" ]] && echo "  Add this npub in your Keychat app: $NPUB"

elif [[ "$(uname -s)" == "Darwin" ]]; then
  launchctl load "$PLIST_FILE"
  sleep 2
  info "launchd service started"
  echo ""
  echo "  View logs: tail -f $INSTALL_DIR/agent.log"
  echo "  Stop:      launchctl unload $PLIST_FILE"

else
  # Fallback: run directly
  exec keychat agent --name "$AGENT_NAME" --port "$AGENT_PORT" "${EXTRA_ARGS[@]}"
fi
