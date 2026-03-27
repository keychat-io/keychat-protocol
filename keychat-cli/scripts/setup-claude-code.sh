#!/usr/bin/env bash
#
# One-click setup: Keychat Agent + Claude Code integration
#
# What this does:
#   1. Installs channel plugin npm dependencies
#   2. Writes Claude Code MCP config (~/.claude/mcp.json)
#   3. Starts agent daemon (foreground)
#
# After running: restart Claude Code, then /keychat:configure to verify.
#
# Usage:
#   ./setup-claude-code.sh                  # defaults
#   ./setup-claude-code.sh --name MyBot     # custom agent name
#   ./setup-claude-code.sh --port 9000      # custom port
#   ./setup-claude-code.sh --install-only   # configure only, don't start agent

set -euo pipefail

# ─── Defaults ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLUGIN_DIR="$REPO_ROOT/keychat-channel-plugin"
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
NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $*"; }
error() { echo -e "${RED}[setup]${NC} $*" >&2; }

# ─── Step 1: Check prerequisites ────────────────────────────
info "Checking prerequisites..."

if ! command -v keychat &>/dev/null; then
  error "'keychat' not found. Install with: cargo install --path keychat-cli"
  exit 1
fi

if ! command -v node &>/dev/null; then
  error "'node' not found. Install Node.js 18+ first."
  exit 1
fi

if ! command -v npx &>/dev/null; then
  error "'npx' not found. Install Node.js 18+ first."
  exit 1
fi

CLI_VERSION=$(keychat --version 2>/dev/null || echo "unknown")
info "keychat: $CLI_VERSION"
info "node: $(node --version)"

# ─── Step 2: Install plugin dependencies ─────────────────────
info "Installing channel plugin dependencies..."

if [[ ! -d "$PLUGIN_DIR" ]]; then
  error "Channel plugin not found at: $PLUGIN_DIR"
  error "Make sure you cloned the full keychat-protocol repo."
  exit 1
fi

cd "$PLUGIN_DIR"
npm install --silent 2>/dev/null
info "Plugin dependencies installed."

# ─── Step 3: Configure Claude Code MCP ───────────────────────
MCP_FILE="$HOME/.claude/mcp.json"
SERVER_TS="$PLUGIN_DIR/server.ts"

info "Configuring Claude Code MCP..."
mkdir -p "$HOME/.claude"

if [[ -f "$MCP_FILE" ]]; then
  # Check if keychat is already configured
  if grep -q '"keychat"' "$MCP_FILE" 2>/dev/null; then
    warn "Keychat already in $MCP_FILE — updating path."
  fi
  # Merge keychat entry into existing config using node
  node -e "
    const fs = require('fs');
    const cfg = JSON.parse(fs.readFileSync('$MCP_FILE', 'utf-8'));
    cfg.mcpServers = cfg.mcpServers || {};
    cfg.mcpServers.keychat = {
      command: 'npx',
      args: ['tsx', '$SERVER_TS']
    };
    fs.writeFileSync('$MCP_FILE', JSON.stringify(cfg, null, 2) + '\n');
  "
else
  cat > "$MCP_FILE" <<MCPEOF
{
  "mcpServers": {
    "keychat": {
      "command": "npx",
      "args": ["tsx", "$SERVER_TS"]
    }
  }
}
MCPEOF
fi

info "MCP config written to $MCP_FILE"

# ─── Step 4: Start agent or show next steps ──────────────────
if $INSTALL_ONLY; then
  echo ""
  info "Setup complete! Next steps:"
  echo ""
  echo "  1. Start the agent:"
  echo "     keychat agent --name \"$AGENT_NAME\" --port $AGENT_PORT"
  echo ""
  echo "  2. Restart Claude Code (or run /reload-plugins)"
  echo ""
  echo "  3. In Claude Code, set your API token:"
  echo "     /keychat:configure token <your-token>"
  echo ""
  echo "  4. Add the agent's npub in your Keychat app"
  echo ""
  exit 0
fi

echo ""
info "Starting agent daemon..."
echo "─────────────────────────────────────────────"
echo ""
echo "  After agent starts, you'll see the API token."
echo "  Then:"
echo "    1. Restart Claude Code (or /reload-plugins)"
echo "    2. /keychat:configure token <token>"
echo "    3. Add agent's npub in Keychat app"
echo ""
echo "─────────────────────────────────────────────"
echo ""

exec keychat agent --name "$AGENT_NAME" --port "$AGENT_PORT" "${EXTRA_ARGS[@]}"
