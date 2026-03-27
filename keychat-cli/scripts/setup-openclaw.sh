#!/usr/bin/env bash
#
# One-click setup: Keychat Agent + OpenClaw bridge
#
# What this does:
#   1. Starts agent daemon (background)
#   2. Waits for agent to be ready
#   3. Starts OpenClaw bridge (foreground)
#
# Usage:
#   ./setup-openclaw.sh                         # defaults
#   ./setup-openclaw.sh --name MyBot            # custom agent name
#   ./setup-openclaw.sh --port 9000             # custom port
#   ./setup-openclaw.sh --agent my-agent-id     # specific OpenClaw agent
#   ./setup-openclaw.sh --install-only          # start agent only, no bridge

set -euo pipefail

# ─── Defaults ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BRIDGE_SCRIPT="$SCRIPT_DIR/bridges/openclaw-bridge.sh"
AGENT_NAME="Keychat Agent"
AGENT_PORT=10443
OPENCLAW_AGENT=""
INSTALL_ONLY=false
VERBOSE=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)          AGENT_NAME="$2"; shift 2 ;;
    --port)          AGENT_PORT="$2"; shift 2 ;;
    --agent)         OPENCLAW_AGENT="$2"; shift 2 ;;
    --install-only)  INSTALL_ONLY=true; shift ;;
    --verbose)       VERBOSE=true; shift ;;
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

if ! command -v jq &>/dev/null; then
  error "'jq' not found. Install with: brew install jq (macOS) or apt install jq (Linux)"
  exit 1
fi

if ! $INSTALL_ONLY && ! command -v openclaw &>/dev/null; then
  warn "'openclaw' not found. Bridge will fail without it."
  warn "Install OpenClaw CLI first: https://docs.openclaw.ai/"
fi

if [[ ! -f "$BRIDGE_SCRIPT" ]]; then
  error "Bridge script not found at: $BRIDGE_SCRIPT"
  exit 1
fi

CLI_VERSION=$(keychat --version 2>/dev/null || echo "unknown")
info "keychat: $CLI_VERSION"

# ─── Step 2: Start agent daemon (background) ─────────────────
info "Starting agent daemon on port $AGENT_PORT..."

# Create a temp file for agent output so we can capture the token
AGENT_OUTPUT=$(mktemp)
trap 'rm -f "$AGENT_OUTPUT"; kill $AGENT_PID 2>/dev/null || true' EXIT

keychat agent --name "$AGENT_NAME" --port "$AGENT_PORT" "${EXTRA_ARGS[@]}" > "$AGENT_OUTPUT" 2>&1 &
AGENT_PID=$!

# Wait for agent to be ready (up to 15s)
info "Waiting for agent to be ready..."
for i in $(seq 1 15); do
  if grep -q "API token:" "$AGENT_OUTPUT" 2>/dev/null; then
    break
  fi
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

# Extract token and npub from output
API_TOKEN=$(grep "API token:" "$AGENT_OUTPUT" | awk '{print $NF}')
NPUB=$(grep "Agent ready:" "$AGENT_OUTPUT" | awk '{print $NF}')

echo ""
echo "─────────────────────────────────────────────"
info "Agent running (PID: $AGENT_PID)"
info "npub: $NPUB"
info "API token: $API_TOKEN"
info "URL: http://127.0.0.1:$AGENT_PORT"
echo "─────────────────────────────────────────────"
echo ""

if $INSTALL_ONLY; then
  info "Agent running in background (PID: $AGENT_PID)."
  echo ""
  echo "  To start the bridge manually:"
  echo "    $BRIDGE_SCRIPT --token $API_TOKEN"
  echo ""
  echo "  To stop the agent:"
  echo "    kill $AGENT_PID"
  echo ""
  # Keep agent running, remove trap
  trap 'rm -f "$AGENT_OUTPUT"' EXIT
  wait $AGENT_PID
  exit 0
fi

# ─── Step 3: Start bridge (foreground) ────────────────────────
info "Starting OpenClaw bridge..."
echo ""

BRIDGE_ARGS=(--token "$API_TOKEN" --url "http://127.0.0.1:$AGENT_PORT")
if [[ -n "$OPENCLAW_AGENT" ]]; then
  BRIDGE_ARGS+=(--agent "$OPENCLAW_AGENT")
fi
if $VERBOSE; then
  BRIDGE_ARGS+=(--verbose)
fi

echo "  Add agent's npub in your Keychat app: $NPUB"
echo ""

# Run bridge in foreground, agent stays in background
exec "$BRIDGE_SCRIPT" "${BRIDGE_ARGS[@]}"
