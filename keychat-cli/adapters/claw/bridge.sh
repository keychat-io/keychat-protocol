#!/usr/bin/env bash
#
# Keychat Agent ↔ Claw bridge (OpenClaw, ZeroClaw, NanoClaw, or any compatible CLI)
#
# Usage: ./bridge.sh [options]
#   --url <base>       Agent HTTP base URL (default: http://127.0.0.1:10443)
#   --token <token>    API Bearer token (required, or set KC_TOKEN env)
#   --agent <id>       Agent ID passed to CLI (optional)
#   --timeout <sec>    CLI agent timeout (default: 300)
#   --cli-cmd <cmd>    CLI command to invoke (default: "openclaw agent")
#   --verbose          Print debug info to stderr
#
# Examples:
#   ./bridge.sh --token kc_abc... --verbose
#   ./bridge.sh --token kc_abc... --cli-cmd "zeroclaw agent"
#   ./bridge.sh --token kc_abc... --cli-cmd "nanoclaw agent"

set -euo pipefail

# Load shared client library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common/keychat-client.sh
source "$SCRIPT_DIR/../common/keychat-client.sh"

# ─── Config ──────────────────────────────────────────────────
CLI_CMD="${KC_CLI_CMD:-openclaw agent}"
AGENT_ID=""
AGENT_TIMEOUT=300
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)      KC_URL="$2"; shift 2 ;;
    --token)    KC_TOKEN="$2"; shift 2 ;;
    --agent)    AGENT_ID="$2"; shift 2 ;;
    --timeout)  AGENT_TIMEOUT="$2"; shift 2 ;;
    --cli-cmd)  CLI_CMD="$2"; shift 2 ;;
    --verbose)  VERBOSE=true; shift ;;
    *)          echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$KC_TOKEN" ]]; then
  echo "[bridge] ERROR: API token required. Use --token or set KC_TOKEN env." >&2
  exit 1
fi

log() { $VERBOSE && echo "[bridge] $*" >&2 || true; }

# ─── Wait for agent ─────────────────────────────────────────
echo "[bridge] Waiting for keychat agent at $KC_URL ..." >&2
kc_wait_ready 30 || { echo "[bridge] ERROR: agent not responding" >&2; exit 1; }

IDENTITY=$(kc_identity)
NPUB=$(echo "$IDENTITY" | jq -r '.data.npub // .npub // empty')
NAME=$(echo "$IDENTITY" | jq -r '.data.name // .name // empty')
echo "[bridge] Connected. Identity: $NAME ($NPUB)" >&2
echo "[bridge] CLI: $CLI_CMD" >&2
echo "[bridge] Listening for SSE events..." >&2

# ─── Message handler ────────────────────────────────────────
kc_on_message() {
  local data="$1"
  local sender_pubkey content kind room_id group_id

  sender_pubkey=$(echo "$data" | jq -r '.sender_pubkey // empty')
  content=$(echo "$data" | jq -r '.content // empty')
  kind=$(echo "$data" | jq -r '.kind // "text"')
  room_id=$(echo "$data" | jq -r '.room_id // empty')
  group_id=$(echo "$data" | jq -r '.group_id // empty')

  if [[ "$kind" != "text" ]]; then
    log "Skipping non-text message (kind: $kind)"
    return
  fi

  if [[ -z "$sender_pubkey" || -z "$content" ]]; then
    log "Skipping event with missing sender/content"
    return
  fi

  local session_id
  session_id=$(kc_session_id "$sender_pubkey" "$group_id")
  log "← [$session_id] $content"

  # Build CLI command
  local cmd="$CLI_CMD --session-id $session_id --timeout $AGENT_TIMEOUT --json"
  if [[ -n "$AGENT_ID" ]]; then
    cmd+=" --agent $AGENT_ID"
  fi
  cmd+=" -m"

  # Call the AI CLI
  local result
  result=$($cmd "$content" 2>/dev/null) || {
    log "CLI agent failed"
    return
  }

  local reply
  reply=$(echo "$result" | jq -r '.result.payloads[0].text // empty' 2>/dev/null)

  if [[ -z "$reply" || "$reply" == "null" ]]; then
    log "No reply from agent"
    return
  fi

  if [[ -n "$room_id" && "$room_id" != "null" ]]; then
    log "→ [room:${room_id:0:8}] $reply"
    kc_send "$room_id" "$reply" >/dev/null 2>&1 || log "Failed to send reply"
  else
    log "No room_id, cannot reply"
  fi
}

kc_on_friend_request() {
  local data="$1"
  log "Friend request: $(echo "$data" | jq -r '.sender_name // "unknown"') (id: $(echo "$data" | jq -r '.request_id // empty'))"
}

kc_on_friend_accepted() {
  local data="$1"
  log "Friend accepted: $(echo "$data" | jq -r '.peer_name // empty')"
}

kc_on_status_change() {
  local data="$1"
  log "Connection: $(echo "$data" | jq -r '.status // empty')"
}

# ─── Start SSE listener ─────────────────────────────────────
kc_sse_listen
