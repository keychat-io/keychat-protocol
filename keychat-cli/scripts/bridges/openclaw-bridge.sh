#!/usr/bin/env bash
#
# Keychat Agent ↔ OpenClaw bridge
#
# Connects keychat agent daemon (SSE) to OpenClaw agent CLI.
# Inbound:  keychat SSE message_received → openclaw agent → reply → POST /send
#
# Usage: ./openclaw-bridge.sh [options]
#   --url <base>       Agent HTTP base URL (default: http://127.0.0.1:10443)
#   --token <token>    API Bearer token (required, or set KEYCHAT_API_TOKEN env)
#   --agent <id>       OpenClaw agent id (optional, uses default routing)
#   --timeout <sec>    openclaw agent timeout (default: 300)
#   --verbose          Print debug info to stderr

set -euo pipefail

KEYCHAT_URL="${KEYCHAT_URL:-http://127.0.0.1:10443}"
API_TOKEN="${KEYCHAT_API_TOKEN:-}"
AGENT_ID=""
AGENT_TIMEOUT=300
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)      KEYCHAT_URL="$2"; shift 2 ;;
    --token)    API_TOKEN="$2"; shift 2 ;;
    --agent)    AGENT_ID="$2"; shift 2 ;;
    --timeout)  AGENT_TIMEOUT="$2"; shift 2 ;;
    --verbose)  VERBOSE=true; shift ;;
    *)          echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$API_TOKEN" ]]; then
  echo "[bridge] ERROR: API token required. Use --token or set KEYCHAT_API_TOKEN env." >&2
  exit 1
fi

AUTH_HEADER="Authorization: Bearer $API_TOKEN"
log() { $VERBOSE && echo "[bridge] $*" >&2 || true; }

# Wait for agent daemon to be ready
echo "[bridge] Waiting for keychat agent at $KEYCHAT_URL ..." >&2
for i in $(seq 1 30); do
  if curl -sf -H "$AUTH_HEADER" "$KEYCHAT_URL/status" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -sf -H "$AUTH_HEADER" "$KEYCHAT_URL/status" >/dev/null 2>&1; then
  echo "[bridge] ERROR: agent not responding at $KEYCHAT_URL" >&2
  exit 1
fi

IDENTITY=$(curl -sf -H "$AUTH_HEADER" "$KEYCHAT_URL/identity")
NPUB=$(echo "$IDENTITY" | jq -r '.data.npub // .npub // empty')
NAME=$(echo "$IDENTITY" | jq -r '.data.name // .name // empty')
echo "[bridge] Connected. Identity: $NAME ($NPUB)" >&2
echo "[bridge] Listening for SSE events..." >&2

# Build openclaw agent command with session routing
build_agent_cmd() {
  local sender="$1"
  local group_id="$2"

  # Route to the correct session:
  #   1:1 DM:        kcv2_dm_<sender_pubkey>
  #   Signal group:  kcv2_sg_<group_id>
  local session_id
  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    session_id="kcv2_sg_${group_id}"
  else
    session_id="kcv2_dm_${sender}"
  fi

  local cmd="openclaw agent"
  cmd+=" --session-id $session_id"
  cmd+=" --timeout $AGENT_TIMEOUT"
  cmd+=" --json"
  if [[ -n "$AGENT_ID" ]]; then
    cmd+=" --agent $AGENT_ID"
  fi
  cmd+=" -m"
  echo "$cmd"
}

# Process a message_received SSE event
handle_message() {
  local data="$1"
  local sender_pubkey content kind room_id group_id

  sender_pubkey=$(echo "$data" | jq -r '.sender_pubkey // empty')
  content=$(echo "$data" | jq -r '.content // empty')
  kind=$(echo "$data" | jq -r '.kind // "text"')
  room_id=$(echo "$data" | jq -r '.room_id // empty')
  group_id=$(echo "$data" | jq -r '.group_id // empty')

  # Only process text messages
  if [[ "$kind" != "text" ]]; then
    log "Skipping non-text message (kind: $kind)"
    return
  fi

  if [[ -z "$sender_pubkey" || -z "$content" ]]; then
    log "Skipping event with missing sender/content"
    return
  fi

  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    log "← [group:${group_id:0:8}] ${sender_pubkey:0:8}: $content"
  else
    log "← [${sender_pubkey:0:8}] $content"
  fi

  # Call openclaw agent
  local cmd
  cmd=$(build_agent_cmd "$sender_pubkey" "$group_id")
  local result
  result=$($cmd "$content" 2>/dev/null) || {
    log "openclaw agent failed"
    return
  }

  # Extract reply text
  local reply
  reply=$(echo "$result" | jq -r '.result.payloads[0].text // empty' 2>/dev/null)

  if [[ -z "$reply" || "$reply" == "null" ]]; then
    log "No reply from agent"
    return
  fi

  # Send reply back via keychat
  if [[ -n "$room_id" && "$room_id" != "null" ]]; then
    log "→ [room:${room_id:0:8}] $reply"
    local send_payload
    send_payload=$(jq -n --arg rid "$room_id" --arg msg "$reply" '{room_id: $rid, text: $msg}')

    curl -sf -X POST "$KEYCHAT_URL/send" \
      -H "$AUTH_HEADER" \
      -H 'Content-Type: application/json' \
      -d "$send_payload" >/dev/null 2>&1 || {
      log "Failed to send reply"
    }
  else
    log "No room_id, cannot reply"
  fi
}

# Process pending_friend_request SSE event
handle_pending_friend() {
  local data="$1"
  local sender_name request_id
  sender_name=$(echo "$data" | jq -r '.sender_name // "unknown"')
  request_id=$(echo "$data" | jq -r '.request_id // empty')
  log "Pending friend request from $sender_name (id: $request_id)"
  # AI could decide to approve here — for now just log
}

# Main SSE loop with auto-reconnect
while true; do
  curl -sfN -H "$AUTH_HEADER" "$KEYCHAT_URL/events?token=$API_TOKEN" 2>/dev/null | while IFS= read -r line; do
    if [[ "$line" =~ ^event:\ (.+)$ ]]; then
      current_event="${BASH_REMATCH[1]}"
      continue
    fi

    if [[ "$line" =~ ^data:\ (.+)$ ]]; then
      event_data="${BASH_REMATCH[1]}"

      case "${current_event:-}" in
        message_received)
          handle_message "$event_data" &
          ;;
        pending_friend_request)
          handle_pending_friend "$event_data"
          ;;
        friend_request_accepted)
          log "Friend request accepted: $(echo "$event_data" | jq -r '.peer_name // empty')"
          ;;
        connection_status_changed)
          log "Connection: $(echo "$event_data" | jq -r '.status // empty')"
          ;;
        *)
          log "Event: ${current_event:-unknown}"
          ;;
      esac

      current_event=""
      continue
    fi
  done

  echo "[bridge] SSE disconnected, reconnecting in 3s..." >&2
  sleep 3
done
