#!/usr/bin/env bash
#
# Keychat ↔ OpenClaw bridge
#
# Connects keychat-cli daemon (SSE) to OpenClaw agent CLI.
# Inbound:  keychat-cli SSE → openclaw agent → reply → keychat-cli POST /send
# Outbound: Agent uses exec to call keychat-cli POST /send directly.
#
# Usage: ./bridge.sh [options]
#   --url <base>       keychat-cli HTTP base URL (default: http://127.0.0.1:7700)
#   --agent <id>       OpenClaw agent id (optional, uses default routing)
#   --timeout <sec>    openclaw agent timeout (default: 300)
#   --verbose          Print debug info to stderr

set -euo pipefail

KEYCHAT_URL="${KEYCHAT_URL:-http://127.0.0.1:7700}"
AGENT_ID=""
AGENT_TIMEOUT=300
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)      KEYCHAT_URL="$2"; shift 2 ;;
    --agent)    AGENT_ID="$2"; shift 2 ;;
    --timeout)  AGENT_TIMEOUT="$2"; shift 2 ;;
    --verbose)  VERBOSE=true; shift ;;
    *)          echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log() { $VERBOSE && echo "[bridge] $*" >&2 || true; }

# Wait for keychat-cli daemon to be ready
echo "[bridge] Waiting for keychat-cli at $KEYCHAT_URL ..." >&2
for i in $(seq 1 30); do
  if curl -sf "$KEYCHAT_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -sf "$KEYCHAT_URL/health" >/dev/null 2>&1; then
  echo "[bridge] ERROR: keychat-cli daemon not responding at $KEYCHAT_URL" >&2
  exit 1
fi

IDENTITY=$(curl -sf "$KEYCHAT_URL/identity")
NPUB=$(echo "$IDENTITY" | jq -r .npub)
NAME=$(echo "$IDENTITY" | jq -r .name)
echo "[bridge] Connected. Identity: $NAME ($NPUB)" >&2
echo "[bridge] Listening for SSE events..." >&2

# Build openclaw agent command with proper routing
build_agent_cmd() {
  local sender="$1"
  local message="$2"
  local group_id="$3"
  local kind="$4"

  # Route to the correct session:
  #   1:1 chat:      kcv2_dm_<sender_npub>
  #   Signal group:  kcv2_sg_<group_id>
  #   MLS group:     kcv2_mls_<group_id>
  local session_id
  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    if [[ "$kind" == "mls_group" ]]; then
      session_id="kcv2_mls_${group_id}"
    else
      session_id="kcv2_sg_${group_id}"
    fi
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

# Process a single SSE message event
handle_message() {
  local data="$1"
  local sender sender_name message kind group_id group_name

  sender=$(echo "$data" | jq -r '.sender // empty')
  sender_name=$(echo "$data" | jq -r '.sender_name // empty')
  message=$(echo "$data" | jq -r '.message // empty')
  kind=$(echo "$data" | jq -r '.kind // "dm"')
  group_id=$(echo "$data" | jq -r '.group_id // empty')
  group_name=$(echo "$data" | jq -r '.group_name // empty')

  if [[ -z "$sender" || -z "$message" ]]; then
    log "Skipping event with missing sender/message"
    return
  fi

  # Log with context
  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    log "← [${group_name:-$group_id}] $sender_name: $message"
  else
    log "← [$sender_name] $message"
  fi

  # Call openclaw agent with proper routing
  local cmd
  cmd=$(build_agent_cmd "$sender" "$message" "$group_id" "$kind")
  local result
  result=$($cmd "$message" 2>/dev/null) || {
    log "openclaw agent failed"
    return
  }

  # Extract reply
  local reply
  reply=$(echo "$result" | jq -r '.result.payloads[0].text // empty' 2>/dev/null)

  if [[ -z "$reply" || "$reply" == "null" ]]; then
    log "No reply from agent"
    return
  fi

  # Route reply to the correct destination
  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    # Group message — send to group
    log "→ [${group_name:-$group_id}] $reply"
    local send_payload
    send_payload=$(jq -n --arg gid "$group_id" --arg msg "$reply" '{group_id: $gid, message: $msg}')

    local endpoint="send-group"
    if [[ "$kind" == "mls_group" ]]; then
      endpoint="send-mls-group"
    fi

    curl -sf -X POST "$KEYCHAT_URL/$endpoint" \
      -H 'Content-Type: application/json' \
      -d "$send_payload" >/dev/null 2>&1 || {
      log "Failed to send group reply"
    }
  else
    # 1:1 message — reply to sender
    log "→ [$sender_name] $reply"
    local send_payload
    send_payload=$(jq -n --arg to "$sender" --arg msg "$reply" '{to: $to, message: $msg}')

    curl -sf -X POST "$KEYCHAT_URL/send" \
      -H 'Content-Type: application/json' \
      -d "$send_payload" >/dev/null 2>&1 || {
      log "Failed to send reply"
    }
  fi
}

# Process friend request events
handle_friend_request() {
  local data="$1"
  local sender_name auto_accepted
  sender_name=$(echo "$data" | jq -r '.sender_name // "unknown"')
  auto_accepted=$(echo "$data" | jq -r '.auto_accepted // false')
  log "Friend request from $sender_name (auto_accepted: $auto_accepted)"
}

# Main SSE loop
# curl -N for no-buffer, parse SSE format
while true; do
  curl -sfN "$KEYCHAT_URL/events" 2>/dev/null | while IFS= read -r line; do
    # SSE format: "event: <type>\ndata: <json>\n\n"
    if [[ "$line" =~ ^event:\ (.+)$ ]]; then
      current_event="${BASH_REMATCH[1]}"
      continue
    fi

    if [[ "$line" =~ ^data:\ (.+)$ ]]; then
      event_data="${BASH_REMATCH[1]}"

      case "${current_event:-message}" in
        message)
          handle_message "$event_data" &
          ;;
        friend_request)
          handle_friend_request "$event_data"
          ;;
      esac

      current_event=""
      continue
    fi
  done

  # SSE connection dropped — reconnect after delay
  echo "[bridge] SSE disconnected, reconnecting in 3s..." >&2
  sleep 3
done
