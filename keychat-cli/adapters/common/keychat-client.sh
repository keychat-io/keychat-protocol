#!/usr/bin/env bash
#
# keychat-client.sh — Shared Bash library for Keychat agent daemon
#
# Source this file in your bridge script or use standalone:
#   source keychat-client.sh
#   export KC_TOKEN="kc_abc123..."
#   kc_identity
#   kc_send <room_id> "Hello!"
#
# All functions return JSON and set $KC_LAST_STATUS to the HTTP status code.

# ─── Configuration ───────────────────────────────────────────
KC_URL="${KC_URL:-http://127.0.0.1:10443}"
KC_TOKEN="${KC_TOKEN:-}"
KC_LAST_STATUS=""

# ─── Internal ────────────────────────────────────────────────
_kc_auth_header() {
  if [[ -n "$KC_TOKEN" ]]; then
    echo "Authorization: Bearer $KC_TOKEN"
  else
    echo "X-No-Auth: true"
  fi
}

_kc_check_token() {
  if [[ -z "$KC_TOKEN" ]]; then
    echo '{"ok":false,"error":"KC_TOKEN not set"}' >&2
    return 1
  fi
}

# ─── HTTP Helpers ────────────────────────────────────────────

# GET request with auth. Usage: kc_get /path
kc_get() {
  local path="$1"
  _kc_check_token || return 1
  curl -sf -H "$(_kc_auth_header)" "$KC_URL$path" 2>/dev/null
}

# POST request with auth. Usage: kc_post /path '{"key":"value"}'
kc_post() {
  local path="$1"
  local body="${2:-}"
  _kc_check_token || return 1
  if [[ -n "$body" ]]; then
    curl -sf -X POST "$KC_URL$path" \
      -H "$(_kc_auth_header)" \
      -H 'Content-Type: application/json' \
      -d "$body" 2>/dev/null
  else
    curl -sf -X POST "$KC_URL$path" \
      -H "$(_kc_auth_header)" 2>/dev/null
  fi
}

# ─── Convenience Functions ───────────────────────────────────

# Get agent identity (npub, name, pubkey)
kc_identity() { kc_get /identity; }

# Get connection status
kc_status() { kc_get /status; }

# List rooms
kc_rooms() { kc_get /rooms; }

# Get messages for a room. Usage: kc_messages <room_id> [limit]
kc_messages() {
  local room_id="$1"
  local limit="${2:-50}"
  kc_get "/rooms/$room_id/messages?limit=$limit"
}

# List contacts
kc_contacts() { kc_get /contacts; }

# Get relay status
kc_relays() { kc_get /relays; }

# Send a message. Usage: kc_send <room_id> <text>
kc_send() {
  local room_id="$1"
  local text="$2"
  local payload
  payload=$(jq -n --arg rid "$room_id" --arg msg "$text" '{room_id: $rid, text: $msg}')
  kc_post /send "$payload"
}

# Send friend request. Usage: kc_add_friend <pubkey> [name]
kc_add_friend() {
  local pubkey="$1"
  local name="${2:-}"
  local payload
  payload=$(jq -n --arg pk "$pubkey" --arg nm "$name" '{pubkey: $pk, name: $nm}')
  kc_post /friend-request "$payload"
}

# ─── Agent-Specific ──────────────────────────────────────────

# List pending friend requests
kc_pending() { kc_get /pending-friends; }

# Approve friend request. Usage: kc_approve <request_id>
kc_approve() {
  local request_id="$1"
  local payload
  payload=$(jq -n --arg rid "$request_id" '{request_id: $rid}')
  kc_post /approve-friend "$payload"
}

# Reject friend request. Usage: kc_reject <request_id>
kc_reject() {
  local request_id="$1"
  local payload
  payload=$(jq -n --arg rid "$request_id" '{request_id: $rid}')
  kc_post /reject-friend "$payload"
}

# Get current owner
kc_owner() { kc_get /owner; }

# ─── SSE Helpers ─────────────────────────────────────────────

# Override these functions in your bridge to handle events:
kc_on_message()       { :; }  # Args: $1=json_data
kc_on_friend_request(){ :; }  # Args: $1=json_data
kc_on_friend_accepted(){ :; } # Args: $1=json_data
kc_on_pending_friend(){ :; }  # Args: $1=json_data
kc_on_status_change() { :; }  # Args: $1=json_data
kc_on_event()         { :; }  # Args: $1=event_type $2=json_data (catch-all)

# Start SSE listener with auto-reconnect. Blocks forever.
# Override kc_on_* functions before calling this.
kc_sse_listen() {
  _kc_check_token || return 1
  local current_event=""

  while true; do
    curl -sfN \
      -H "$(_kc_auth_header)" \
      "$KC_URL/events?token=$KC_TOKEN" 2>/dev/null | while IFS= read -r line; do

      if [[ "$line" =~ ^event:\ (.+)$ ]]; then
        current_event="${BASH_REMATCH[1]}"
        continue
      fi

      if [[ "$line" =~ ^data:\ (.+)$ ]]; then
        local event_data="${BASH_REMATCH[1]}"

        case "${current_event:-}" in
          message_received)         kc_on_message "$event_data" ;;
          friend_request_received)  kc_on_friend_request "$event_data" ;;
          friend_request_accepted)  kc_on_friend_accepted "$event_data" ;;
          pending_friend_request)   kc_on_pending_friend "$event_data" ;;
          connection_status_changed) kc_on_status_change "$event_data" ;;
          *)                        kc_on_event "${current_event:-unknown}" "$event_data" ;;
        esac

        current_event=""
        continue
      fi
    done

    echo "[keychat] SSE disconnected, reconnecting in 3s..." >&2
    sleep 3
  done
}

# ─── Session Routing ─────────────────────────────────────────

# Get session ID for routing. Usage: kc_session_id <sender_pubkey> <group_id>
# Returns: kcv2_dm_<pubkey> or kcv2_sg_<group_id>
kc_session_id() {
  local sender="$1"
  local group_id="${2:-}"
  if [[ -n "$group_id" && "$group_id" != "null" ]]; then
    echo "kcv2_sg_${group_id}"
  else
    echo "kcv2_dm_${sender}"
  fi
}

# ─── Wait for Agent Ready ───────────────────────────────────

# Poll /status until agent responds. Usage: kc_wait_ready [max_seconds]
kc_wait_ready() {
  local max_wait="${1:-30}"
  local i
  for i in $(seq 1 "$max_wait"); do
    if kc_status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "[keychat] Agent not ready after ${max_wait}s" >&2
  return 1
}
