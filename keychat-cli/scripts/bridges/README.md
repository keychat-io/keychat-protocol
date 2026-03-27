# Keychat Agent Bridge Adapters

Bridge scripts connect the keychat agent daemon to external AI tools.

## How It Works

```
AI Tool (OpenClaw, Claude Code, Gemini, ...)
    ↕ AI-specific protocol
Bridge Script
    ↕ HTTP API + SSE
Keychat Agent Daemon (:10443)
    ↕ Signal-encrypted Nostr messages
Users
```

The agent daemon provides a standard HTTP API + SSE event stream. Each bridge script adapts a specific AI tool to this interface.

## Quick Start

```bash
# 1. Start the agent
keychat agent --name "MyBot"
# Output:
#   Agent ready: npub1xxx...
#   API token: kc_abc123...
#   Listening on http://0.0.0.0:10443

# 2. Run the OpenClaw bridge
./openclaw-bridge.sh --token kc_abc123... --verbose
```

## API Reference

All endpoints require `Authorization: Bearer <token>` header.

### Core Endpoints (from daemon)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/identity` | Agent's pubkey, npub, name |
| GET | `/status` | Connection status |
| GET | `/rooms` | List chat rooms |
| GET | `/rooms/{room_id}/messages` | Message history |
| GET | `/contacts` | Contact list |
| POST | `/send` | Send message `{"room_id":"...","text":"..."}` |
| GET | `/events` | SSE event stream (also accepts `?token=`) |
| GET | `/relays` | Relay connection status |
| POST | `/connect` | Connect to relays |
| POST | `/friend-request` | Send friend request |
| POST | `/retry` | Retry failed messages |

### Agent-Specific Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pending-friends` | Pending friend requests |
| POST | `/approve-friend` | Accept pending request `{"request_id":"..."}` |
| POST | `/reject-friend` | Reject pending request `{"request_id":"..."}` |
| GET | `/owner` | Current owner pubkey |
| POST | `/owner` | Transfer ownership `{"requester":"...","new_owner":"..."}` |
| POST | `/backup-mnemonic` | Export mnemonic (owner only) `{"requester":"..."}` |

### SSE Event Types

Subscribe: `GET /events` with `Authorization: Bearer <token>` or `?token=<token>`.

| Event | Payload Fields |
|-------|---------------|
| `message_received` | `room_id, sender_pubkey, kind, content, event_id, group_id` |
| `friend_request_received` | `request_id, sender_pubkey, sender_name, created_at` |
| `friend_request_accepted` | `peer_pubkey, peer_name` |
| `pending_friend_request` | `request_id, sender_pubkey, sender_name, created_at` |
| `room_updated` | `room_id` |
| `message_added` | `room_id, msgid` |
| `message_updated` | `room_id, msgid` |
| `connection_status_changed` | `status, message` |
| `relay_ok` | `event_id, relay_url, success, message` |

## Universal Bridge Pattern

Every bridge follows this pattern:

```
1. Subscribe to SSE: GET /events
2. On message_received:
   a. Extract sender_pubkey, content, room_id, group_id
   b. Forward to AI tool
   c. Get AI reply
   d. POST /send {"room_id": "...", "text": "reply"}
3. On pending_friend_request:
   a. Decide whether to approve
   b. POST /approve-friend or /reject-friend
4. On SSE disconnect: reconnect after delay
```

## Writing Your Own Adapter

Use `openclaw-bridge.sh` as a reference. The key integration points:

1. **Receive messages**: Parse SSE `message_received` events
2. **Session routing**: Map `room_id` or `sender_pubkey` to your AI tool's session/conversation concept
3. **Send replies**: `POST /send {"room_id": "<room_id>", "text": "<reply>"}`
4. **Manage friends**: Optionally handle `pending_friend_request` events

Your adapter can be a shell script, Python script, Node.js process, or any language that can consume SSE and make HTTP calls.
