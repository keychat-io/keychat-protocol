---
name: keychat-v2
description: "E2E encrypted messaging via Keychat (Signal Protocol + Nostr). Agent daemon with Bearer token auth; bridge connects to OpenClaw/ZeroClaw/NanoClaw via CLI."
metadata:
  openclaw:
    emoji: "🔐"
    homepage: "https://github.com/keychat-io/keychat-cli"
---

# Keychat — Claw Skill

E2E encrypted messaging using Signal Protocol (PQXDH) over Nostr relays. Runs as an agent daemon with a configurable bridge script.

## Architecture

```
User ←→ Keychat App ←→ Nostr Relay ←→ keychat agent daemon (:10443)
                                            ↕ HTTP API + Bearer Auth
                                       bridge.sh (sources keychat-client.sh)
                                            ↕
                                    openclaw/zeroclaw/nanoclaw agent CLI
```

## Install

```bash
# One-click (downloads binary + bridge)
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-openclaw.sh | bash

# From source
cargo install --path keychat-cli
```

## Setup

### 1. Start agent daemon

```bash
keychat agent --name "MyBot"
# Output:
#   Agent ready: npub1xxx...
#   API token: kc_abc123...
#   Listening on http://0.0.0.0:10443
```

### 2. Start bridge

```bash
# OpenClaw (default)
./bridge.sh --token kc_abc123...

# ZeroClaw
./bridge.sh --token kc_abc123... --cli-cmd "zeroclaw agent"

# NanoClaw
./bridge.sh --token kc_abc123... --cli-cmd "nanoclaw agent"
```

### 3. Add agent as friend

Add the agent's npub in your Keychat app. First person becomes owner.

## Message Routing

| Context | Session ID |
|---------|-----------|
| 1:1 DM | `kcv2_dm_<sender_pubkey>` |
| Signal group | `kcv2_sg_<group_id>` |

## CLI Interface Contract

All claw variants share this invocation pattern:

```bash
<cli-cmd> --session-id <id> --timeout <sec> --json -m "<message>"
# Returns: { "result": { "payloads": [{ "text": "reply" }] } }
```

## Owner Policy

- **First friend = owner**: auto-accepted, stored in DB
- **Owner messages**: always auto-accepted
- **Others**: queued as pending, need approval via API

## HTTP API Reference

All endpoints require `Authorization: Bearer <token>`.

### Core

| Method | Path | Description |
|--------|------|-------------|
| GET | `/identity` | Agent pubkey, npub, name |
| GET | `/status` | Connection status |
| GET | `/rooms` | List chat rooms |
| GET | `/rooms/{id}/messages` | Message history |
| POST | `/send` | Send message `{"room_id":"...","text":"..."}` |
| GET | `/events` | SSE event stream |

### Agent

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pending-friends` | Pending friend requests |
| POST | `/approve-friend` | Accept request |
| POST | `/reject-friend` | Reject request |
| GET | `/owner` | Current owner pubkey |

### SSE Events

| Event | Payload |
|-------|---------|
| `message_received` | room_id, sender_pubkey, kind, content, event_id, group_id |
| `friend_request_received` | request_id, sender_pubkey, sender_name |
| `friend_request_accepted` | peer_pubkey, peer_name |
| `pending_friend_request` | request_id, sender_pubkey, sender_name |
| `connection_status_changed` | status, message |
