---
name: keychat-v2
description: "E2E encrypted messaging via Keychat (Signal Protocol + Nostr). Agent daemon with Bearer token auth; bridge connects to OpenClaw via `openclaw agent` CLI."
metadata:
  openclaw:
    emoji: "🔐"
    homepage: "https://github.com/keychat-io/keychat-cli"
---

# Keychat — OpenClaw Skill

E2E encrypted messaging using Signal Protocol (PQXDH) over Nostr relays. Runs as an agent daemon with a bridge script — no gateway restart required.

## Architecture

```
User ←→ Keychat App ←→ Nostr Relay ←→ keychat agent daemon (:10443)
                                            ↕ HTTP API + Bearer Auth
                                       bridge.sh
                                            ↕
                                    openclaw agent CLI → Gateway
```

One daemon per agent. Each has its own identity, data directory, and port.

## Install

```bash
# From source (requires Rust toolchain)
cargo install --path keychat-cli

# Verify
keychat --version
keychat agent --help
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

First run automatically:
- Generates a new BIP-39 identity
- Creates encrypted DB with auto-generated key
- Stores secrets in `~/.keychat/secrets/` (mnemonic, dbkey, api-token)
- First peer to add this agent becomes the **owner**

### 2. Start bridge

```bash
./scripts/bridge.sh --token kc_abc123... --verbose
```

### 3. Add agent as friend

Get the agent's npub from the startup output, or:
```bash
curl -H "Authorization: Bearer kc_abc123..." http://127.0.0.1:10443/identity | jq '.data.npub'
```

Add this npub in your Keychat app. The first person to add becomes owner.

## Message Routing

The bridge routes messages to separate OpenClaw sessions by context:

| Context | Session ID | Description |
|---------|-----------|-------------|
| 1:1 DM | `kcv2_dm_<sender_pubkey>` | Per-user conversation |
| Signal group | `kcv2_sg_<group_id>` | Per-group conversation |

## Owner Policy

- **First friend = owner**: auto-accepted, stored in DB
- **Owner messages**: always auto-accepted
- **Others**: queued as pending, need owner approval via API or bridge logic

## Agent CLI Options

```bash
keychat agent [OPTIONS]

Options:
  --port <PORT>          Listen port (default: 10443)
  --no-auto-accept       Disable auto-accept friend requests
  --name <NAME>          Agent display name (default: "Keychat Agent")
  --relay <URLS>         Relay URLs, comma-separated (overrides defaults)
  --api-token <TOKEN>    API token (auto-generated if not provided)
  --data-dir <DIR>       Data directory (default: ~/.keychat)
```

## Headless Secrets

Secrets resolve in priority order (env → file → auto-generate):

| Secret | Env Var | File | Fallback |
|--------|---------|------|----------|
| DB key | `KEYCHAT_DB_KEY` | `secrets/dbkey` | OS keyring / auto-gen |
| Mnemonic | `KEYCHAT_MNEMONIC` | `secrets/mnemonic` | Create new identity |
| API token | `KEYCHAT_API_TOKEN` | `secrets/api-token` | `kc_` + random hex |

## HTTP API Reference

All endpoints require `Authorization: Bearer <token>` header.

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/identity` | Agent pubkey, npub, name |
| GET | `/status` | Connection status |
| GET | `/rooms` | List chat rooms |
| GET | `/rooms/{id}/messages` | Message history `?limit=50&offset=0` |
| GET | `/contacts` | Contact list |
| POST | `/send` | Send message `{"room_id":"...","text":"..."}` |
| GET | `/events` | SSE event stream (also accepts `?token=`) |
| GET | `/relays` | Relay connection status |
| POST | `/connect` | Connect to relays |
| POST | `/friend-request` | Send friend request |
| POST | `/retry` | Retry failed messages |

### Agent Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pending-friends` | Pending friend requests |
| POST | `/approve-friend` | Accept request `{"request_id":"..."}` |
| POST | `/reject-friend` | Reject request `{"request_id":"..."}` |
| GET | `/owner` | Current owner pubkey |
| POST | `/owner` | Transfer ownership |
| POST | `/backup-mnemonic` | Export mnemonic (owner only) |

### SSE Events

Subscribe: `GET /events` with `Authorization: Bearer <token>` or `?token=<token>`.

| Event | Payload |
|-------|---------|
| `message_received` | room_id, sender_pubkey, kind, content, event_id, group_id |
| `friend_request_received` | request_id, sender_pubkey, sender_name, created_at |
| `friend_request_accepted` | peer_pubkey, peer_name |
| `pending_friend_request` | request_id, sender_pubkey, sender_name, created_at |
| `connection_status_changed` | status, message |
| `room_updated` | room_id |
| `message_added` | room_id, msgid |

## Security

- **Mnemonic**: `secrets/mnemonic` with 0600 permissions, or env var
- **DB key**: `secrets/dbkey` with 0600 permissions, or OS keyring
- **API token**: Required for all HTTP access, auto-generated with `kc_` prefix
- **Transport**: Signal Protocol (PQXDH) end-to-end encryption, NIP-17 gift-wrap on Nostr
