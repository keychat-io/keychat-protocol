---
name: keychat-v2
description: "E2E encrypted messaging via Keychat v2 (Signal Protocol + Nostr). Runs as independent daemon; bridge connects to OpenClaw via `openclaw agent` CLI. No gateway config changes needed."
metadata:
  openclaw:
    emoji: "🔐"
    homepage: "https://github.com/keychat-io/keychat-cli"
---

# Keychat v2 — OpenClaw Skill

E2E encrypted messaging using Signal Protocol (PQXDH) over Nostr relays. Runs as an independent daemon with a bridge script — no gateway restart required.

## Architecture

```
User ←→ Keychat App ←→ Nostr Relay ←→ keychat-agent daemon (decrypt)
                                            ↕ HTTP API
                                       bridge.sh
                                            ↕
                                    openclaw agent CLI → Gateway
```

### Single-agent mode
One daemon per agent. Each has its own identity, data-dir, port.

### Multi-agent mode
One daemon manages multiple agents. Each agent has its own subdirectory under `<data-dir>/agents/<id>/`.

```bash
# Single agent
keychat-agent --data-dir /data/assistant --listen 127.0.0.1:7700

# Multi-agent (auto-detects new agent directories)
keychat-agent --multi --data-dir /data/keychat --listen 127.0.0.1:7700
```

## Install

```bash
# From source (requires Rust toolchain)
cargo install --path keychat-cli-agent

# Or download pre-built binary
# curl -L https://github.com/keychat-io/keychat-cli/releases/latest/download/keychat-agent-$(uname -s)-$(uname -m) -o /usr/local/bin/keychat-agent
```

## Setup

### 1. Start daemon

```bash
keychat-agent --listen 127.0.0.1:7700 &
```

First run:
- Generates a new BIP-39 identity
- Stores mnemonic + DB key in **OS keychain** (never in config files)
- Creates `config.json` with non-sensitive settings only
- First peer to add this agent becomes the **owner** (DM Policy)

### 2. Start bridge

```bash
./bridge.sh &
```

### 3. Add agent as friend

Get the agent's npub: `curl -s http://127.0.0.1:7700/identity | jq .npub`

Add this npub in your Keychat app. The first person to add becomes owner.

## Multi-Agent: Creating Agents

```bash
# Via API (daemon auto-starts the new agent)
curl -X POST http://127.0.0.1:7700/agents \
  -d '{"id":"reviewer","name":"Code Reviewer"}'

# Or: create directory with config.json → daemon auto-detects within 5s
```

Each agent gets its own mnemonic (in OS keychain), npub, Signal sessions, and DB.

## Message Routing

bridge.sh routes messages to separate OpenClaw sessions by context:

| Context | Session ID | Reply endpoint |
|---------|-----------|----------------|
| 1:1 DM | `kcv2_dm_<sender_npub>` | `POST /send` |
| Signal group | `kcv2_sg_<group_id>` | `POST /send-group` |
| MLS group | `kcv2_mls_<group_id>` | `POST /send-mls-group` |

Multi-agent SSE events include `agent_id` and `agent_npub` for per-agent routing.

## DM Policy (Owner Model)

- **First friend = owner**: auto-accepted, stored in config
- **Owner adds again** (e.g., after reset): auto-accepted
- **Others**: queued as pending, need owner approval via `POST /approve-friend`

## Agent: Sending Messages

```bash
# Send 1:1 message
curl -X POST http://127.0.0.1:7700/send \
  -d '{"to":"<npub>","message":"Hello!"}'

# Send to Signal group
curl -X POST http://127.0.0.1:7700/send-group \
  -d '{"group_id":"<gid>","message":"Hello group!"}'

# Add a friend
curl -X POST http://127.0.0.1:7700/add-friend \
  -d '{"npub":"<hex>"}'

# Get identity / list contacts
curl -s http://127.0.0.1:7700/identity
curl -s http://127.0.0.1:7700/peers
```

## HTTP API Reference

### Single-agent mode

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events` | SSE stream (message, friend_request) |
| POST | `/send` | Send 1:1 message `{"to":"...","message":"..."}` |
| POST | `/send-group` | Send Signal group message `{"group_id":"...","message":"..."}` |
| POST | `/send-mls-group` | Send MLS group message `{"group_id":"...","message":"..."}` |
| POST | `/add-friend` | Send friend request `{"npub":"..."}` |
| POST | `/approve-friend` | Approve pending request `{"npub":"..."}` |
| POST | `/reject-friend` | Reject pending request `{"npub":"..."}` |
| GET | `/pending-friends` | List pending friend requests |
| GET | `/owner` | Get current owner |
| POST | `/backup-mnemonic` | Backup mnemonic (owner only) `{"owner_npub":"..."}` |
| GET | `/identity` | Get npub, name, relays |
| GET | `/peers` | List contacts |
| GET | `/health` | Liveness check |

### Multi-agent mode

All per-agent endpoints are prefixed with `/agents/:id/`:
- `GET /agents` — list all agents
- `POST /agents` — create new agent `{"id":"...","name":"..."}`
- `/agents/:id/send`, `/agents/:id/peers`, etc.

## Security

- **Mnemonic**: OS keychain only (macOS Keychain / Linux keyring). Never in config files.
- **DB key**: Auto-generated, stored in OS keychain.
- **config.json**: Contains only name, relays, owner, pubkey_hex. No secrets.
- **Backup**: `POST /backup-mnemonic` requires owner identity verification.

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `~/.local/share/keychat-agent` | Config + DB directory |
| `--relay` | `wss://nos.lol` | Nostr relay(s), comma-separated |
| `--listen` | `127.0.0.1:7700` | HTTP listen address |
| `--auto-accept` | `true` | Auto-accept (with DM Policy) |
| `--name` | `keychat-agent` | Agent display name |
| `--multi` | `false` | Multi-agent mode |
