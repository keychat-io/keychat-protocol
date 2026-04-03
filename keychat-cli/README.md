# keychat-cli

A terminal client for the [Keychat protocol](../README.md) — sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption. Built on [keychat-uniffi](../keychat-uniffi/), the same protocol library that powers the Keychat iOS app.

## Overview

keychat-cli provides four interface modes for interacting with the Keychat network:

| Mode                 | Description                                                                | Best for                          |
| -------------------- | -------------------------------------------------------------------------- | --------------------------------- |
| **TUI** (default)    | Full terminal UI with ratatui — room list, messages, input bar, status bar | Daily use                         |
| **Interactive REPL** | Readline-based REPL with 30 slash commands                                 | Scripting, debugging              |
| **HTTP Daemon**      | REST API with 18 endpoints + SSE event stream                              | Bots, integrations, web frontends |
| **Agent**            | Headless daemon with Bearer auth for AI frameworks                         | AI agents, Claude Code, OpenClaw  |

### Key Features

- **E2E encryption** — Signal Protocol (PQXDH) for 1:1 and group chats over Nostr
- **Database encryption** — DB key stored in OS keyring (macOS Keychain, Linux secret-service) with automatic file fallback
- **Signal groups** — Create, invite, rename, kick, leave, and dissolve encrypted group chats
- **Multi-instance** — Run multiple identities side-by-side via `--data-dir` isolation
- **Shared protocol library** — Uses keychat-uniffi, identical to the iOS app

## Installation

### From source (recommended)

```sh
# Clone the repository
git clone https://github.com/nicepkg/keychat-protocol.git
cd keychat-protocol

# Install the binary
cargo install --path keychat-cli
```

### Build only

```sh
cargo build -p keychat-cli --release
# Binary at target/release/keychat
```

## Quick Start

```sh
# 1. Launch the TUI
keychat

# 2. Create an identity (in REPL mode for clarity)
keychat interactive
> /create

# 3. Connect to relays
> /add-relay wss://relay.damus.io
> /connect

# 4. Add a friend by their npub/hex pubkey
> /add npub1...

# 5. Once they accept, start chatting
> /chat npub1...
> Hello from keychat-cli!
```

## Usage Modes

### TUI Mode (default)

```sh
keychat          # Start TUI
keychat tui      # Explicit
```

Full terminal UI powered by [ratatui](https://ratatui.rs/):

```
┌─ Rooms ──────────┬─ Messages ──────────────────────────┐
│ ● Alice          │ Alice: Hey, are you there?           │
│   Bob            │ You: Yes! Testing keychat-cli        │
│   Signal Group 1 │ Alice: Nice, encryption working      │
│                  │                                      │
│                  ├──────────────────────────────────────│
│                  │ > Type a message...                  │
├──────────────────┴──────────────────────────────────────┤
│ ✓ Connected │ Identity: npub1abc... │ 3 rooms           │
└─────────────────────────────────────────────────────────┘
```

**Keyboard shortcuts:**

| Key      | Action                                           |
| -------- | ------------------------------------------------ |
| `Tab`    | Switch between panels (rooms / messages / input) |
| `↑` `↓`  | Navigate room list or scroll messages            |
| `Enter`  | Select room / send message                       |
| `Esc`    | Go back / deselect                               |
| `F1`     | Toggle help overlay                              |
| `Ctrl-C` | Quit                                             |

### Interactive REPL

```sh
keychat interactive
```

A simple readline-based REPL. Type slash commands or plain text (sent as a message to the active chat room). Supports history, line editing, and tab completion.

```
keychat> /whoami
  Identity: npub1abc...def
  Public key: abc123...def456

keychat> /chat npub1abc...
  Now chatting with: Alice

keychat [Alice]> Hello!
  Message sent.
```

### HTTP Daemon

```sh
keychat daemon --port 8080           # REST API only
keychat daemon --port 8080 --interactive  # REST API + REPL side-by-side
```

Starts an HTTP server exposing a REST API and an SSE event stream. Ideal for building bots, web frontends, or integrating Keychat into other systems.

### Agent Mode

```sh
keychat agent                          # Start with defaults
keychat agent --name "MyBot"           # Custom display name
keychat agent --port 9000              # Custom port
keychat agent --no-auto-accept         # Manual friend approval only
keychat agent --api-token mytoken123   # Custom API token
```

Headless daemon designed for AI frameworks. On first run it automatically creates an identity, generates an API token, and starts listening:

```
$ keychat agent --name "MyBot"
Agent ready: npub1abc...xyz
API token: kc_7f3a2b...
Listening on http://0.0.0.0:10443
```

All HTTP endpoints require Bearer token authentication. Agent mode adds friend request auto-accept policy, owner management, and pending request queues on top of the standard daemon API.

**CLI options:**

| Flag               | Default            | Description                             |
| ------------------ | ------------------ | --------------------------------------- |
| `--port`           | `10443`            | HTTP listen port                        |
| `--name`           | `Keychat Agent`    | Agent display name                      |
| `--no-auto-accept` | _(off)_            | Disable auto-accept for friend requests |
| `--relay`          | _(default relays)_ | Relay URLs, comma-separated             |
| `--api-token`      | _(auto-generated)_ | API Bearer token                        |
| `--data-dir`       | `~/.keychat`       | Data directory                          |

**Headless secrets:** Secrets resolve in priority order for container/CI deployments:

| Secret            | Env Var             | File                | Fallback                     |
| ----------------- | ------------------- | ------------------- | ---------------------------- |
| DB encryption key | `KEYCHAT_DB_KEY`    | `secrets/dbkey`     | OS keyring / auto-gen        |
| Identity mnemonic | `KEYCHAT_MNEMONIC`  | `secrets/mnemonic`  | Create new / restore from DB |
| API token         | `KEYCHAT_API_TOKEN` | `secrets/api-token` | `kc_` + random hex           |

Secret files are stored in `<data-dir>/secrets/` with `0600` permissions.

**Owner policy:**

1. First friend request is auto-accepted, sender becomes the **owner**
2. Subsequent requests from the owner are auto-accepted
3. Requests from others are queued as **pending** (approve/reject via API)
4. Use `--no-auto-accept` to require manual approval for all requests

### Identity

| Command            | Description                                           |
| ------------------ | ----------------------------------------------------- |
| `/create`          | Create a new Nostr identity                           |
| `/import`          | Import an existing identity from nsec/hex private key |
| `/whoami`          | Show current identity (npub, hex pubkey)              |
| `/backup`          | Export identity for backup (displays nsec)            |
| `/delete-identity` | Delete the current identity                           |

### Connection

| Command               | Description                                |
| --------------------- | ------------------------------------------ |
| `/connect`            | Connect to all configured relays           |
| `/disconnect`         | Disconnect from all relays                 |
| `/reconnect`          | Disconnect and reconnect to all relays     |
| `/relays`             | List configured relays and their status    |
| `/add-relay <url>`    | Add a relay (e.g., `wss://relay.damus.io`) |
| `/remove-relay <url>` | Remove a relay                             |
| `/status`             | Show connection status overview            |

### Friends

| Command         | Description                     |
| --------------- | ------------------------------- |
| `/add <pubkey>` | Send a friend request           |
| `/accept <id>`  | Accept a pending friend request |
| `/reject <id>`  | Reject a pending friend request |
| `/contacts`     | List all contacts               |

### Messaging

| Command          | Description                       |
| ---------------- | --------------------------------- |
| `/rooms`         | List all chat rooms               |
| `/chat <pubkey>` | Switch to a 1:1 chat room         |
| `/read`          | Mark current room as read         |
| `/history [n]`   | Show recent message history       |
| _(plain text)_   | Send a message to the active room |

### Signal Groups

| Command                  | Description                          |
| ------------------------ | ------------------------------------ |
| `/sg-create <name>`      | Create a new Signal group            |
| `/sg-chat <id>`          | Switch to a Signal group chat        |
| `/sg-rename <id> <name>` | Rename a Signal group                |
| `/sg-kick <id> <pubkey>` | Remove a member from a Signal group  |
| `/sg-leave <id>`         | Leave a Signal group                 |
| `/sg-dissolve <id>`      | Dissolve a Signal group (admin only) |

### Utility

| Command  | Description                 |
| -------- | --------------------------- |
| `/retry` | Retry failed message sends  |
| `/debug` | Toggle debug output         |
| `/help`  | Show all available commands |
| `/quit`  | Exit the application        |

## API Reference

The HTTP daemon exposes the following REST endpoints. All request/response bodies are JSON.

### Identity

| Method | Endpoint           | Description              |
| ------ | ------------------ | ------------------------ |
| `GET`  | `/identity`        | Get current identity     |
| `POST` | `/identity/create` | Create a new identity    |
| `POST` | `/identity/import` | Import identity from key |

### Connection

| Method   | Endpoint      | Description            |
| -------- | ------------- | ---------------------- |
| `GET`    | `/status`     | Connection status      |
| `POST`   | `/connect`    | Connect to relays      |
| `POST`   | `/disconnect` | Disconnect from relays |
| `GET`    | `/relays`     | List relays            |
| `POST`   | `/relay`      | Add a relay            |
| `DELETE` | `/relay`      | Remove a relay         |

### Friends

| Method | Endpoint                     | Description             |
| ------ | ---------------------------- | ----------------------- |
| `GET`  | `/contacts`                  | List contacts           |
| `POST` | `/friend-request`            | Send a friend request   |
| `POST` | `/friend-request/:id/accept` | Accept a friend request |
| `POST` | `/friend-request/:id/reject` | Reject a friend request |

### Messaging

| Method | Endpoint              | Description            |
| ------ | --------------------- | ---------------------- |
| `GET`  | `/rooms`              | List all rooms         |
| `GET`  | `/rooms/:id/messages` | Get messages in a room |
| `POST` | `/rooms/:id/send`     | Send a message         |
| `POST` | `/rooms/:id/read`     | Mark room as read      |

### Server-Sent Events

| Method | Endpoint  | Description                    |
| ------ | --------- | ------------------------------ |
| `GET`  | `/events` | SSE stream of real-time events |

The `/events` endpoint streams events as they occur — new messages, friend requests, connection status changes, etc. Connect with any SSE client:

```sh
# Daemon mode (no auth)
curl -N http://localhost:8080/events

# Agent mode (Bearer token required)
curl -N -H "Authorization: Bearer kc_abc123..." http://localhost:10443/events
```

## Configuration

## Multi-Instance

Run multiple independent Keychat identities on the same machine using `--data-dir`:

```sh
# Terminal 1 — Alice
keychat --data-dir ~/.keychat-alice tui

# Terminal 2 — Bob
keychat --data-dir ~/.keychat-bob interactive

# Terminal 3 — Bot (daemon)
keychat --data-dir ~/.keychat-bot daemon --port 9000

# Terminal 4 — AI Agent
keychat --data-dir ~/.keychat-agent agent --name "MyBot" --port 10443
```

Each instance has its own database, identity, and keyring entry. They can communicate with each other over relays just like any other Keychat clients.

## Building from Source

### Prerequisites

- Rust 1.75+ (edition 2021)
- A C compiler (for SQLCipher / libsqlite3)
- On Linux: `libdbus-1-dev` and `libsecret-1-dev` (for keyring support)

### Build

```sh
cargo build -p keychat-cli --release
```

### Test

```sh
cargo test -p keychat-cli
```

### Install

```sh
cargo install --path keychat-cli
```

This installs the `keychat` binary to `~/.cargo/bin/`.

## License

See the repository root [LICENSE](../LICENSE) for details.
