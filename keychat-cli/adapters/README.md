# Keychat Agent Adapters

Connect the Keychat agent daemon to AI tools via bridge adapters. One agent daemon, multiple AI tools.

## Quick Start

```bash
# Claude Code
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-claude-code.sh | bash

# OpenAI Codex
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-codex.sh | bash

# Gemini CLI
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-gemini.sh | bash

# OpenClaw / ZeroClaw / NanoClaw
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-openclaw.sh | bash
curl -fsSL ... | bash -s -- --variant zeroclaw
curl -fsSL ... | bash -s -- --variant nanoclaw

# Pi / Headless server
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-protocol/main/keychat-cli/adapters/setup/setup-pi.sh | bash
```

## Architecture

```
                ┌──────────────────────────┐
                │   Keychat Agent Daemon   │
                │   HTTP API + SSE         │
                │   (:10443)               │
                └──────────┬───────────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
       MCP Server     Claw Bridge    Direct API
       (TypeScript)   (Bash)         (curl/SDK)
            │              │
       ┌────┼────┐    ┌────┼────┐
       │    │    │    │    │    │
    Claude Codex Gem  OC  ZC  NC
     Code              Pi
```

**Key insight**: Claude Code, Codex, and Gemini CLI all support MCP — one server covers all three. OpenClaw derivatives share a CLI interface — one configurable bridge covers all.

## Comparison

| Tool | Protocol | Adapter | Setup Script |
|------|----------|---------|--------------|
| Claude Code | MCP (stdio) | `mcp/server.ts` | `setup/setup-claude-code.sh` |
| OpenAI Codex | MCP (stdio) | `mcp/server.ts` | `setup/setup-codex.sh` |
| Gemini CLI | MCP (stdio) | `mcp/server.ts` | `setup/setup-gemini.sh` |
| OpenClaw | CLI exec | `claw/bridge.sh` | `setup/setup-openclaw.sh` |
| ZeroClaw | CLI exec | `claw/bridge.sh` | `setup/setup-openclaw.sh --variant zeroclaw` |
| NanoClaw | CLI exec | `claw/bridge.sh` | `setup/setup-openclaw.sh --variant nanoclaw` |
| Pi/Headless | HTTP API | (direct) | `setup/setup-pi.sh` |

## Directory Structure

```
adapters/
├── README.md                    # this file
├── common/
│   ├── keychat-client.sh        # shared bash HTTP/SSE client
│   └── keychat-client.ts        # shared TypeScript HTTP/SSE client
├── mcp/
│   ├── server.ts                # MCP server (Claude Code, Codex, Gemini)
│   └── package.json
├── claw/
│   ├── bridge.sh                # configurable bridge (OpenClaw + derivatives)
│   └── SKILL.md                 # OpenClaw skill manifest
├── setup/
│   ├── setup-claude-code.sh     # curl | bash installer
│   ├── setup-codex.sh
│   ├── setup-gemini.sh
│   ├── setup-openclaw.sh        # also --variant zeroclaw/nanoclaw
│   └── setup-pi.sh              # headless / Raspberry Pi
└── tests/
    └── test-adapters.sh         # verification script
```

## Shared Client Libraries

### Bash (`common/keychat-client.sh`)

Source this in any bash bridge:

```bash
source keychat-client.sh
export KC_TOKEN="kc_abc123..."

kc_identity          # GET /identity
kc_status            # GET /status
kc_rooms             # GET /rooms
kc_messages <id> 50  # GET /rooms/<id>/messages?limit=50
kc_contacts          # GET /contacts
kc_send <id> "text"  # POST /send
kc_pending           # GET /pending-friends
kc_approve <id>      # POST /approve-friend
kc_reject <id>       # POST /reject-friend
kc_owner             # GET /owner
kc_wait_ready 30     # poll /status until connected
kc_sse_listen        # SSE loop (override kc_on_message etc.)
kc_session_id <pk> <group_id>  # routing helper
```

### TypeScript (`common/keychat-client.ts`)

Import in any TypeScript adapter:

```typescript
import { KeychatClient } from "../common/keychat-client.js";

const client = new KeychatClient({
  daemonUrl: "http://127.0.0.1:10443",
  apiToken: "kc_abc123...",
});

await client.identity();
await client.send(roomId, "Hello!");
const controller = client.subscribe({
  onMessage: (data) => console.log(data),
});
```

## Writing Your Own Adapter

Any language that can make HTTP calls and consume SSE can be an adapter. The agent daemon API is simple:

1. **Receive messages**: Connect to `GET /events` (SSE stream)
2. **Process**: Pass message to your AI tool
3. **Reply**: `POST /send` with `{"room_id":"...","text":"..."}`

All requests need `Authorization: Bearer <token>` header. See the [CLI README](../README.md) for the full API reference.

## MCP Tools

The MCP server exposes these tools to AI assistants:

| Tool | Description |
|------|-------------|
| `reply` | Send a message to a room |
| `fetch_messages` | Get message history |
| `list_rooms` | List all rooms |
| `list_contacts` | List all contacts |
| `get_status` | Connection status |
| `get_identity` | Agent identity |
| `send_friend_request` | Add a friend |
| `pending_friends` | List pending requests |
| `approve_friend` | Accept a request |
| `reject_friend` | Reject a request |

## Testing

```bash
# Syntax check all scripts
bash adapters/tests/test-adapters.sh

# With a running agent daemon
KC_TOKEN=kc_abc... bash adapters/tests/test-adapters.sh --live
```
