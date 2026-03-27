# Keychat Channel Plugin for Claude Code

E2E encrypted messaging channel that bridges Claude Code to a [keychat-cli](../keychat-cli/) daemon via HTTP API.

## Architecture

```
Claude Code ←stdio MCP→ this plugin ←HTTP→ keychat-cli daemon ←Nostr→ Relay
```

The daemon handles all encryption (Signal PQXDH + NIP-17 gift-wrap). This plugin only does MCP ↔ HTTP translation.

## Setup

### 1. Start the daemon

```bash
keychat daemon --port 8080
```

### 2. Install the plugin

Add to your Claude Code MCP config (`~/.claude/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "keychat": {
      "command": "npx",
      "args": ["tsx", "/path/to/keychat-channel-plugin/server.ts"]
    }
  }
}
```

### 3. Configure (optional)

```bash
# In Claude Code:
/keychat:configure              # Check status
/keychat:configure http://host:port  # Set daemon URL (default: http://127.0.0.1:8080)
```

### 4. Manage access

```bash
/keychat:access                 # Show access status
/keychat:access allow <pubkey>  # Allow a sender (hex pubkey)
/keychat:access remove <pubkey> # Remove a sender
/keychat:access policy allowlist # Restrict to allowlist only
/keychat:access policy open      # Allow all senders
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `reply` | Send a message to a Keychat room |
| `fetch_messages` | Fetch recent messages from a room |
| `list_rooms` | List all rooms/conversations |
| `list_contacts` | List all contacts |
| `get_status` | Get daemon status (identity, relays) |

## How It Works

1. Plugin connects to daemon's SSE `/events` endpoint for real-time messages
2. Incoming messages are forwarded as MCP `notifications/claude/channel` notifications
3. Claude Code can reply using the `reply` tool, which POSTs to the daemon's HTTP API
4. Access control filters messages by sender pubkey before forwarding

## Configuration Files

All stored in `~/.claude/channels/keychat/`:

- `config.json` — daemon URL
- `access.json` — sender allowlist and policy
