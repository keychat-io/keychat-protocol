# Keychat Channel Plugin for Claude Code

E2E encrypted messaging channel that bridges Claude Code to a [keychat-cli](../keychat-cli/) agent daemon via HTTP API.

## Architecture

```
Claude Code ←stdio MCP→ this plugin ←HTTP→ keychat agent daemon ←Nostr→ Relay
```

The daemon handles all encryption (Signal PQXDH + NIP-17 gift-wrap). This plugin only does MCP ↔ HTTP translation. All API calls use Bearer token authentication.

## Setup

### 1. Start the agent daemon

```bash
keychat agent --name "MyBot"
# Output:
#   Agent ready: npub1xxx...
#   API token: kc_abc123...
#   Listening on http://0.0.0.0:10443
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

### 3. Configure

```bash
# In Claude Code:
/keychat:configure                          # Check status
/keychat:configure http://host:10443        # Set daemon URL
/keychat:configure token kc_abc123...       # Set API token
```

Configuration is stored in `~/.claude/channels/keychat/config.json`:

```json
{
  "daemonUrl": "http://127.0.0.1:10443",
  "apiToken": "kc_abc123..."
}
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

### Messaging

| Tool | Description |
|------|-------------|
| `reply` | Send a message to a Keychat room |
| `fetch_messages` | Fetch recent messages from a room |
| `list_rooms` | List all rooms/conversations |
| `list_contacts` | List all contacts |

### Agent Management

| Tool | Description |
|------|-------------|
| `get_identity` | Get agent identity (pubkey, npub, name) |
| `get_status` | Get daemon status (connection, relays) |
| `send_friend_request` | Send a friend request to a Nostr pubkey |
| `pending_friends` | List pending friend requests |
| `approve_friend` | Approve a pending friend request |
| `reject_friend` | Reject a pending friend request |

## How It Works

1. Plugin connects to daemon's SSE `/events` endpoint for real-time messages (with Bearer token)
2. Incoming messages are forwarded as MCP `notifications/claude/channel` notifications
3. Claude Code can reply using the `reply` tool, which POSTs to the daemon's `/send` endpoint
4. Access control filters messages by sender pubkey before forwarding

## SSE Events Forwarded

| Event | Forwarded As |
|-------|-------------|
| `message_received` | Channel notification with room_id, sender, content |
| `friend_request_received` | System notification with request details |
| `friend_request_accepted` | System notification |

## Configuration Files

All stored in `~/.claude/channels/keychat/`:

- `config.json` — daemon URL and API token
- `access.json` — sender allowlist and policy
