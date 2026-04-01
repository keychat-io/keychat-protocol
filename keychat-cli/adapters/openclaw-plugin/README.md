# @keychat-io/keychat-cli

OpenClaw channel plugin for [keychat-cli](https://github.com/keychat-io/keychat-protocol/tree/main/keychat-cli) — E2E encrypted messaging via Signal Protocol + Nostr.

## Install

### Command Line (for developers)

```bash
# Step 1: Install the plugin (triggers gateway restart)
openclaw plugins install @keychat-io/keychat-cli

# Step 2: Install keychat-cli binary, start daemon, generate identities
bash ~/.openclaw/extensions/keychat-cli/scripts/postinstall.sh
```

After installation, ask your agent for its Keychat npub on any existing channel (Discord, Telegram, etc.), then add it as a friend in the [Keychat app](https://www.keychat.io).

### Via Agent (for non-technical users)

Simply tell your agent: **"Install keychat-cli"**. The agent will handle everything and send you the npub + QR code.

## Architecture

```
Keychat App ←→ Nostr Relay ←→ keychat-cli agent (:7800)
                                    ↕ HTTP API (localhost)
                              this plugin (pure TS)
                                    ↕
                              OpenClaw Gateway → Agent
```

## How It Works

- **Inbound**: SSE from `GET /agents/{id}/events` → DM policy check → dispatch to agent
- **Outbound**: Agent reply → `POST /agents/{id}/send` → daemon encrypts → Nostr relay
- **Multi-agent**: Each OpenClaw agent gets its own Keychat identity (npub), managed by a single daemon process
- **Friend requests**: First person = owner (auto-accept). Others → notify owner → owner approves via natural language

## Config

Automatically configured by `postinstall.sh`. Manual config:

```json
{
  "channels": {
    "keychat-cli": {
      "enabled": true,
      "url": "http://127.0.0.1:7800",
      "accounts": {
        "main": { "enabled": true, "dmPolicy": "open", "allowFrom": ["*"] }
      }
    }
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `url` | `http://127.0.0.1:7800` | Daemon URL |
| `dmPolicy` | `pairing` | `open` / `allowlist` / `pairing` / `disabled` |
| `allowFrom` | `[]` | Allowed sender pubkeys (`["*"]` for open access) |
