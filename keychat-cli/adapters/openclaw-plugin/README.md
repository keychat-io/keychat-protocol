# @keychat-io/keychat-cli

OpenClaw channel plugin for [keychat-cli](https://github.com/keychat-io/keychat-protocol/tree/main/keychat-cli) — E2E encrypted messaging via Signal Protocol + Nostr.

## Install

```bash
openclaw plugin add @keychat-io/keychat-cli
```

This will:
1. Download the keychat-cli binary for your platform
2. Start the agent daemon
3. Create a new Keychat identity
4. Output your agent's npub + QR code

## Architecture

```
Keychat App ←→ Nostr Relay ←→ keychat-cli agent (:7800)
                                    ↕ HTTP API (localhost)
                              this plugin (pure TS)
                                    ↕
                              OpenClaw Gateway → Agent
```

## How It Works

- **Inbound**: SSE from `GET /events` → DM policy check → dispatch to agent
- **Outbound**: Agent reply → `POST /send` → daemon encrypts → Nostr relay
- **Friend requests**: First person = owner (auto-accept). Others → notify owner → owner approves via natural language

## Config

Add to `openclaw.json`:

```json
{
  "channels": {
    "keychat-cli": {
      "enabled": true,
      "url": "http://127.0.0.1:7800"
    }
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `url` | `http://127.0.0.1:7800` | Daemon URL |
| `dmPolicy` | `pairing` | `open` / `allowlist` / `pairing` / `disabled` |
| `allowFrom` | `[]` | Allowed sender pubkeys |
