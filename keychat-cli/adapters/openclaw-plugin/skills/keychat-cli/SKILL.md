---
name: keychat-cli
description: "Install Keychat CLI — E2E encrypted messaging channel for OpenClaw agents via Signal Protocol over Nostr relays. Use when the user wants to add Keychat, set up encrypted messaging, or install keychat-cli for their agent."
---

# Install Keychat CLI

Keychat adds E2E encrypted messaging to your OpenClaw agent. Users talk to your agent via the Keychat app (iOS/Android).

## Prerequisites

- `qrencode` for QR code generation (install with `brew install qrencode` on macOS or `apt install qrencode` on Linux)

## Install Steps (execute in order)

### Step 1: Install plugin

```bash
openclaw plugins install @keychat-io/keychat-cli
```

This installs the plugin TS code and triggers a gateway restart. Wait for gateway to come back (~10s).

### Step 2: Run postinstall

```bash
bash ~/.openclaw/extensions/keychat-cli/scripts/postinstall.sh
```

This installs the keychat-cli binary, starts the daemon (launchd/systemd), and generates an identity + QR code for each agent.

Parse the output — look for `npub:` and `QR_IMAGE:` lines for each agent.

### Step 3: Send npub + QR to user

Send to the CURRENT channel/room where the user asked to install. Use the message tool.

Total messages = 1 + number of agents.
Use the user's language (match the language they used to request the install).

**Message 1 (text only, no media) — summary:**

Content (adapt to user's language):
- 🔑 Keychat CLI installed!
- List each agent's ID (npub)
- Tell user they can add agents now via Keychat app
- Mention they can also scan QR codes below

Example:
```
🔑 Keychat CLI installed!

Agent "main" ID:
npub1xxx...

Agent "test" ID:
npub1yyy...

You can now add these agents in Keychat app, or scan the QR codes below.
```

**Message 2..N (one per agent, image with caption):**
```
Agent "<agent_id>" QR:
[attach ~/.keychat/qr-<agent_id>.png via message tool filePath parameter]
```

### Step 4: Configure channel accounts

Use the gateway config.patch tool to write channel config:

```json
{
  "channels": {
    "keychat-cli": {
      "enabled": true,
      "url": "http://127.0.0.1:7800",
      "accounts": {
        "<agent_id>": { "enabled": true, "dmPolicy": "open", "allowFrom": ["*"] }
      }
    }
  }
}
```

Build accounts from the agent IDs in the postinstall output. This triggers a hot-reload — plugin connects to daemon SSE automatically.

### Critical rules
- Steps MUST be in this order: plugin install → postinstall → send messages → config.patch
- Send npub + QR BEFORE config.patch (config.patch is safe but messages should go out first)
- Send to the current channel/room (use group:ID for group chats), NOT to user's DM
- Use `message` tool with `filePath` for QR images — do NOT use MEDIA: inline syntax
- The first person to add the agent becomes the owner (auto-approved)

## Friend Approval

- **First person** to add the agent as friend becomes the **owner** (auto-approved)
- **Others** are held as pending — the agent notifies the owner and waits for approval
- Owner says "approve" → agent uses `keychat_approve_friend` tool

## Troubleshooting

Check daemon status:
```bash
curl http://127.0.0.1:7800/agents
```
