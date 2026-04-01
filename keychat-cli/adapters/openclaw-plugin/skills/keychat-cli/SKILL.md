---
name: keychat-cli
description: "Install Keychat CLI — E2E encrypted messaging channel for OpenClaw agents via Signal Protocol over Nostr relays. Use when the user wants to add Keychat, set up encrypted messaging, or install keychat-cli for their agent."
---

# Install Keychat CLI

Keychat adds E2E encrypted messaging to your OpenClaw agent. Users talk to your agent via the Keychat app (iOS/Android).

## Prerequisites

- `qrencode` for QR code generation (install with `brew install qrencode` on macOS or `apt install qrencode` on Linux)

## Install

```bash
openclaw plugins install @keychat-io/keychat-cli
```

This runs `postinstall.sh` which:
1. Downloads the keychat-cli binary for the current platform
2. Starts the agent daemon on `127.0.0.1:7800`
3. Creates a Keychat identity (stored in system keychain)
4. Generates a QR code image (`~/.keychat/npub-qr.png`)
5. Outputs the npub and QR image path

## After Install

postinstall outputs `npub:` and `QR_IMAGE:` lines for each agent. You MUST:

1. **Parse the output** — extract each agent's npub and QR image path
2. **Send to the CURRENT channel/room** (the one where the user asked to install) using the message tool:
   - For each agent: send npub text + QR image (use `media` parameter, not file path text)
   - Add: "⏳ 1分钟后可以加 agent" (gives time for plugin + gateway restart)
   - Do NOT send links, only npub and QR image
   - Send to the current room/group, NOT to the user's DM
3. **Configure the plugin** in openclaw.json (add channels.keychat-cli config with accounts matching agents.list)
4. **Restart the gateway** so the plugin loads and connects to the daemon SSE
5. After restart, plugin auto-connects to daemon — messages start flowing

### Message format example
```
🔑 Keychat CLI installed!

Main Agent npub:
npub1xxx...
[QR image attached]

Test Agent npub:
npub1yyy...
[QR image attached]

⏳ 1分钟后可以加 agent
```

### Critical rules
- Send npub + QR BEFORE restarting gateway (restart may disconnect your session)
- Send to the current channel/room, not DM
- Use message tool with `media` parameter for QR images
- The first person to add the agent becomes the owner (auto-approved)

## Config

After install, the plugin auto-configures. If you need to adjust:

```bash
openclaw config set channels.keychat-cli.enabled true
openclaw config set channels.keychat-cli.url "http://127.0.0.1:7800"
```

## Friend Approval

- **First person** to add the agent as friend becomes the **owner** (auto-approved)
- **Others** are held as pending — the agent notifies the owner and waits for approval
- Owner says "approve" → agent uses `keychat_approve_friend` tool
- One approval = Signal session + agent access (both layers synced)

## Troubleshooting

If the agent daemon isn't running:
```bash
keychat agent --port 7800 &
```

Check status:
```bash
curl http://127.0.0.1:7800/identity
curl http://127.0.0.1:7800/status
```
