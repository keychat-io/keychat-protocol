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

1. **Read the output** — look for `npub:` and `QR_IMAGE:` lines
2. **Send the QR image** to the user who requested the install (use the message tool with the image path from `QR_IMAGE:`)
3. **Send the npub** as text so the user can copy it
4. **Restart the gateway** so the plugin loads:
   ```bash
   openclaw gateway restart
   ```
5. Tell the user: "Scan the QR code or add this npub in Keychat app. The first person to add me becomes the owner."

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
