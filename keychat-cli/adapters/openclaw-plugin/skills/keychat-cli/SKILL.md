---
name: keychat-cli
description: "Install Keychat CLI — E2E encrypted messaging channel for OpenClaw agents via Signal Protocol over Nostr relays. Use when the user wants to add Keychat, set up encrypted messaging, or install keychat-cli for their agent."
---

# Install Keychat CLI

Keychat adds E2E encrypted messaging to your OpenClaw agent. Users talk to your agent via the Keychat app (iOS/Android).

## Prerequisites

- `qrencode` for QR code generation (install with `brew install qrencode` on macOS or `apt install qrencode` on Linux)

## Install Steps (execute in order, do NOT reorder)

### Step 1: Install plugin files (NO restart)

Copy plugin files to extensions directory. Do NOT use `openclaw plugins install` — it triggers a gateway restart that breaks the session.

```bash
cp -r <plugin_source_path> ~/.openclaw/extensions/keychat-cli
```

If installing from npm, download and extract manually:
```bash
npm pack @keychat-io/keychat-cli --pack-destination /tmp
mkdir -p ~/.openclaw/extensions/keychat-cli
tar xzf /tmp/keychat-io-keychat-cli-*.tgz -C ~/.openclaw/extensions/keychat-cli --strip-components=1
```

### Step 2: Run postinstall

```bash
bash ~/.openclaw/extensions/keychat-cli/scripts/postinstall.sh
```

This installs the keychat-cli binary, starts the daemon (launchd/systemd), and generates an identity + QR code for each agent.

Parse the output — look for `npub:` and `QR_IMAGE:` lines for each agent.

### Step 3: Send npub + QR to user

Send IMMEDIATELY to the CURRENT channel/room. Do this BEFORE any restart.

Total messages = 1 + number of agents.
Use the user's language.

**Message 1 (text only):**

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

**Message 2..N (one per agent, QR image):**
```
Agent "<agent_id>" QR:
[attach ~/.keychat/qr-<agent_id>.png via message tool filePath parameter]
```

### Step 4: Configure plugin + channel (triggers restart)

Use gateway config.patch to write BOTH plugin entry AND channel config in one call:

```json
{
  "plugins": {
    "load": { "paths": ["~/.openclaw/extensions/keychat-cli"] },
    "entries": { "keychat-cli": { "enabled": true, "config": {} } }
  },
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

Build accounts from agent IDs in postinstall output. This triggers gateway restart — plugin loads and connects to daemon.

### Critical rules
- Steps MUST be in this order: copy files → postinstall → send messages → config.patch
- Gateway restart happens ONLY at the end (step 4), AFTER messages are sent
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
