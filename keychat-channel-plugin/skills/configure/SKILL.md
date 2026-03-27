---
name: configure
description: Set up the Keychat channel — configure daemon URL, API token, and review access policy. Use when the user asks to configure Keychat, set the daemon URL or token, asks "how do I set this up," or wants to check channel status.
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Bash(ls *)
  - Bash(mkdir *)
---

# /keychat:configure — Keychat Channel Setup

Writes the daemon URL and API token to `~/.claude/channels/keychat/config.json` and
orients the user on access policy. The channel server reads config at boot.

Arguments passed: `$ARGUMENTS`

---

## State shape

`~/.claude/channels/keychat/config.json`:

```json
{
  "daemonUrl": "http://127.0.0.1:10443",
  "apiToken": "kc_abc123..."
}
```

Missing file = `{daemonUrl: "http://127.0.0.1:10443"}`.

- `daemonUrl`: HTTP URL of the keychat agent daemon
- `apiToken`: Bearer token for authenticating API requests (printed when agent starts)

---

## Dispatch on arguments

Parse `$ARGUMENTS` (space-separated). If empty or unrecognized, show status.

### No args — status and guidance

Read both state files and give the user a complete picture:

1. **Daemon URL** — check `~/.claude/channels/keychat/config.json` for
   `daemonUrl`. Show current value or default (`http://127.0.0.1:10443`).

2. **API Token** — check config for `apiToken`. Show whether set (masked)
   or missing.

3. **Access** — read `~/.claude/channels/keychat/access.json` (missing file
   = defaults: empty allowFrom, autoApproveOwner true). Show:
   - Policy: open (all senders) or allowlist (restricted)
   - Allowed senders: count and list
   - autoApproveOwner setting

4. **Connection test** — suggest the user verify the daemon is running:
   `curl -H "Authorization: Bearer <token>" http://127.0.0.1:10443/status`

5. **What next** — end with a concrete next step based on state:
   - No token set → *"Set the API token with: `/keychat:configure token <your-token>`"*
   - No daemon running → *"Start the agent with: `keychat agent --name MyBot`"*
   - Daemon running, open policy → *"Ready. Messages from any Keychat
     contact will come through. To restrict, run `/keychat:access policy allowlist`
     then add specific pubkeys."*
   - Daemon running, allowlist set → *"Ready. Only allowed pubkeys can
     reach you."*

### `<url>` — save daemon URL

1. Detect if `$ARGUMENTS` looks like an HTTP URL (starts with `http://` or `https://`).
2. `mkdir -p ~/.claude/channels/keychat`
3. Read existing `config.json` if present; update `daemonUrl`, preserve
   other keys. Write back.
4. Confirm, then show the no-args status so the user sees where they stand.
5. Note: config changes need a session restart or `/reload-plugins` to take
   effect.

### `token <value>` — save API token

1. Detect if first word is `token` and extract the value.
2. `mkdir -p ~/.claude/channels/keychat`
3. Read existing `config.json` if present; update `apiToken`, preserve
   other keys. Write back.
4. Confirm with masked token (show first 6 chars + `…`).
5. Note: config changes need a session restart or `/reload-plugins` to take
   effect.

### `clear` — reset to default

1. Read config.json, set `daemonUrl` to `http://127.0.0.1:10443`, remove `apiToken`, write.

---

## Implementation notes

- The channels dir might not exist if the server hasn't run yet. Missing
  file = not configured (uses defaults), not an error.
- The server reads `config.json` once at boot. URL/token changes need a
  session restart or `/reload-plugins`. Say so after saving.
- `access.json` is re-read on every inbound message — policy changes via
  `/keychat:access` take effect immediately, no restart needed.
- The daemon itself handles all encryption (Signal PQXDH + NIP-17
  gift-wrap). The channel plugin only does MCP ↔ HTTP translation. No
  secrets or keys are stored in the channel config.
- The API token is printed to stdout when `keychat agent` starts. The user
  needs to copy it from there.
