# Keychat Protocol

Keychat protocol is a sovereign messaging stack that integrates five layers:

- **Identity** — Nostr keypair, self-custodial with no server dependency
- **Transport** — Nostr relay network, open and self-hostable
- **Encryption** — Signal Protocol for 1-to-1 and small group chats, MLS for large group messaging
- **Addressing** — Receiving and sending addresses are decoupled from identity and continuously rotate
- **Stamps** — Cashu ecash tokens attached to messages as anonymous micropayments to relays

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Apps                           │
├──────────────┬──────────────┬───────────────┬───────────────┤
│   iOS App    │ Android App  │  Desktop App  │  keychat-cli  │
│   (Swift)    │  (Kotlin)    │ (Tauri/etc.)  │   (Rust)      │
└──────┬───────┴──────┬───────┴───────┬───────┴───────┬───────┘
       │              │               │               │
       ▼              ▼               │               │
┌─────────────────────────────┐      │               │
│      keychat-uniffi         │      │               │
│  (thin FFI export layer)    │      │               │
│  UniFFI → Swift / Kotlin    │      │               │
└──────────────┬──────────────┘      │               │
               │                     │               │
               ▼                     ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                     keychat-app-sdk                          │
│                    (thin glue layer)                         │
│                                                             │
│  App Data (rooms, messages, contacts, attachments)          │
│  App Storage (SQLCipher) · Relay Publish & Tracking         │
│  UI Callbacks (EventListener / DataListener)                │
│  HTTP File Upload/Download · Event Loop Infrastructure      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                       libkeychat                            │
│            (protocol + business logic)                       │
│                                                             │
│  KeychatContext · Message Routing · Send Orchestration       │
│  Session Management · Group Fan-out · Friend Requests       │
│  Identity (BIP-39/NIP-06) · Signal Protocol (PQXDH)        │
│  MLS (RFC 9420) · NIP-17/44 Encryption · Nostr Transport   │
│  Address Rotation · Cashu Stamps · Secure Storage           │
└─────────────────────────────────────────────────────────────┘
```

## Contents

### Core

- **[libkeychat](libkeychat/)** — Protocol implementation and business logic (encryption, routing, session management)
- **[keychat-app-sdk](keychat-app-sdk/)** — Thin glue layer: app storage, relay publishing, UI callbacks, file I/O
- **[keychat-uniffi](keychat-uniffi/)** — Thin UniFFI export layer for Swift/Kotlin bindings
- **[Keychat Spec](SPEC.md)** — Authoritative protocol specification (v0.4.0-draft)
- **[Client Guide](libkeychat/docs/client-guide.md)** — KeychatClient API guide and usage examples

### CLI & Tools

- **[keychat-cli](keychat-cli/)** — Terminal client with 4 modes: TUI, REPL, HTTP daemon, and AI agent
- **[keychat-claude-mcp](keychat-claude-mcp/)** — Claude MCP server for keychat agent daemon
- **[keychat-agent-skill](keychat-agent-skill/)** — OpenClaw skill + bridge for agent daemon

### [NIPs](nips/)

Nostr Implementation Possibilities proposed by Keychat:

| NIP                                                           | Title                                                                                        | Status |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------ |
| [NIP-XX: Signal Protocol over Nostr](nips/nip-signal.md)      | E2E encrypted 1:1 messaging using Signal Protocol (PQXDH + Double Ratchet) over Nostr relays | Draft  |
| [NIP-XX: MLS Protocol over Nostr](nips/nip-mls.md)            | E2E encrypted group messaging using MLS (RFC 9420) over Nostr relays                         | Draft  |
| [NIP-XX: Ecash Token as Nostr Note Stamp](nips/nip-estamp.md) | Anonymous per-event micropayments to relays using Cashu ecash                                | Draft  |
