# Keychat Protocol Specification v2

> **Version**: 2.0 Draft — 2026-03-13
> **Purpose**: Everything a developer needs to implement a fully interoperable Keychat client.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Identity Layer (Nostr)](#2-identity-layer-nostr)
3. [Transport Layer (Nostr Relays)](#3-transport-layer-nostr-relays)
4. [Message Format (KCMessage v2)](#4-message-format-kcmessage-v2)
5. [Encryption Layer](#5-encryption-layer)
6. [Adding a Contact (Friend Request)](#6-adding-a-contact-friend-request)
7. [Accepting a Friend Request](#7-accepting-a-friend-request)
8. [Signal-Encrypted 1:1 Chat](#8-signal-encrypted-11-chat)
9. [Receiving Address Rotation](#9-receiving-address-rotation)
10. [Signal Group (sendAll)](#10-signal-group-sendall)
11. [MLS Group](#11-mls-group)
12. [Media & File Transfer](#12-media--file-transfer)
13. [Ecash Stamps](#13-ecash-stamps)
14. [Cryptographic Primitives Reference](#14-cryptographic-primitives-reference)
15. [Implementation Checklist](#15-implementation-checklist)

---

## 1. Overview

Keychat protocol is a sovereign messaging stack that integrates five layers:

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Identity** | Nostr secp256k1 keypair (npub/nsec) | Self-custodial, no server dependency |
| **Transport** | Nostr relay network | Open and self-hostable message routing |
| **Encryption** | Signal Protocol with PQXDH (1:1 & small group), MLS (large group) | End-to-end encryption with post-quantum security |
| **Addressing** | Ratchet-derived ephemeral addresses | Receiving and sending addresses decoupled from identity, continuously rotating |
| **Stamps** | Cashu ecash tokens | Anonymous micropayments to relays for message delivery |

### Key Design Principles

1. **Signal as a pure encryption layer**: Keychat abstracts Signal Protocol into a replaceable encryption primitive. Signal handles only encryption and decryption — identity, transport, addressing, and delivery are all handled by other layers. Signal identities (Curve25519 keypairs) are **ephemeral and per-peer**: a new Signal identity is generated for every contact and discarded on session reset. The user's permanent identity is their Nostr keypair, not any Signal key.
2. **Sender anonymity**: Every message is sent from a random ephemeral Nostr keypair. The sender's real npub never appears as a Nostr event author.
3. **Receiver unlinkability**: The receiver's address rotates with each Double Ratchet step, derived deterministically from the ratchet state. Addresses are decoupled from identity — neither relay nor observer can link messages to either party.
4. **Unified transport**: All messages use Nostr event kind 1059, regardless of encryption protocol.
5. **Post-quantum security**: The initial key agreement uses PQXDH (Signal's hybrid classical + post-quantum protocol), combining Curve25519 ECDH with ML-KEM 1024 (Kyber) key encapsulation.
6. **Economic anti-spam**: Cashu ecash stamps serve as anonymous micropayments to relays, enabling permissionless message delivery without accounts or identity disclosure.

### Session Types

| Session Type | Protocol | Encryption Model | Key Rotation | Max Members |
|-------------|----------|-----------------|--------------|-------------|
| Signal 1:1 | Signal (PQXDH + Double Ratchet) | Peer-to-peer session | Per-message ratchet | 2 |
| Signal Group | Signal sendAll | Per-member peer-to-peer | Per-message ratchet | ~50 |
| MLS Group | MLS (RFC 9420) | Shared group secret (ratchet tree) | Per-epoch Commit | Thousands |

---

## 2. Identity Layer (Nostr)

A Keychat identity is a standard Nostr secp256k1 keypair derived per [NIP-06](https://github.com/nostr-protocol/nips/blob/master/06.md):

```
BIP-39 mnemonic (12 or 24 words)
  → BIP-39 seed (with optional passphrase)
  → BIP-32 derivation path: m/44'/1237'/<account>'/0/0
  → secp256k1 keypair
  → pubkey (hex, 64 chars) = Nostr identity
  → npub (bech32 encoding)
  → nsec (bech32 encoding of private key)
```

The derivation path follows [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) coin type 1237 (Nostr). A basic client uses `account = 0`. Advanced clients may increment `account` to derive multiple independent identities from the same mnemonic.

This is the user's **permanent, sovereign identity**. It is used for:
- Signing Nostr events
- NIP-44 encryption (Gift Wrap)
- Long-term discoverable address (others add you by npub)
- Schnorr signature for identity binding (`globalSign`)

### 2.1 Key Storage Security

The BIP-39 mnemonic and derived private key (nsec) are the **root of all identity and encryption**. Compromise of these keys means complete loss of the identity. Implementations **MUST**:

1. **Never store the mnemonic or private key in plaintext config files** (e.g., JSON, YAML, TOML configs that may be version-controlled or world-readable).
2. **Use hardware-backed secure storage when available** (RECOMMENDED):
   - **iOS/macOS**: Keychain Services (`Security.framework`) or Secure Enclave
   - **Android**: Android Keystore system (hardware-backed when available)
   - **Desktop with secure hardware**: TPM-backed credential stores
3. **Fall back to software-based secure storage when hardware is unavailable** (RECOMMENDED):
   - **OS keyring**: `libsecret`/GNOME Keyring, KWallet, macOS Keychain (software mode)
   - **Encrypted secrets file**: A dedicated file (e.g., `secrets/mnemonic`) with restricted permissions (mode `0600`) and, ideally, encrypted with a user-provided passphrase or a separately managed key
   - **Environment variables**: Acceptable for ephemeral/container deployments where the variable is injected securely (e.g., Docker secrets, systemd credentials), but **NOT** for persistent storage on disk
4. **Avoid plaintext file storage** (NOT RECOMMENDED): Storing the mnemonic in a plain unencrypted file without restricted permissions is strongly discouraged. If no better option is available, the file MUST have mode `0600` (owner-read-only) at minimum.
5. **Zeroize private key material from memory** when no longer needed (use `zeroize` crate or equivalent).
6. **Never display the mnemonic at creation time**. Store it directly in secure storage. Only reveal it when the user explicitly requests a backup, after identity verification (biometric, PIN, or owner authentication). Never log it, never include it in crash reports or diagnostics.

> **Storage priority** (from most to least preferred):
> 1. Hardware-backed secure element (Secure Enclave, TPM, Android Keystore)
> 2. OS keyring / Keychain (software-backed)
> 3. Encrypted secrets file (passphrase-protected, mode `0600`)
> 4. Restricted-permission plaintext file (mode `0600`, last resort)
>
> Implementations SHOULD try higher-priority options first and fall back gracefully. For daemon/headless deployments where interactive keychain prompts are not possible, encrypted secrets files or injected environment variables are the expected path.

> **Rationale**: The mnemonic is equivalent to the user's identity. Unlike Signal Protocol keys (which are ephemeral and per-peer), the Nostr keypair is permanent — its compromise cannot be remediated by session reset. It requires the same protection level as a cryptocurrency seed phrase.

### 2.2 Multi-Agent Identity Isolation

Each agent instance MUST have its own **independent identity** — its own BIP-39 mnemonic, its own Nostr keypair (npub/nsec), its own Signal sessions, and its own encrypted database. There is no shared key material between agents.

When multiple agents run on the same host (e.g., multiple AI agents on one server), each agent:

1. **Generates its own mnemonic** at first launch — stored separately in the OS keychain, scoped by its public key.
2. **Has its own npub** — users must add each agent as a separate contact.
3. **Maintains independent state** — separate data directory, separate peer list, separate Signal sessions, separate address manager. No state is shared.
4. **Runs its own daemon** (if using daemon mode) on a separate port with a separate data directory.

This ensures:
- **Compromise isolation**: if one agent's keys are compromised, other agents on the same host are unaffected.
- **Clean identity semantics**: each npub corresponds to exactly one agent with one purpose. Users know exactly who they are talking to.
- **No routing ambiguity**: each agent independently manages its own receiving addresses and relay subscriptions.

> **Example**: An OpenClaw instance hosts a personal assistant agent and a code review agent. Each has its own npub. A user adds both as separate contacts in their Keychat client and chats with each independently.

All Signal Protocol key material (Curve25519 identity keys, signed prekeys, one-time prekeys, Kyber KEM keys) belongs to the **encryption layer** and is **ephemeral, per-peer, and disposable**. A new Signal identity is generated for every contact; it is discarded and regenerated on session reset. Signal identities are not part of a user's identity — they are internal encryption state that the user never sees or manages.

### 2.3 Owner Management (Agent Mode Only)

> **Scope**: This section applies only to **agent deployments** (AI agents running as daemons). Human Keychat clients do not have an "owner" concept — the user controls their own identity directly.

Each agent has an **owner** — the Nostr identity (npub) of the human administrator with management privileges over that agent. The owner can approve/reject friend requests from other peers and perform sensitive operations like mnemonic backup.

**Owner assignment**:
- On first launch, the agent has no owner. The first peer to send a friend request is automatically accepted and becomes the owner.
- Subsequent friend requests require owner approval.

**Owner transfer** (e.g., when the owner's device is lost):
- The agent daemon exposes a `POST /set-owner` endpoint bound to `127.0.0.1` only — not accessible from the network.
- This endpoint accepts a new owner pubkey (npub or hex) or `null` to clear the owner (next friend request becomes owner).
- **Authorization model**: The `/set-owner` API has no authentication at the HTTP level — security relies on localhost binding. When an AI agent framework (e.g., OpenClaw) manages the daemon, owner changes MUST only be executed when the request originates from a verified platform owner, not from arbitrary chat messages. Chat messages (including Keychat) MUST NOT be treated as proof of ownership.

---

## 3. Transport Layer (Nostr Relays)

### 3.1 Relay Connection

Connect to **multiple** Nostr relays simultaneously via WebSocket (`wss://`). All communication uses standard Nostr relay protocol (NIP-01):

- **Publish**: `["EVENT", <event_json>]` or `["EVENT", <event_json>, <ecash_token>]` (ecash stamp is a Keychat relay extension, not standard NIP-01)
- **Subscribe**: `["REQ", <subscription_id>, <filter>]`
- **Unsubscribe**: `["CLOSE", <subscription_id>]`

#### Multi-Relay Broadcast

Implementations **MUST** support connecting to multiple relays and **MUST** broadcast every published event to **all** connected relays simultaneously. This provides:

- **Redundancy**: If one relay is down or censors events, the message still reaches the receiver via other relays.
- **Availability**: The receiver subscribes to the same set of relays and receives the event from whichever relay delivers it first.
- **Censorship resistance**: No single relay can block communication.

Subscriptions **MUST** also be registered on all connected relays. Deduplication ensures each event is processed only once, even if received from multiple relays.

A publish is considered successful if **at least one** relay accepts the event. Implementations SHOULD log relay-level failures but MUST NOT fail the send operation unless all relays reject the event.

Recommended default relays: `wss://nos.lol`, `wss://relay.damus.io`. Implementations SHOULD allow user-configurable relay lists.

### 3.2 Unified Event Kind

All Keychat messages use **kind 1059** as the transport event, regardless of the encryption protocol used. The only exception is MLS KeyPackage publication, which uses kind 10443.

| Kind | Purpose |
|------|---------|
| **1059** | All message transport (Signal, MLS, NIP-17 Gift Wrap) |
| **10443** | MLS KeyPackage (replaceable event, published directly) |

### 3.3 Two Transport Modes

#### Mode 1: Direct Transport (Signal / MLS encrypted messages)

Signal and MLS messages are already end-to-end encrypted at the application layer. They are transported directly as kind 1059 events without additional Nostr-layer encryption:

```
Kind 1059 Event:
  pubkey:      ephemeral one-time key (NOT sender's real pubkey)
  created_at:  real current timestamp (NOT tweaked)
  tags:        [["p", <receiver_address>]]
  content:     base64(signal_or_mls_ciphertext)
```

**Public Agent mode** (§3.6): When the receiver has declared `publicAgent: true`, the sender adds a second `p`-tag with the receiver's npub:

```
Kind 1059 Event (Public Agent mode):
  pubkey:      ephemeral one-time key
  created_at:  real current timestamp
  tags:        [["p", <ratchet_derived_address>], ["p", <agent_npub>]]
  content:     base64(signal_ciphertext)
```

**Note**: Unlike NIP-17 Gift Wrap, Mode 1 uses the **real timestamp** — no random offset. The content is already encrypted by Signal/MLS, so timestamp randomization provides no additional privacy benefit.

Used for:
- Signal 1:1 messages
- Signal Group messages (per-member encrypted)
- MLS Group application messages and Commits
- `mlsGroupInvite` when a Signal session exists with the target

#### Mode 2: NIP-17 Gift Wrap (unencrypted payloads)

When no Signal session exists (e.g., friend requests), NIP-17 three-layer wrapping provides encryption and metadata protection:

```
Layer 3: Gift Wrap (kind 1059)
  pubkey:      ephemeral key (NOT sender's real pubkey)
  created_at:  real current timestamp (NOT tweaked)
  content:     NIP-44 encrypt(ephemeral_privkey, receiver_pubkey) →
    Layer 2: Seal (kind 13)
      pubkey:    sender's real pubkey
      content:   NIP-44 encrypt(sender_real_privkey, receiver_pubkey) →
        Layer 1: Rumor (unsigned event)
          kind:    14
          tags:    [["p", <receiver_pubkey>]]
          content: KCMessage JSON plaintext
```

> **Keychat divergence from NIP-17**: Standard NIP-17 recommends random timestamp offsets (0–2 days) on the Gift Wrap layer. Keychat uses **real timestamps for all kind 1059 events**, including Gift Wraps. Relays filter by `since` — tweaked timestamps may make events invisible to receivers. Since sender anonymity is already provided by ephemeral pubkeys, timestamp tweaking adds no meaningful privacy benefit for Keychat's use cases.

> **Note**: Building a Gift Wrap requires **two keypairs**: the sender's real identity (for the Seal layer) and an ephemeral keypair (for the outer Gift Wrap). The Seal binds the message to the real sender; the Gift Wrap hides the real sender from relays.

Used for:
- `friendRequest` (no Signal session yet)
- `mlsGroupInvite` when no Signal session exists with the target

### 3.4 Four Types of Listening Addresses

A Keychat client listens on at most four types of receiving addresses simultaneously:

#### Type 1: Identity npub (permanent)

Your Nostr identity pubkey. Always listened on. Used for:
- **Incoming friend requests** — when someone sends you a `friendRequest`, it is delivered to your npub via NIP-17 Gift Wrap.
- **MLS group invitations from non-contacts** — when someone adds you to an MLS group but does not have a 1:1 Signal session with you, the `mlsGroupInvite` is sent to your npub via NIP-17.

#### Type 2: firstInbox (temporary, per outbound friend request)

When you send a friend request to someone, you generate a fresh `firstInbox` keypair and include the pubkey in the request. You listen on this address to receive the peer's response (approve or reject). 

**Not necessarily one-time**: after the peer sends their approval message, they may send several follow-up messages to the same `firstInbox` address before the ratchet-derived address takes over. The `firstInbox` is cleared once you receive a message on a ratchet-derived address, confirming the ratchet is active.

#### Type 3: Signal ratchet-derived addresses (dynamic, per peer)

The most commonly used receiving addresses. Derived from the Signal Double Ratchet state (see §9). 

**Lifecycle**: When Bob sends his approval of Alice's friend request, the ratchet initializes. Bob computes his first ratchet-derived receiving address and begins listening on it, ready for Alice's reply. When Alice decrypts Bob's approval, she derives Bob's ratchet receiving address (to send to) and also advances her own ratchet, producing her own receiving address. From this point on, all messages between Alice and Bob use ratchet-derived addresses that rotate with each direction change.

A sliding window of 2–3 addresses per peer is maintained (see §9.3).

#### Type 4: MLS-derived address (dynamic, per MLS group)

Used only for MLS large groups. Each member derives a shared receiving address (`mlsTempInbox`) from the MLS export secret. All members in the same epoch compute the same address. This address rotates after every MLS Commit (see §11.3).

#### Subscription Filter

Normal client:
```json
{
  "kinds": [1059],
  "#p": [
    "<npub>",
    "<firstInbox_1>", "<firstInbox_2>",
    "<ratchet_addr_peer1_a>", "<ratchet_addr_peer1_b>",
    "<ratchet_addr_peer2_a>", "<ratchet_addr_peer2_b>",
    "<mls_temp_inbox_group1>", "<mls_temp_inbox_group2>",
    ...
  ],
  "since": <unix_timestamp>
}
```

Public Agent (§3.6): only subscribes to its own npub:
```json
{
  "kinds": [1059],
  "#p": ["<agent_npub>"],
  "since": <unix_timestamp>
}
```

### 3.5 Receiver Routing

When a kind 1059 event arrives, the receiver determines the message type by matching the `p`-tag target address:

```
Received kind 1059 event:
  ├── p-tag matches room.mlsTempInbox?
  │     → MLS message (Mode 1), decrypt with MLS
  │
  ├── p-tag matches a Signal ratchet receiving address?
  │     → Signal message (Mode 1), decrypt with Signal Protocol
  │
  ├── Public Agent mode: event has dual p-tags (§3.6)?
  │     → Extract the non-npub p-tag as ratchet address
  │     → Match ratchet address to room → decrypt with Signal Protocol
  │
  └── Neither?
        → Try NIP-17 Gift Wrap unwrap (Mode 2)
        → Parse KCMessage.kind to route (friendRequest, mlsGroupInvite, etc.)
```

### 3.6 Public Agent Routing

#### Problem

In normal Keychat operation, each peer's Signal ratchet produces unique receiving addresses that rotate on every direction change. The receiver must subscribe to all active ratchet addresses across all peers — typically a sliding window of 2–3 addresses per peer.

For a regular user with dozens of contacts, this is manageable. But a **public agent** — an agent that accepts friend requests from anyone and may serve thousands or tens of thousands of concurrent peers — faces a fundamentally different scaling challenge:

- **Subscription explosion**: With 10,000 peers × 2 addresses each = 20,000 addresses in the relay subscription filter. Nostr relays are not designed for filters of this magnitude; query performance degrades, and some relays impose filter size limits.
- **State management**: The agent must track, rotate, and garbage-collect addresses for every peer. A restart requires reconstructing the full subscription set from persistent state.
- **Relay reconnection**: On any relay reconnect, the agent must resubmit the entire address set. This becomes a bottleneck proportional to peer count.

The ratchet-derived address mechanism provides unlinkability — an observer cannot correlate messages from different peers to the same receiver. But a public agent's identity is already public by definition; there is no unlinkability to protect. The privacy cost of revealing the receiver's npub is zero.

#### Solution: Dual p-tag

When a sender knows the receiver is a public agent, it includes **two `p`-tags** in the kind 1059 event:

```
tags: [["p", <ratchet_derived_address>], ["p", <agent_npub>]]
```

- **First `p`-tag** (`ratchet_derived_address`): The standard ratchet-derived address for this peer. Used by the agent to **route the message to the correct room/session**. The ratchet continues to operate normally — addresses rotate, sliding windows are maintained — but they are used for routing only, not for relay subscription.
- **Second `p`-tag** (`agent_npub`): The agent's permanent Nostr identity pubkey. This is the **only address the agent subscribes to** on relays.

The agent's relay subscription reduces to O(1) regardless of peer count:

```json
{ "kinds": [1059], "#p": ["<agent_npub>"], "since": <timestamp> }
```

Upon receiving an event, the agent inspects the `p`-tags, ignores its own npub, and matches the remaining ratchet address to a room — exactly as it would in normal mode.

#### Signaling

A public agent declares its mode in the `friendApprove` message by including a `publicAgent` field:

```json
{
  "v": 2,
  "kind": "friendApprove",
  "friendApprove": {
    "requestId": "fr-uuid-001",
    "message": "Welcome!",
    "publicAgent": true
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `publicAgent` | `bool` | No | If `true`, the sender requests dual p-tag routing. Default: `false`. |

The receiving client MUST persist this flag on the room. All subsequent Mode 1 messages to this peer MUST include the dual `p`-tag.

#### Backward Compatibility

- **Old client → new agent**: The old client does not recognize `publicAgent`, ignores the field, and continues sending single `p`-tag messages. The agent MUST maintain a fallback subscription for ratchet addresses of peers that have not adopted dual `p`-tag. Over time, as clients upgrade, the fallback set shrinks to zero.
- **New client → old agent**: The new client sends dual `p`-tags. The relay delivers the event because it matches the ratchet address (which the old agent subscribes to). The extra `p`-tag is harmless — the old agent ignores it.
- **No protocol break**: Dual `p`-tag is purely additive. Clients that do not understand it work exactly as before.

#### Privacy Considerations

The second `p`-tag reveals the receiver's npub to relay operators and network observers. This is an acceptable trade-off because:

1. Public agents are discoverable by design — their npub is published for anyone to initiate contact.
2. The message content remains fully encrypted by Signal Protocol — only the receiver identity is exposed, not the sender or the payload.
3. Users communicating with each other (non-agent) continue to use single `p`-tag with full unlinkability.

This mode SHOULD NOT be used for 1:1 communication between regular users.

---

## 4. Message Format (KCMessage v2)

All structured messages use the KCMessage v2 envelope. This is the content that goes inside the encrypted payload (for Signal/MLS) or the NIP-17 Rumor (for Gift Wrap).

### 4.1 Envelope Structure

```json
{
  "v": 2,
  "id": "<uuid-v4>",
  "kind": "<KCMessageKind>",
  "<payload_field>": { ... },
  "groupId": "<group_pubkey>",
  "replyTo": { ... },
  "signalPrekeyAuth": { ... },
  "fallback": "<human-readable degraded text>",
  "threadId": "<root_message_id>",
  "forwardFrom": { ... },
  "burnAfterReading": true
}
```

### 4.2 Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | `int` | Yes | Protocol version. Must be `2`. |
| `kind` | `string` | Yes | Message type identifier (see §4.4). |
| `id` | `string?` | No | Message UUID v4. Required for group messages, taskRequest/taskResponse, friendRequest. Recommended for all messages. |
| `groupId` | `string?` | No | Group public key. Present for group messages, absent for 1:1. |
| `replyTo` | `ReplyTo?` | No | Reply reference (see §4.6). |
| `signalPrekeyAuth` | `SignalPrekeyAuth?` | No | Identity binding for PrekeyMessages (see §4.6). |
| `fallback` | `string?` | No | Human-readable text for clients that don't recognize the `kind`. |
| `threadId` | `string?` | No | Root message ID for thread/sub-conversation. |
| `forwardFrom` | `ForwardFrom?` | No | Original sender info for forwarded messages. |
| `burnAfterReading` | `bool?` | No | Self-destruct after reading. |

### 4.3 Design Principles

1. **Flat enum dispatch** — A single `kind` field routes all message types.
2. **Typed payloads** — Each `kind` has exactly one corresponding payload field.
3. **Protocol-agnostic** — The message body contains no encryption metadata (`MessageType c` from v1 is removed). Encryption and transport are handled externally.
4. **Versioned** — `v: 2` distinguishes the new format.
5. **Forward-compatible** — Unknown `kind` values degrade gracefully via the `fallback` field.
6. **Size limit** — Serialized KCMessage should not exceed 64KB. Larger content should be sent as `files` kind with encrypted upload.

### 4.4 KCMessageKind Enum

#### Naming Convention

| Scope | Prefix | Examples |
|-------|--------|----------|
| Universal (all protocols) | none | `text`, `files`, `cashu`, `location` |
| Message operations | `message` | `messageDelete`, `messageEdit` |
| Group-wide operations | `group` | `groupPinMessage`, `groupAnnouncement` |
| Signal 1:1 | none | `friendRequest`, `profileSync` |
| Signal Group (sendAll) | `signal` | `signalGroupInvite`, `signalGroupDissolve` |
| MLS Group | `mls` | `mlsGroupInvite` |
| Agent (interactive UI) | `agent` | `agentActions`, `agentOptions`, `agentConfirm` |
| Agent (protocol) | none | `taskRequest`, `skillQuery`, `eventNotify` |

#### Core Kinds

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `text` | `text` | Text message |
| `files` | `files` | Files, images, video, audio, voice |
| `cashu` | `cashu` | Ecash token transfer |
| `lightningInvoice` | `lightning` | Lightning invoice |

#### Signal 1:1 Kinds

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `friendRequest` | `friendRequest` | Friend request with PQXDH prekey bundle (via NIP-17) |
| `friendApprove` | `friendApprove` | Accept friend request (references request ID) |
| `friendReject` | `friendReject` | Reject friend request (references request ID) |
| `profileSync` | `profile` | Profile update |
| `relaySyncInvite` | `relaySync` | Relay sync invitation (local confirm, no reply sent) |

#### Signal Group Kinds

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `signalGroupInvite` | `signalGroupInvite` | Admin sends group invite with RoomProfile |
| `signalGroupMemberRemoved` | `signalGroupAdmin` | Admin removes member |
| `signalGroupSelfLeave` | `signalGroupAdmin` | Member leaves group |
| `signalGroupDissolve` | `signalGroupAdmin` | Admin dissolves group |
| `signalGroupNameChanged` | `signalGroupAdmin` | Admin renames group |
| `signalGroupNicknameChanged` | `signalGroupAdmin` | Member changes nickname |

#### MLS Group Kind

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `mlsGroupInvite` | `mlsGroupInvite` | MLS group invitation (via Signal or NIP-17) |

> **MLS management operations** (add/remove members, rename, dissolve, key update) are performed through MLS Commits at the protocol layer, not as KCMessage kinds. See §11.

#### Agent Kinds

| Kind | Payload Field | Category | Description |
|------|---------------|----------|-------------|
| `agentActions` | `agent` | Interactive | Action menu (like Telegram Bot commands) |
| `agentOptions` | `agent` | Interactive | Option list (single or multi-select) |
| `agentConfirm` | `agent` | Interactive | Confirmation dialog |
| `agentReply` | `agent` | Interactive | User reply to any agent interactive |
| `taskRequest` | `taskRequest` | Protocol | Task delegation request |
| `taskResponse` | `taskResponse` | Protocol | Task execution result |
| `skillQuery` | none | Protocol | Capability discovery (empty payload) |
| `skillDeclare` | `skillDeclare` | Protocol | Capability declaration |
| `eventNotify` | `eventNotify` | Protocol | One-way event notification |
| `streamChunk` | `streamChunk` | Protocol | Streaming intermediate output |

#### Additional Kinds

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `reaction` | `reaction` | Add/remove emoji reaction |
| `messageDelete` | `messageDelete` | Delete/retract a message |
| `messageEdit` | `messageEdit` | Edit a sent message |
| `readReceipt` | `readReceipt` | Read receipt |
| `typing` | none | Typing indicator (ephemeral, not persisted) |
| `location` | `location` | Location sharing |
| `contact` | `contact` | Contact card sharing |
| `sticker` | `sticker` | Sticker/emoji pack |
| `poll` | `poll` | Create a poll |
| `pollVote` | `pollVote` | Vote on a poll |
| `callSignal` | `callSignal` | Call signaling (offer/answer/reject/end/ICE) |
| `groupPinMessage` | `groupPinMessage` | Pin/unpin a group message |
| `groupAnnouncement` | `groupAnnouncement` | Group announcement |

### 4.5 Core Payload Definitions

#### KCTextPayload

```json
{
  "v": 2,
  "kind": "text",
  "text": {
    "content": "Hello, world!",
    "format": "plain"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | `string` | Yes | Message text |
| `format` | `string?` | No | `"plain"` (default) or `"markdown"`. Markdown rendering must prohibit raw HTML. |

#### KCFilesPayload

```json
{
  "v": 2,
  "kind": "files",
  "files": {
    "message": "Today's photos",
    "items": [
      {
        "category": "image",
        "url": "https://example.com/encrypted/abc123",
        "type": "image/jpeg",
        "suffix": "jpg",
        "size": 245760,
        "key": "aes256-key-hex",
        "iv": "iv-hex",
        "hash": "sha256-hex"
      }
    ]
  }
}
```

**KCFilesPayload**: `message` (optional text), `items` (list of KCFilePayload).

**KCFilePayload fields**: `category` (FileCategory enum), `url`, `type` (MIME), `suffix`, `size` (bytes), `key` (AES hex), `iv` (hex), `hash` (SHA256 hex), `sourceName`, `audioDuration` (seconds), `amplitudeSamples` (waveform), `ecashToken`.

**FileCategory enum**: `image`, `video`, `voice`, `audio`, `document`, `text`, `archive`, `other`.

#### KCFriendRequestPayload

The prekey bundle for establishing a Signal session with PQXDH. Sent via NIP-17 Gift Wrap (Mode 2).

```json
{
  "v": 2,
  "id": "fr-uuid-001",
  "kind": "friendRequest",
  "friendRequest": {
    "message": "Hi, I'm Alice. Let's start an encrypted chat.",
    "name": "Alice",
    "nostrIdentityKey": "abc123...",
    "signalIdentityKey": "05def456...",
    "firstInbox": "ephemeral-nostr-pubkey-hex",
    "deviceId": "device-uuid",
    "signalSignedPrekeyId": 1,
    "signalSignedPrekey": "hex...",
    "signalSignedPrekeySignature": "hex...",
    "signalOneTimePrekeyId": 1,
    "signalOneTimePrekey": "hex...",
    "signalKyberPrekeyId": 1,
    "signalKyberPrekey": "hex...",
    "signalKyberPrekeySignature": "hex...",
    "globalSign": "schnorr-sig-hex",
    "time": 1700000000,
    "version": 2
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | `string?` | No | Optional greeting |
| `name` | `string` | Yes | Display name |
| `nostrIdentityKey` | `string` | Yes | Sender's Nostr secp256k1 pubkey (hex) |
| `signalIdentityKey` | `string` | Yes | Sender's Signal Curve25519 identity pubkey (hex, 33 bytes) |
| `firstInbox` | `string` | Yes | Ephemeral Nostr pubkey for first-message delivery (not a Signal key) |
| `deviceId` | `string` | Yes | Device ID for multi-device disambiguation |
| `signalSignedPrekeyId` | `int` | Yes | Signed prekey ID |
| `signalSignedPrekey` | `string` | Yes | Signed prekey (Curve25519, hex) |
| `signalSignedPrekeySignature` | `string` | Yes | XEdDSA signature over the signed prekey |
| `signalOneTimePrekeyId` | `int` | Yes | One-time prekey ID |
| `signalOneTimePrekey` | `string` | Yes | One-time prekey (Curve25519, hex) |
| `signalKyberPrekeyId` | `int` | Yes | Kyber KEM prekey ID |
| `signalKyberPrekey` | `string` | Yes | Kyber KEM public key (ML-KEM 1024, hex) |
| `signalKyberPrekeySignature` | `string` | Yes | XEdDSA signature over the Kyber prekey |
| `globalSign` | `string` | Yes | Schnorr signature: `sign("Keychat-{nostrIdentityKey}-{signalIdentityKey}-{time}")` |
| `time` | `int?` | No | Unix timestamp |
| `version` | `int` | Yes | Protocol version, must be `2` |
| `relay` | `string?` | No | Preferred relay URL |
| `avatar` | `string?` | No | Avatar URL |
| `lightning` | `string?` | No | Lightning address |

> **v1 → v2 field mapping**: `pubkey` → `nostrIdentityKey`, `curve25519PkHex` → `signalIdentityKey`, `onetimekey` → `firstInbox`, `prekeyId`/`prekeyPubkey` → `signalOneTimePrekeyId`/`signalOneTimePrekey`. The Kyber fields are new in v2.

#### KCFriendApprovePayload / KCFriendRejectPayload

```json
{ "requestId": "fr-uuid-001", "message": "Nice to meet you!", "publicAgent": true }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `requestId` | `string` | Yes | The `KCMessage.id` of the original friendRequest |
| `message` | `string?` | No | Optional text |
| `publicAgent` | `bool?` | No | If `true`, receiver is a public agent — sender should use dual `p`-tag routing (§3.6). Default: `false`. |

#### KCCashuPayload

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint` | `string` | Yes | Cashu mint URL |
| `token` | `string` | Yes | Cashu token string |
| `amount` | `int` | Yes | Amount in satoshis |
| `unit` | `string?` | No | Currency unit |
| `memo` | `string?` | No | Memo |
| `message` | `string?` | No | Optional text |

#### KCLightningPayload

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `invoice` | `string` | Yes | BOLT-11 Lightning invoice |
| `amount` | `int` | Yes | Amount in satoshis |
| `mint` | `string?` | No | Associated Cashu mint URL |
| `hash` | `string?` | No | Payment hash (hex) |
| `message` | `string?` | No | Optional text |

### 4.6 Envelope Metadata Fields

#### ReplyTo

References another message as a reply. Uses dual-ID lookup for cross-member compatibility in groups.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targetId` | `string?` | No | The `KCMessage.id` of the replied-to message (reliable across group members) |
| `targetEventId` | `string?` | No | The Nostr event ID (local fallback) |
| `content` | `string` | Yes | Quoted content preview |
| `userId` | `string?` | No | Original author's pubkey |
| `userName` | `string?` | No | Original author's display name |

**Lookup order**: Try `targetId` first, fall back to `targetEventId`.

**Why dual IDs**: In Signal Groups, the same message produces different Nostr event IDs for each member (per-member encryption), but shares the same `KCMessage.id`.

#### SignalPrekeyAuth

Identity binding carried on the first Signal PrekeyMessage after session establishment. This is a standalone type — **not** the same as KCFriendRequestPayload (which carries the full prekey bundle for key exchange).

| Field | Type | Description |
|-------|------|-------------|
| `nostrId` | `string` | Sender's secp256k1 Nostr pubkey |
| `signalId` | `string` | Sender's Curve25519 Signal pubkey |
| `time` | `int` | Unix timestamp (anti-replay) |
| `name` | `string` | Display name |
| `sig` | `string` | Schnorr signature over `"Keychat-{nostrId}-{signalId}-{time}"` |
| `avatar` | `string?` | Avatar URL |
| `lightning` | `string?` | Lightning address |

**Appears when**:
- Bob sends the first message after accepting a friend request (PrekeyMessage)
- Alice sends the first message after scanning a QR code (PrekeyMessage)
- After a session reset (new PrekeyMessage)

The receiver verifies the Schnorr signature and updates the locally stored peer profile.

#### threadId

Assigns a message to a sub-conversation. The root message is the one whose `KCMessage.id` equals the `threadId`. Threads are flat (all messages in a thread point to the root, not to the previous reply).

`threadId` and `replyTo` can coexist: `threadId` says which thread, `replyTo` says which message within the thread is being quoted.

#### ForwardFrom

Marks a message as forwarded. `senderName`, `senderId`, `originalTime` — all optional for anonymous forwarding.

### 4.7 Forward Compatibility

| Scenario | Behavior |
|----------|----------|
| Known `kind` | Parse normally, ignore `fallback` |
| Unknown `kind` + `fallback` present | Display `fallback` as plain text |
| Unknown `kind` + no `fallback` | Show default: "This message requires a newer version of Keychat" |

**Sender rule**: When using a `kind` not defined in the initial v2 spec, **should** populate `fallback`.

### 4.8 Version Negotiation

- **1:1**: `friendRequest.version` carries the sender's protocol version. Stored as `Room.peerVersion`.
- **Signal Group**: `RoomProfile` in the invite carries version info.
- **MLS Group**: `GroupExtension` includes a `version` field.

**Parsing logic**:
```
tryParseMessage(str):
  json = JSON.parse(str)
  if json.v == 2 → KCMessage.fromJson(json)
  else → null (treat as plain text)
```

---

## 5. Encryption Layer

### 5.1 Signal Protocol with PQXDH

Keychat's encryption layer is built on two established cryptographic libraries:

- **libsignal** — Signal's official Rust implementation of the Signal Protocol, providing PQXDH key agreement, Double Ratchet, and session management.
- **OpenMLS** — An open-source Rust implementation of the MLS (Messaging Layer Security) standard (RFC 9420), providing scalable group encryption.

The Keychat protocol implementation library, **libkeychat**, is built on top of these two libraries, adding the Nostr identity layer, relay transport, address rotation, and ecash stamp integration.

Keychat uses Signal Protocol for 1:1 and small group encryption, upgraded from X3DH to **PQXDH** (Post-Quantum Extended Diffie-Hellman) for the initial key agreement.

#### PQXDH Parameters

| Parameter | Value |
|-----------|-------|
| curve | Curve25519 |
| hash | SHA-512 |
| pqkem | ML-KEM 1024 (CRYSTALS-Kyber-1024) |
| info | "Keychat" |

#### What PQXDH Changes

PQXDH extends X3DH by adding a post-quantum KEM (Key Encapsulation Mechanism) to the initial handshake. The prekey bundle now includes a **Kyber KEM public key** in addition to the Curve25519 keys.

During session establishment:
1. Alice performs the standard ECDH calculations (DH1, DH2, DH3, optionally DH4)
2. Alice **also** encapsulates a shared secret using Bob's Kyber public key: `(CT, SS) = PQKEM-ENC(KyberPrekey)`
3. The final session key combines both: `SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)`
4. Alice sends the KEM ciphertext `CT` along with her initial message

This provides **hybrid security**: the session is protected if either the classical (ECDH) or post-quantum (Kyber) assumption holds. A quantum computer must break both to compromise the session key.

#### After PQXDH

Once the session is established, the Double Ratchet operates identically to standard Signal Protocol. The post-quantum protection applies to the initial key agreement; ongoing ratchet steps use Curve25519 ECDH. Future Signal Protocol revisions may add post-quantum ratcheting.

### 5.2 MLS (Messaging Layer Security)

Large groups use MLS (RFC 9420) for scalable group encryption with a ratchet tree structure. See §11 for details.

### 5.3 NIP-17 Gift Wrap

Used when no encrypted session exists (friend requests). Provides NIP-44 encryption with metadata protection. See §3.3 Mode 2.

---

## 6. Adding a Contact (Friend Request)

Alice wants to add Bob. She only knows Bob's npub.

### 6.1 Prerequisites

- Alice's Nostr identity (secp256k1 keypair)
- Bob's Nostr pubkey (hex) or npub

#### Public Key Format Normalization

All public API entry points that accept a Nostr public key **MUST** accept both formats:
- **npub** (bech32, e.g., `npub1cqpv...558u`)
- **hex** (64 chars, e.g., `c002c688...d033`)

Implementations MUST normalize to hex internally. This applies to:
- Adding contacts (friend request target)
- Group invitations (invitee identity)
- Any user-facing API that accepts a peer identifier

### 6.2 Step-by-Step

```
1. Generate a Signal identity for this peer:
   (signal_private, signal_public) = generate_signal_ids()
   signalIdentityKey = hex(signal_public)  // 33 bytes → 66 hex chars

2. Generate a signed prekey:
   (signedId, signedPublic, signedSignature, signedRecord) =
     generate_signed_key(signal_private)

3. Generate a one-time prekey:
   (prekeyId, prekeyPublic, prekeyRecord) = generate_prekey()

4. Generate a Kyber KEM prekey (PQXDH):
   (kyberPrekeyId, kyberPublic, kyberSignature, kyberRecord) =
     generate_kyber_prekey(signal_private)

5. Generate firstInbox (ephemeral Nostr keypair for first-message receiving):
   firstInbox_pair = generate_secp256k1()
   firstInbox = firstInbox_pair.pubkey  // hex

6. Build KCFriendRequestPayload:
   {
     "name": "<alice_display_name>",
     "nostrIdentityKey": "<alice_nostr_pubkey_hex>",
     "signalIdentityKey": "<signal_public_hex>",
     "firstInbox": "<firstInbox_pubkey_hex>",
     "deviceId": "<device_uuid>",
     "signalSignedPrekeyId": <signedId>,
     "signalSignedPrekey": "<hex(signedPublic)>",
     "signalSignedPrekeySignature": "<hex(signedSignature)>",
     "signalOneTimePrekeyId": <prekeyId>,
     "signalOneTimePrekey": "<hex(prekeyPublic)>",
     "signalKyberPrekeyId": <kyberPrekeyId>,
     "signalKyberPrekey": "<hex(kyberPublic)>",
     "signalKyberPrekeySignature": "<hex(kyberSignature)>",
     "globalSign": "<schnorr_sig>",
     "time": <unix_timestamp>,
     "version": 2
   }

7. Compute globalSign (Schnorr signature):
   message = "Keychat-<nostrIdentityKey>-<signalIdentityKey>-<time>"
   globalSign = schnorr_sign(alice_nostr_private_key, sha256(message))

8. Build KCMessage:
   {
     "v": 2,
     "id": "<uuid-v4>",
     "kind": "friendRequest",
     "friendRequest": <payload_from_step_6>
   }

9. Send as NIP-17 Gift Wrap (kind:1059, Mode 2):
   ephemeral_wrapper = generate_ephemeral_keypair()  // random, for outer Gift Wrap
   gift_wrap = create_gift_wrap(
     wrapper_keys = ephemeral_wrapper,        // outer layer: hides Alice
     sender_keys = alice_nostr_keypair,       // Seal layer: proves Alice's identity
     receiver_pubkey = bob_nostr_pubkey,
     content = kcmessage_json,
     timestamp_tweaked = false
   )
   publish to relay
   // Outer Gift Wrap pubkey = ephemeral (anonymous)
   // Seal pubkey = Alice's real identity (encrypted, only Bob can see)

   // All Keychat kind 1059 events use real timestamps — no tweaking.

10. Start listening on:
    - alice_nostr_pubkey (always)
    - firstInbox (for Bob's first reply)
```

### 6.3 Critical: Post-Hello Listening Addresses

After sending a friend request, Alice **must** subscribe to these addresses for kind 1059 events:

1. **firstInbox** — Bob's first reply (approval/rejection and possibly follow-up messages) will be sent here
2. **Ratchet-derived addresses** — Once the ratchet activates, subsequent messages arrive on derived addresses (§9)

If Alice fails to listen on `firstInbox`, she will miss Bob's response entirely.

---

## 7. Accepting a Friend Request

Bob receives a kind 1059 event addressed to his pubkey.

### 7.1 Unwrap Gift Wrap

```
1. Decrypt kind:1059 content with NIP-44 using bob_private_key + event.pubkey
   → seal_json (kind 13)

2. Verify seal event signature

3. Decrypt seal content with NIP-44 using bob_private_key + seal.pubkey
   → rumor_json (kind 14, unsigned)

4. Parse rumor.content as KCMessage
   Check v == 2 and kind == "friendRequest"

5. Extract friendRequest payload
```

### 7.2 Verify Identity

```
message = "Keychat-<friendRequest.nostrIdentityKey>-<friendRequest.signalIdentityKey>-<friendRequest.time>"
verify_schnorr(friendRequest.nostrIdentityKey, friendRequest.globalSign, sha256(message))
```

If verification fails, abort.

### 7.3 Establish Signal Session (PQXDH)

```
process_prekey_bundle(
  my_keypair = bob_signal_keypair,
  remote_address = {
    name: friendRequest.signalIdentityKey,
    device_id: bob_identity_id
  },
  identity_key = friendRequest.signalIdentityKey,
  signed_prekey_id = friendRequest.signalSignedPrekeyId,
  signed_prekey = friendRequest.signalSignedPrekey,
  signed_prekey_signature = friendRequest.signalSignedPrekeySignature,
  one_time_prekey_id = friendRequest.signalOneTimePrekeyId,
  one_time_prekey = friendRequest.signalOneTimePrekey,
  kyber_prekey_id = friendRequest.signalKyberPrekeyId,
  kyber_prekey = friendRequest.signalKyberPrekey,
  kyber_prekey_signature = friendRequest.signalKyberPrekeySignature
)
```

The PQXDH handshake internally:
1. Performs ECDH calculations with Alice's Curve25519 keys
2. Encapsulates a shared secret using Alice's Kyber public key
3. Combines both via HKDF to derive the session key

### 7.4 Auto-Reply (If Approved)

If Bob accepts, he sends a `friendApprove` message via Signal encryption. This is the first Signal message from Bob to Alice — a **PrekeyMessage** (ratchet just initialized).

The reply is sent to Alice's **firstInbox** address.

```json
{
  "v": 2,
  "kind": "friendApprove",
  "friendApprove": {
    "requestId": "<original_friendRequest.id>"
  },
  "signalPrekeyAuth": {
    "nostrId": "<bob_nostr_pubkey>",
    "signalId": "<bob_signal_pubkey>",
    "name": "Bob",
    "time": 1700000000,
    "sig": "<schnorr_signature>"
  }
}
```

**One message, three functions**: friend approval + identity binding + Signal session establishment.

---

## 8. Signal-Encrypted 1:1 Chat

Once a Signal session is established, all messages use kind 1059 events (Mode 1) with Signal Protocol encryption.

### 8.1 Sending a Message

```
1. Construct KCMessage:
   { "v": 2, "kind": "text", "text": { "content": "Hello Bob!" } }

2. Determine the sending address (where to deliver):
   session = get_session(my_keypair, peer_signal_pubkey, device_id)
   bob_address = session.bobAddress

   if bob_address starts with "05" (raw Signal identity key, ratchet not yet established):
     if room.peerFirstInbox exists → to_address = peerFirstInbox
     else → to_address = peer_nostr_pubkey
   else:
     to_address = derive_nostr_address(bob_address)

3. Encrypt with Signal:
   (ciphertext, new_receiving_addr, msg_key_hash, alice_addrs) =
     encrypt_signal(my_keypair, kcmessage_json, remote_address)

4. If new_receiving_addr is returned:
   derived_pubkey = derive_nostr_address(new_receiving_addr)
   Subscribe to this address on relay (it is MY new receiving address)
   Store in DB

5. Generate ephemeral sender keypair:
   sender = generate_ephemeral_keypair()  // random, use-once

6. Build kind 1059 event:
   {
     "kind": 1059,
     "pubkey": sender.pubkey,           // EPHEMERAL, not my real pubkey
     "content": base64_encode(ciphertext),
     "tags": [["p", to_address]],
     "created_at": unix_now(),          // real timestamp, not tweaked
     "id": compute_event_id(...),
     "sig": sign(sender.privkey, ...)
   }

7. Publish to relay
```

### 8.2 Receiving a Message

```
1. Event arrives on one of my listening addresses (kind 1059, Mode 1)

2. Decode: ciphertext = base64_decode(event.content)

3. Check if PrekeyMessage:
   is_prekey = PreKeySignalMessage::try_from(ciphertext).is_ok()

   ⚠️ Do NOT use ciphertext[0] == 3 for detection. Signal messages
   are protobuf-encoded; the first byte is a field tag, not a type indicator.

4. If PrekeyMessage:
   (signal_identity, signed_prekey_id) =
     parse_identity_from_prekey_signal_message(ciphertext)
   Use signed_prekey_id to find which of your Signal identities this is for
   Decrypt with is_prekey=true
   Parse signalPrekeyAuth from the decrypted KCMessage, verify signature

5. If normal message:
   Decrypt with is_prekey=false

6. After decrypt, update sending address for this peer:
   The session's bobAddress now points to the peer's new receiving address.
   Use this updated address next time you send (see step 2 above).

7. Parse decrypted plaintext:
   Try JSON parse as KCMessage (check v == 2) → route by kind
   If not valid KCMessage JSON → treat as plain text
```

### 8.3 When to Use firstInbox

`firstInbox` is a temporary receiving address, not necessarily one-time. The peer may send multiple messages to it (approval + follow-up messages) before ratchet addresses take over.

```
send_hello:
  → peerFirstInbox = alice.firstInbox (from friendRequest)

peer sends approval + possibly more messages → all go to firstInbox

receive_first_message on a ratchet-derived address:
  → clear peerFirstInbox (ratchet is now active)
  → ratchet addresses handle all subsequent routing
```

---

## 9. Receiving Address Rotation

This is Keychat's most distinctive feature. Each DH ratchet step generates a new Nostr receiving address, providing **message unlinkability**.

### 9.1 Address Derivation

The Signal Double Ratchet exchanges DH public keys. Keychat derives a Nostr secp256k1 pubkey from each ratchet key pair:

```
Input:
  private_key: Curve25519 private key (32 bytes)
  public_key:  Curve25519 public key (33 bytes)

1. ECDH:   shared_secret = private_key.calculate_agreement(public_key)

2. Pad:    seed = [0xFF; 32] || shared_secret

3. Hash:   hash = SHA256(seed)[0..32]  // first 32 bytes

4. Derive: secret_key = secp256k1_secret_key(hash)

5. Result: nostr_address = x_only_public_key(secret_key).hex()
```

This is a cross-curve one-way mapping: Curve25519 ratchet state → secp256k1 Nostr address.

### 9.2 When Addresses Rotate

- **After encrypt**: `new_receiving_addr` is YOUR new address. Subscribe to it on the relay.
- **After decrypt**: `session.bobAddress` updates to the PEER's new address. Use it as the destination next time.
- **Rotation is directional**: Sending 5 messages in a row does not rotate the address. The DH ratchet only advances on **direction change** (receive then send, or vice versa).

### 9.3 Sliding Window

Maintain a sliding window of receiving addresses per peer (recommended: 2–3):

```
addresses = [addr_n-1, addr_n]  // listen on both
// When addr_n+1 arrives → drop addr_n-1, add addr_n+1
```

Old addresses are removed from relay subscriptions. This bounds the number of addresses per peer while tolerating minor message reordering.

### 9.4 Sender Address Resolution

When sending, resolve the target address in this priority order:

```
1. session.bobAddress exists and is NOT a raw Signal identity key (0x05 prefix, 66 chars)?
   → derive_nostr_address(bobAddress) = delivery target

2. bobAddress is raw Signal identity key or missing?
   → room.peerFirstInbox exists? Use it (first message to peer)
   → else: room.toMainPubkey (peer's Nostr identity pubkey)
```

When using `peerFirstInbox`, the message will be a PrekeyMessage with `signalPrekeyAuth`.

### 9.5 Lifecycle Example

```
Alice                                              Bob
  |                                                  |
  |-- friendRequest (NIP-17 → Bob's npub) ---------> |
  |                                                  |
  | <-- friendApprove (Signal PrekeyMsg → firstInbox) |
  |    [Bob ratchet initialized, registers recvAddr_B1]
  |                                                  |
  |-- msg1 (→ recvAddr_B1) --------------------------> |
  |    [Alice ratchet steps, registers recvAddr_A1]  |
  |    [Alice clears peerFirstInbox]                 |
  |                                                  |
  | <-------------------------------- msg2 (→ recvAddr_A1)
  |                              [Bob ratchet steps] |
  |                              [Bob registers recvAddr_B2]
  |                              [Bob drops recvAddr_B1]
  |                                                  |
  |-- msg3 (→ recvAddr_B2) --------------------------> |
  |    ...                                           |
```

---

## 10. Signal Group (sendAll)

Small groups (recommended < 50 members) use Signal Protocol with per-member encryption.

### 10.1 How It Works

There is no shared group key. Instead, the sender encrypts each message individually for every group member using their respective 1:1 Signal sessions:

```
Sender constructs KCMessage:
  { "v": 2, "id": "msg-uuid", "kind": "text", "groupId": "group-pubkey", "text": {...} }

For each member (parallel):
  encrypt_signal(member_session, kcmessage_json)
  → publish as kind 1059 to member's receiving address
```

All members receive the same `KCMessage.id`, enabling deduplication and consistent reply references.

### 10.2 Sender Authentication

Signal Protocol inherently authenticates the sender — each member decrypts via their known 1:1 session. No additional application-layer signature is needed.

Admin operations (`signalGroupMemberRemoved`, `signalGroupDissolve`, etc.) are verified by checking `RoomMember.isAdmin` for the sender.

### 10.3 Group Management

| Operation | KCMessage Kind |
|-----------|---------------|
| Invite | `signalGroupInvite` (contains RoomProfile with member list) |
| Remove member | `signalGroupMemberRemoved` |
| Member leaves | `signalGroupSelfLeave` |
| Dissolve | `signalGroupDissolve` |
| Rename | `signalGroupNameChanged` |
| Change nickname | `signalGroupNicknameChanged` |

---

## 11. MLS Group

Large groups use MLS (RFC 9420) for scalable encryption.

### 11.1 Key Concepts

- **Ratchet Tree**: Tree-based key derivation. Members hold leaf secrets; the root derives the group encryption key.
- **Epoch**: Each Commit advances the epoch, rotating the group key.
- **KeyPackage**: A member's public key bundle, published as a kind 10443 Nostr event.
- **Welcome**: Invitation data for a new member to join the group.
- **Signer (SignatureKeyPair)**: A long-lived Ed25519 keypair used to sign leaf nodes and Commits. Unlike session keys, it must survive restarts: if a member rotates their signer, existing group state becomes unrecoverable (leaf signatures no longer verify). See §11.2 for persistence requirements.

### 11.2 Signer Persistence

Each identity owns exactly one MLS signer (Ed25519 SignatureKeyPair). The signer is bound to the identity via the MLS BasicCredential, which carries the Nostr pubkey as its identity field:

```
BasicCredential.identity = nostrId (hex pubkey)
CredentialWithKey = { credential, signature_key = signer.public_key }
```

**Persistence requirements:**

- The signer MUST be persisted keyed by `nostrId`, not as a global value.
- Multiple identities on the same device each have their own signer; storing a single global signer will break the credential-to-key binding for all but one identity.
- On process start for a given identity:
  1. Look up the signer by `nostrId`
  2. If found → restore it
  3. If not found → generate a fresh SignatureKeyPair and persist it under `nostrId`

**Storage format** (implementation-specific but conceptually):

```
Table: keychat_mls_identity
  nostr_id    PRIMARY KEY  -- hex pubkey
  signer      BLOB         -- serialized Ed25519 SignatureKeyPair
```

The table should reside in the same database as OpenMLS group state so that signer and ratchet tree state are always consistent on disk.

### 11.3 Receiving Address (mlsTempInbox)

Each MLS group member computes a shared receiving address from the MLS export
secret. MLS `exportSecret` already domain-separates by `(group_id, epoch, label)`,
so the 32-byte output is interpreted **directly** as a secp256k1 secret key — no
additional hashing is needed.

```
deriveMlsTempInbox(groupId):
  export_secret = MLS.exportSecret(
    groupId,
    label   = "keychat-mls-inbox",
    context = <empty>,
    length  = 32
  )
  sk           = secp256k1_secret_key(export_secret)   // interpret 32 bytes as SK
  mlsTempInbox = x_only_public_key(sk).hex()           // 64 hex chars
```

All members in the same epoch derive the same `mlsTempInbox`. The derivation
does **not** depend on `nostrId`.

```
replaceListenPubkey(room):
  new_inbox = deriveMlsTempInbox(room.groupId)
  if new_inbox == room.mlsTempInbox → no change
  else:
    unsubscribe(old mlsTempInbox)
    room.mlsTempInbox = new_inbox
    subscribe(new_inbox)
```

This address **rotates after every Commit** (add/remove member, key update, etc.). After processing a Commit, all members must call `replaceListenPubkey()`.

### 11.4 Joining a Group

**Prerequisite**: Every user who wishes to be added to an MLS group MUST first publish their KeyPackage to relays as a kind 10443 event. The admin fetches each invitee's KeyPackage via an author-filtered subscription on kind 10443 before calling `addMembers`.

```
Admin                                          New Member
  |                                                |
  |                                                +-- publish KeyPackage (kind 10443)
  | <-- fetch kind 10443 by author ----------------|
  +-- mls.addMembers(keyPackages)                  |
  +-- mls.selfCommit()                             |
  +-- replaceListenPubkey()                        |
  +-- broadcast Commit (kind 1059, Mode 1)         |
  +-- send mlsGroupInvite (Signal or NIP-17) ----> |
  |                                                +-- mls.joinMlsGroup(welcome)
  |                                                +-- replaceListenPubkey()
  |                                                +-- send greeting (selfUpdate Commit)
  | <-- selfUpdate Commit (kind 1059) -------------|
  +-- process update, replaceListenPubkey()        |
```

### 11.5 Sending Messages

```
1. Construct KCMessage:
   { "v": 2, "kind": "text", "groupId": "...", "text": {...} }

2. Encrypt: mls.createMessage(nostrId, groupId, kcmessage_json)

3. Generate ephemeral sender keypair

4. Publish kind 1059 to room.mlsTempInbox (Mode 1)
```

### 11.6 MLS vs. KCMessage for Management

MLS has native management via Commits. These are **not** expressed as KCMessage kinds:

| Operation | Mechanism | Transport |
|-----------|-----------|-----------|
| Add member | `mls.addMembers()` → Commit + Welcome | Commit: broadcast (kind 1059); Welcome: via `mlsGroupInvite` |
| Remove member | `mls.removeMembers()` → Commit | kind 1059 |
| Self leave | `mls.selfUpdate(status: "removed")` → Commit | kind 1059 |
| Dissolve | `mls.updateGroupContextExtensions(status: "dissolved")` → Commit | kind 1059 |
| Rename | `mls.updateGroupContextExtensions(name: ...)` → Commit | kind 1059 |
| Key update | `mls.selfUpdate()` → Commit | kind 1059 |

---

## 12. Media & File Transfer

### 12.1 Upload

Files are encrypted client-side and uploaded to a file server (S3-compatible or Blossom):

```
1. Generate random AES-256 key + IV
2. Encrypt file with AES-256-CTR + PKCS7 padding
3. Compute SHA256 hash of encrypted file
4. Upload to file server → receive access URL
5. Send KCMessage kind "files" with url, key, iv, hash
```

The receiver downloads the encrypted file and decrypts locally.

### 12.2 Message Format

```json
{
  "v": 2,
  "kind": "files",
  "files": {
    "items": [{
      "category": "image",
      "url": "https://files.example.com/abc123",
      "type": "image/jpeg",
      "size": 245760,
      "key": "<aes-key-hex>",
      "iv": "<iv-hex>",
      "hash": "<sha256-hex>"
    }]
  }
}
```

### 12.3 Voice Messages

Voice recordings use `category: "voice"` with additional fields:
- `audioDuration`: Duration in seconds
- `amplitudeSamples`: Waveform data for inline rendering

---

## 13. Ecash Stamps

Keychat uses Cashu ecash as anti-spam "postage stamps" for message delivery.

### 13.1 How It Works

```
1. Sender obtains a Cashu ecash token from a mint
2. Sender appends the token as a third element to the Nostr EVENT message:
   ["EVENT", <event_json>, <ecash_token_string>]
   (This is a Keychat relay protocol extension — standard NIP-01 only has two elements)
3. Relay receives the event, redeems the ecash stamp
4. Relay stores and broadcasts the standard Nostr event (without the token)
```

The ecash stamp is transparent to the receiver — only the relay sees and collects it. This provides economic anti-spam without requiring accounts or identity.

### 13.2 Token Format

The `<ecash_token_string>` is a Cashu token (base64 string starting with `cashuA`).

---

## 14. Cryptographic Primitives Reference

### 14.1 Key Types

| Key | Curve / Algorithm | Size | Usage |
|-----|-------------------|------|-------|
| Nostr identity | secp256k1 | 32 bytes private, 32 bytes x-only public | Identity, signing, NIP-44 |
| Signal identity | Curve25519 | 32 bytes private, 33 bytes public | Signal session identity |
| Signed prekey | Curve25519 | 33 bytes public | PQXDH handshake |
| One-time prekey | Curve25519 | 33 bytes public | PQXDH handshake (single use) |
| Kyber prekey | ML-KEM 1024 | ~1568 bytes public | PQXDH post-quantum KEM |
| firstInbox | secp256k1 | 32 bytes x-only public | Temporary Nostr receive address |
| Ratchet-derived address | secp256k1 | 32 bytes x-only public | Per-message Nostr receive address |

### 14.2 Encryption Algorithms

| Algorithm | Usage |
|-----------|-------|
| **NIP-44** (XChaCha20 + HMAC-SHA256) | Gift Wrap encryption |
| **Signal Protocol** (PQXDH + Double Ratchet, AES-256-CBC + HMAC-SHA256) | 1:1 and small group encryption |
| **ML-KEM 1024** (CRYSTALS-Kyber) | Post-quantum key encapsulation in PQXDH |
| **MLS** (TreeKEM + AEAD) | Large group encryption |
| **AES-256-CTR** | Media file encryption |

### 14.3 Signatures

| Algorithm | Usage |
|-----------|-------|
| **Schnorr** (BIP-340) | `globalSign` in friendRequest, `sig` in SignalPrekeyAuth |
| **XEdDSA** | Signal prekey signatures (signed prekey, Kyber prekey) |
| **Ed25519** | Nostr event signatures |

### 14.4 PQXDH Key Agreement

```
Alice (initiator)                         Bob (responder)

Has: IK_A (identity)                      Has: IK_B (identity)
Generates: EK_A (ephemeral)               Published: SPK_B (signed prekey)
                                                     OPK_B (one-time prekey, optional)
                                                     PQPK_B (Kyber prekey)

Alice computes:
  DH1 = DH(IK_A, SPK_B)
  DH2 = DH(EK_A, IK_B)
  DH3 = DH(EK_A, SPK_B)
  DH4 = DH(EK_A, OPK_B)                  // if OPK_B available
  (CT, SS) = PQKEM-ENC(PQPK_B)           // Kyber encapsulation

  SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)

Alice sends to Bob:
  - IK_A, EK_A, CT
  - Key identifiers (which prekeys were used)
  - Initial ciphertext (encrypted with SK)

Bob computes:
  Same DH values using his private keys
  SS = PQKEM-DEC(PQPK_B, CT)             // Kyber decapsulation
  SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)
```

### 14.5 Ratchet Address Derivation

```
derive_receiving_address(private_key: [u8; 32], public_key: [u8; 33]) -> String:
  // Input: Curve25519 ratchet private key + peer's ratchet public key
  dh   = private_key.calculate_agreement(public_key)
  seed = [0xFF; 32] || dh
  hash = SHA256(seed)[0..32]
  sk   = secp256k1_secret_key(hash)
  return x_only_public_key(sk).hex()
```

---

## 15. Implementation Checklist

### Phase 1: Identity & Transport
- [ ] Generate/import Nostr identity from BIP-39 mnemonic
- [ ] Connect to Nostr relays via WebSocket
- [ ] Subscribe to events by pubkey filter (kind 1059)
- [ ] Publish events to relay (with optional ecash stamp)
- [ ] NIP-44 encrypt/decrypt (for Gift Wrap)
- [ ] NIP-17 three-layer wrap/unwrap (kind 1059 → seal → rumor)

### Phase 2: Friend Request (PQXDH)
- [ ] Generate Signal identity (Curve25519)
- [ ] Generate signed prekey + one-time prekey
- [ ] Generate Kyber KEM prekey (ML-KEM 1024)
- [ ] Build KCFriendRequestPayload with all fields
- [ ] Compute Schnorr `globalSign`
- [ ] Send friend request as NIP-17 Gift Wrap
- [ ] Listen on firstInbox + signalIdentityKey derived address

### Phase 3: Accept Friend Request
- [ ] Unwrap kind 1059 Gift Wrap (three-layer decryption)
- [ ] Parse KCMessage v2 `kind: "friendRequest"`
- [ ] Verify Schnorr `globalSign`
- [ ] Process PQXDH prekey bundle (EC + Kyber keys)
- [ ] Send `friendApprove` with `signalPrekeyAuth` (first PrekeyMessage)

### Phase 4: Signal Chat
- [ ] Encrypt messages with Signal Protocol
- [ ] Send as kind 1059 with ephemeral sender + base64 content
- [ ] Receive and decrypt kind 1059 messages (Mode 1)
- [ ] Detect PrekeyMessage via `PreKeySignalMessage::try_from()`
- [ ] Parse and verify `signalPrekeyAuth`
- [ ] KCMessage v2 parsing (v==2, kind-based routing)

### Phase 5: Address Rotation
- [ ] After encrypt: derive new receiving address, subscribe on relay
- [ ] After decrypt: update sending address from session.bobAddress
- [ ] Sliding window of receiving addresses (2–3 per peer)
- [ ] Clean up old addresses from subscriptions
- [ ] Clear peerFirstInbox after first ratchet exchange

### Phase 6: Groups
- [ ] Signal Group: per-member encrypt + send (sendAll)
- [ ] Signal Group: management kinds (invite, remove, leave, dissolve, rename)
- [ ] MLS: KeyPackage publish (kind 10443)
- [ ] MLS: Welcome processing (join group)
- [ ] MLS: Application message send/receive (kind 1059)
- [ ] MLS: Commit processing + mlsTempInbox rotation
- [ ] MLS: KeyPackage re-publish after joining

### Phase 7: Media & Payments
- [ ] File encryption (AES-256-CTR) + upload
- [ ] KCFilesPayload with encrypted metadata
- [ ] Voice message with waveform data
- [ ] Cashu ecash token send/receive
- [ ] Lightning invoice send/receive

### Phase 8: Robustness
- [ ] Persist Signal session state (ratchet keys survive restarts)
- [ ] Persist receiving/sending addresses in DB
- [ ] Event deduplication (track processed event IDs)
- [ ] Retry logic for relay publish failures
- [ ] Handle session reset (new friend request)
- [ ] Ecash stamp attachment for relay delivery

---

## Appendix A: Room Model

| Field | Type | Description |
|-------|------|-------------|
| `id` | `int` | Auto-increment primary key |
| `toMainPubkey` | `string` | Peer's Nostr pubkey (1:1) or group pubkey (group) |
| `identityId` | `int` | Owner's Nostr identity |
| `type` | `RoomType` | `common` (1:1) or `group` |
| `groupType` | `GroupType?` | `sendAll` (Signal Group), `mls` (MLS Group) |
| `status` | `RoomStatus` | Lifecycle state (see below) |
| `encryptMode` | `EncryptMode` | `signal`, `nip17`, `mls` |
| `peerFirstInbox` | `string?` | Peer's first-message receiving pubkey (cleared after ratchet exchange) |
| `mlsTempInbox` | `string?` | MLS group receiving pubkey (rotates per epoch) |
| `version` | `int` | Anti-replay timestamp / epoch tracker |
| `peerVersion` | `int?` | Peer's KCMessage protocol version |

### RoomStatus

| Value | Description |
|-------|-------------|
| `init` | Created, not yet active |
| `requesting` | Friend request sent, waiting for reply |
| `approving` | Friend request received, waiting for user approval |
| `enabled` | Active session established |
| `rejected` | Friend request rejected |
| `dissolved` | Group dissolved by admin |
| `removedFromGroup` | Removed from group by admin |

---

## Appendix B: v1 → v2 Migration Summary

| Aspect | v1 | v2 |
|--------|----|----|
| Message format | `{"c":"signal","type":100,"msg":"...","name":"..."}` | `{"v":2,"kind":"text","text":{"content":"..."}}` |
| Transport kinds | kind:4 (Signal), kind:1059 (NIP-17), kind:444 (MLS Welcome) | kind:1059 for everything |
| Key agreement | X3DH | PQXDH (X3DH + Kyber KEM) |
| Friend request field: identity | `curve25519PkHex` | `signalIdentityKey` |
| Friend request field: inbox | `onetimekey` | `firstInbox` |
| Friend request field: nostr key | `pubkey` | `nostrIdentityKey` |
| Identity binding | `PrekeyMessageModel` (embedded in `name` field) | `signalPrekeyAuth` (envelope metadata field) |
| Message types | Numeric (`type: 100, 101, 104, ...`) | String enum (`"text"`, `"friendRequest"`, ...) |
| Protocol indicator | `"c": "signal"` / `"nip04"` / `"group"` | Removed (handled externally) |

---

## Appendix C: Common Pitfalls

1. **All messages use kind 1059** — There is no kind:4 in v2. Signal messages, MLS messages, and NIP-17 Gift Wraps all use kind 1059. The receiver routes by matching the `p`-tag against known addresses.

2. **Mode 1 content is raw base64, not NIP-44** — For Signal/MLS messages, the kind 1059 event content is simply `base64(ciphertext)`. Do not apply NIP-44 encryption on top.

3. **Every message uses a random ephemeral sender** — Generate a fresh Nostr keypair for each outgoing event. Never publish from your real npub.

4. **PrekeyMessage detection: use `try_from()`, not byte inspection** — Signal messages are protobuf-encoded. `ciphertext[0]` is a field tag, not a type indicator.

5. **Signal identity must be per-peer** — Generate a new Curve25519 keypair for every contact. Sharing across peers causes routing conflicts.

6. **Listen on firstInbox after sending friend request** — The peer's first reply goes to your firstInbox. Missing this subscription means missing their response entirely.

7. **Never delete the Signal DB** — It contains ratchet state. Losing it permanently destroys all sessions.

8. **Address rotation is directional** — `new_receiving_addr` after encrypt is YOUR address. `bobAddress` after decrypt is the PEER's address. Don't mix them up.

9. **The DH ratchet only advances on direction change** — Sending multiple messages in a row does not rotate the address.

10. **PQXDH Kyber keys are required** — v2 mandates Kyber KEM prekeys in friend requests. Implementations must generate and process ML-KEM 1024 key material.

11. **All kind 1059 events use real timestamps** — Unlike standard NIP-17, Keychat does not use random timestamp offsets on any kind 1059 event (including Gift Wraps). Relays filter by `since` — tweaked timestamps may make events invisible.

12. **mlsTempInbox must rotate after every Commit** — Failing to call `replaceListenPubkey()` after processing an MLS Commit will cause the member to miss subsequent group messages.
