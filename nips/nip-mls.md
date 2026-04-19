# NIP-XX -- MLS Protocol over Nostr

`optional` `author:keychat`

## Abstract

This NIP defines a **binding** of the Messaging Layer Security (MLS) protocol (RFC 9420) to the Nostr network. It specifies how MLS roles, messages, and state transitions map to Nostr event kinds, relay-based transport, and decentralized key distribution — enabling scalable end-to-end encrypted group messaging over a network of untrusted relays.

The focus of this document is not the MLS protocol itself (for which readers are referred to RFC 9420), but the unique challenges and design decisions that arise from running MLS on a decentralized, permissionless relay network where no single node can be trusted for message ordering, delivery guarantees, or directory services.

## Motivation

Private group communication over Nostr is currently served by NIP-17 combined with the Signal Protocol. While effective for small groups, this approach has fundamental scalability limitations: group state management (membership changes, key rotations) requires **O(N)** operations, as the sender must encrypt and distribute updates to each member individually. For groups with hundreds or thousands of members, this linear cost becomes prohibitive.

The Messaging Layer Security(MLS) protocol (RFC 9420) reduces the complexity of group operations to **O(log N)** through its TreeKEM ratchet tree structure, providing Forward Secrecy (FS) and Post-Compromise Security (PCS) efficiently at scale.

However, MLS was designed with the assumption of a semi-trusted infrastructure — a Delivery Service (DS) that reliably orders and forwards messages, and a Directory Service that faithfully hosts key material. Nostr provides neither guarantee. This NIP addresses the gap: how to realize MLS's security properties on a network where relays may drop, reorder, or selectively withhold messages.

## Specification

### Roles

- **Member:** A Nostr account (secp256k1 pubkey) participating in an MLS group. Each member maintains a local MLS group state including their position in the ratchet tree.
- **Admin:** A member with elevated privileges (stored in group context extensions). Admins can add/remove members and update group metadata. The creator is the initial admin.
- **Sender:** A member broadcasting MLS messages or group operations (Add/Remove/Update). For application messages, the sender uses a random one-time Nostr keypair to prevent metadata correlation.
- **Relay:** Acts as the **MLS Delivery Service (DS)**, storing and forwarding encrypted events. Relays are unaware of message content due to MLS encryption. Unlike a traditional MLS DS, Nostr relays provide **no ordering or delivery guarantees**.
- **Directory Service:** Implemented via `kind: 10443` Nostr events to host and serve `KeyPackages` for asynchronous group joining. Unlike a traditional MLS Directory Service, there is no central authority — KeyPackages are published by members and may be stored by any relay.

### Cryptographic Primitives

The implementation uses the following MLS ciphersuite:

```
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
```

This provides:
- **DHKEM(X25519):** Key encapsulation using Curve25519 Diffie-Hellman
- **AES-128-GCM:** Authenticated encryption with associated data (AEAD) for message content
- **SHA-256:** Hash function for tree hashing, key derivation, and transcript hashing
- **Ed25519:** Digital signatures for leaf nodes, credentials, and proposals

For details on how these primitives compose within MLS, see RFC 9420 Section 5 (Cryptographic Objects) and Section 13 (Ciphersuites).

The group's shared subscription address (`listen_key`, referred to as `mlsTempInbox` in implementations) is derived from the MLS `export_secret`:

```
export_secret = MLS_Export(group_state, label="nostr", context=b"nostr", length=32)
keypair = secp256k1_keypair_from(export_secret)
listen_key = x_only_pubkey(keypair)
```

MLS messages are already end-to-end encrypted by the MLS layer. They are published directly as `kind: 1059` events with `base64(mls_ciphertext)` as the content — no additional NIP-44 encryption is applied.

### Credential Binding

Each MLS leaf node uses a `BasicCredential` containing the member's **Nostr secp256k1 public key (hex)**. This binds MLS group membership to Nostr identity without requiring additional identity verification infrastructure.

### Group Context Extensions

Group metadata is stored in a custom MLS `GroupContextExtension` (type `0xF233`) with the following structure:

```
struct NostrGroupDataExtension {
    name: Vec<u8>,           // Group display name (UTF-8)
    description: Vec<u8>,    // Group description (UTF-8)
    admin_pubkeys: Vec<Vec<u8>>,  // List of admin Nostr pubkeys
    relays: Vec<Vec<u8>>,    // List of designated relay URLs
    status: Vec<u8>,         // Group status: "enabled" | "dissolved"
}
```

This extension is included in the group context and is updated via `GroupContextExtensions` proposals. All members can read it; only admins SHOULD modify it.

> **Multi-admin support:** The `admin_pubkeys` field is a list, enabling multiple admins in principle. However, the governance model for multi-admin groups (e.g., consensus requirements for membership changes, admin promotion/demotion policies) is left for future discussion and is not specified in this draft.

## Event Classification

### 1. KeyPackage Publication (`kind: 10443`)

KeyPackages enable asynchronous group joining. A member publishes their MLS KeyPackage so that group creators/admins can fetch it and add the member to a group without instant interaction.

**Event Structure:**

```json
{
  "kind": 10443,
  "pubkey": "<member's secp256k1 pubkey hex>",
  "content": "<hex-encoded TLS-serialized KeyPackage>",
  "created_at": <unix_timestamp>,
  "tags": [
    ["mls_protocol_version", "1.0"],
    ["ciphersuite", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
    ["extensions", "<extension info string>"],
    ["client", "<client name>"],
    ["relay", "<relay_url_1>", "<relay_url_2>", ...]
  ]
}
```

**Notes:**

- `kind: 10443` is a replaceable event, so each new publication replaces the previous one per relay.
- Clients SHOULD rotate KeyPackages periodically and validate expiration via the `lifetime` extension before use. However, on a decentralized network, the target member may be offline and unable to refresh an expired KeyPackage. Implementations SHOULD decide their own policy — for example, accepting recently expired KeyPackages with a grace period, using a longer `lifetime` (e.g., 180 days), or prompting the admin to retry later. The trade-off is between security (rejecting stale key material) and usability (not blocking group invitations).
- After a KeyPackage is consumed by a Welcome, the member SHOULD publish a fresh one as soon as possible.
- The KeyPackage's `LeafNode` credential MUST contain the member's Nostr secp256k1 public key in hex format.
- **Identity verification:** When fetching a KeyPackage, the consumer MUST verify that the `kind: 10443` event's `pubkey` matches the Nostr public key in the KeyPackage's `BasicCredential`. A mismatch indicates a forged credential and the KeyPackage MUST be rejected.
- Clients SHOULD upload fresh KeyPackages on startup and after joining a group (since the KeyPackage is consumed by the Welcome).

### 2. Welcome Message (`kind: 444`)

When a member is added to a group, the admin sends a `Welcome` message containing the group state needed for the new member to initialize their local MLS group.

> **Note:** Per RFC 9420, MLS does not restrict invitation to admins only. However, in this specification, only admins SHOULD perform Add operations to simplify group governance on a decentralized network.

**Event Structure (NIP-17 Gift Wrap):**

```json
{
  "kind": 1059,
  "pubkey": "<random one-time pubkey>",
  "content": "<NIP-44 encrypted seal>",
  "tags": [["p", "<invitee's secp256k1 pubkey>"]],
  "created_at": <tweaked_timestamp>
}
```

The inner sealed event (kind: 13 → kind: 444):
```json
{
  "kind": 444,
  "pubkey": "<admin's secp256k1 pubkey>",
  "content": "<base64-encoded MLS Welcome message>",
  "tags": [["p", "<group_id (toMainPubkey)>"]]
}
```

**Notes:**

- Welcome messages are sent individually to each invitee via NIP-17 (kind: 1059 gift wrap), ensuring only the intended recipient can decrypt the outer layer.
- The `p` tag in the inner event contains the `group_id` for routing.
- The Welcome message contains the full ratchet tree state, so the recipient can immediately participate in group messaging.

### 3. MLS Group Message (`kind: 1059`)

All MLS protocol messages (application messages, Commits, Proposals) within a group are published as `kind: 1059` events, using the group's `listen_key` as the subscription address.

> **Privacy by design:** MLS group messages intentionally reuse `kind: 1059` (the same kind used by NIP-17 Signal Protocol direct messages) to minimize metadata leakage.

**Event Structure:**

```json
{
  "kind": 1059,
  "pubkey": "<random one-time pubkey>",
  "content": "<base64(mls_ciphertext)>",
  "tags": [["p", "<listen_key>"]],
  "created_at": <unix_timestamp>
}
```

**Encryption:**

1. **MLS PrivateMessage:** Plaintext → `MlsGroup.create_message()` → MLS ciphertext (AuthenticatedContent)
2. **Nostr event:** `base64(mls_ciphertext)` → `kind: 1059` event signed by random one-time keypair

**Decryption:**

1. Member subscribes to `listen_key` (`mlsTempInbox`) on designated relays for `kind: 1059` events
2. `base64_decode(content)` → MLS ciphertext bytes
3. Parse MLS message type: `Application` | `Commit` | `Proposal`
4. Process accordingly via `MlsGroup.process_message()`

**Listen Key Rotation:**

The `listen_key` (stored as `mlsTempInbox` on the room) is derived from the group's `export_secret`, which changes every time the group epoch advances (after a Commit is merged). After processing a Commit, all members MUST:
1. Derive the new `listen_key` from the updated `export_secret`
2. Subscribe to the new `listen_key` on the group's relays
3. Continue listening to the old `listen_key` briefly to handle in-flight messages

## mlsGroupInvite Message

When an admin adds a member to an MLS group, the Welcome data is delivered to the invitee via an `mlsGroupInvite` KCMessage. This message can be sent through an existing Signal session (Mode 1) or via NIP-17 Gift Wrap (Mode 2) if no Signal session exists.

**KCMessage Structure:**

```json
{
  "v": 2,
  "kind": "mlsGroupInvite",
  "mlsGroupInvite": {
    "groupId": "<group_pubkey_hex>",
    "name": "Group Name",
    "description": "Group description",
    "adminPubkeys": ["<admin_pubkey_hex>"],
    "relays": ["wss://relay1.example.com", "wss://relay2.example.com"],
    "welcome": "<base64-encoded MLS Welcome message>"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `groupId` | `string` | Yes | Group public key (hex) |
| `name` | `string` | Yes | Group display name |
| `description` | `string` | No | Group description |
| `adminPubkeys` | `string[]` | Yes | List of admin Nostr pubkeys (hex) |
| `relays` | `string[]` | Yes | Designated relay URLs for the group |
| `welcome` | `string` | Yes | Base64-encoded MLS Welcome message (TLS-serialized) |

The invitee processes the Welcome to join the group (see §3 Joining a Group).

## Protocol Flow

### 1. Initialization & KeyPackage Management

Upon startup, a member generates one or more `KeyPackages` and publishes them as `kind: 10443`. After joining a group (KeyPackage consumed), generate and publish a new KeyPackage.

**KeyPackage Lifecycle:**

- Created with a `lifetime` extension (recommended: 90 days)
- Validated by recipients before use
- Automatically rotated on startup if older than 30 days
- Consumed (deleted) when used in a Welcome message

### 2. Group Creation

The creator(admin) initializes the MLS group state locally and generates a `Welcome` message for member invitation.

#### Part 1: Group Initialization

1. **Initialize Group**: The admin locally sets up an MLS group. This includes generating a secp256k1 keypair (public key as group_id), calling create_mls_group (configuring use_ratchet_tree_extension and NostrGroupDataExtension), and executing a self_commit() to finalize the initial state.
2. **Generate Welcome Message**: A Welcome message is generated locally for future invitees.

#### Part 2: Inviting Group Members

1. **Validate KeyPackages**: Fetch kind: 10443 KeyPackages from relays for all invitees and perform validation (ciphersuite, lifetime, signature).
2. **Add Members & Generate Messages**: Execute add_members to perform an MLS Commit with Add proposals, which generates both the Commit (queued_msg) and Welcome messages.
3. **Merge Local Commit**: A self_commit() merges the pending Commit into the local group state.
4. **Distribute Messages**:
    • Broadcast the Commit message (kind: 1059, base64-encoded) to the group's `listen_key`.
    • Send the Welcome to each invitee individually via `mlsGroupInvite` (see [mlsGroupInvite Message](#mlsgroupinvite-message)).

### 3. Joining a Group

When a member receives a Welcome message:

1. Receive `kind: 444` event via NIP-17 gift wrap on their Nostr pubkey
2. Decrypt NIP-17 layers (gift wrap → seal → rumor) to extract the Welcome content
3. Decode the Welcome: `base64_decode(content)` → MLS Welcome bytes
4. Parse and validate: `parse_welcome_message(nostr_id, welcome)` — extracts group metadata (name, description, admins, relays)
5. Join the group: `join_mls_group(nostr_id, group_id, welcome)` — initializes local MLS group state from the Welcome's ratchet tree
6. Derive the `listen_key` from the group's `export_secret`
7. Subscribe to `listen_key` on the group's designated relays for `kind: 1059` events
8. Publish a new KeyPackage (the previous one was consumed)

### 4. Group Messaging

All group communication — application messages, Commits, and Proposals — flows through `kind: 1059` events addressed to the group's `listen_key`. Welcome messages are **not** part of this flow; they are delivered individually to invitees via NIP-17 (`kind: 444`) as described in §2 (Event Classification) and §3 (Joining a Group).

Members subscribe to the group's `listen_key` (`mlsTempInbox`) on designated relays. Upon receiving a `kind: 1059` event, the client decodes and decrypts it via MLS and dispatches based on message type:

| Message Type                                          | Action                                                    | Result                                       |
| ----------------------------------------------------- | --------------------------------------------------------- | -------------------------------------------- |
| **Application**                                       | `decrypt_message()` → extract plaintext + sender identity | Display to user                              |
| **Commit** (Add/Remove/Update/GroupContextExtensions) | `others_commit_normal()` → update group state             | Derive new `listen_key`, rotate subscription |
| **Proposal** (e.g. self-leave)                        | `others_proposal_leave()` → queue proposal                |                                              |

To send a message, a member encrypts the plaintext via MLS, base64-encodes the ciphertext, and publishes it as a `kind: 1059` event signed by a random one-time keypair to the group's designated relays.

**Fan-out:** Since all members derive the same `listen_key` from the shared `export_secret`, a single broadcast reaches all members.

**Sequencing:** MLS requires strictly ordered messages within an epoch. Clients MUST handle potential out-of-order delivery using the MLS internal `epoch` counter and `sender_data`. If a Commit is received, it MUST be processed before any subsequent application messages in the new epoch.

**Commit authority:** This specification RECOMMENDS an admin-only Commit model — only admins issue Commits for membership changes (Add/Remove) and group metadata updates. This significantly reduces the probability of concurrent Commit conflicts on a decentralized network. Member-initiated operations (self-update for key rotation, self-leave) produce Proposals that are committed by an admin. Implementations MAY adopt alternative governance models (e.g., any-member Commit) at their own discretion.

### 5. Membership Changes

All membership changes follow a common pattern: the admin creates a Commit (with associated proposals), broadcasts it to the group, and merges locally. Other members process the Commit and derive a new `listen_key`. Each operation advances the group epoch, revoking access for removed members and granting access to added ones.

#### Add Member

1. Admin fetches and validates the new member's KeyPackage (`kind: 10443`): check lifetime, ciphersuite, and signature
2. `add_members(nostr_id, group_id, [key_package])` → `AddMembersResult { queued_msg, welcome }`
3. Broadcast Commit (`queued_msg`) to `listen_key`; `self_commit()` locally
4. Send Welcome to the new member via NIP-17 (`kind: 444`)

#### Remove Member

1. Admin resolves the target's `LeafNodeIndex`: `get_lead_node_index(admin_nostr_id, target_nostr_id, group_id)`
2. `remove_members(nostr_id, group_id, [leaf_node_index])` → Commit
3. Broadcast Commit to `listen_key`; `self_commit()` locally
4. The removed member can no longer decrypt messages (lacks the new epoch's keys)

#### Member Self-Leave

A non-admin member can leave a group:

1. Member broadcasts a leave proposal: `self_leave(nostr_id, group_id)` → serialized proposal
2. Admin processes the proposal (`others_proposal_leave`) and commits (`admin_proposal_leave` → `admin_commit_leave`)
3. Remaining members process via `normal_member_commit_leave()`

Leave proposals SHOULD be encrypted consistently with other MLS messages to avoid leaking membership change metadata to relays.

#### Group Dissolution

The admin dissolves the group by updating the group context extension: `update_group_context_extensions(status="dissolved")`. Members process the `GroupContextExtensions` commit and SHOULD display a dissolution notice and prevent further messaging.

### 6. Group Metadata Updates

1. Admins update group name, description, relay list, or admin list via `update_group_context_extensions()`. Only changed fields need to be provided; others are preserved. 
2. The operation produces a Commit, which is broadcast and processed by members like any other `GroupContextExtensions` commit.

### 7. Self Update (Key Rotation)

Any member can rotate their own leaf node keys for Post-Compromise Security: `self_update(nostr_id, group_id, extensions)` → Commit. This advances the epoch with fresh key material.

## Database Design

### MLS Storage

MLS group state is persisted in a SQLite database via `openmls-sqlite-storage`. Each member maintains:

- **Identity:** Ed25519 signing key, credential (Nostr pubkey), and key packages
- **Groups:** Per-group MLS state (ratchet tree, epoch, pending proposals, etc.)
- **Key Packages:** Generated but not yet consumed key packages

The storage path is per-identity, typically: `<app_data>/mls/<nostr_id>.db`

### In-Memory State

```rust
struct MlsStore {
    pub user: HashMap<String, User>,  // nostr_id → User
}

struct User {
    pub mls_user: MlsUser,  // Contains identity, groups, provider
}

// MlsUser (from kc crate):
struct MlsUser {
    pub provider: OpenMlsRustPersistentCrypto,
    pub identity: RwLock<Identity>,    // Ed25519 signer + credential + key packages
    pub groups: RwLock<HashMap<String, Group>>,  // group_id → Group
    pub group_list: HashSet<String>,   // Set of joined group IDs
}
```

## Security Considerations

### MLS Protocol Guarantees

The MLS protocol (RFC 9420) provides the following security properties. For formal definitions and proofs, see RFC 9420 Section 16 (Security Considerations):

- **Message Confidentiality:** Only current group members can decrypt application messages.
- **Forward Secrecy (FS):** Compromise of a member's current keys does not reveal past messages, as each epoch derives new keys through the TreeKEM ratchet.
- **Post-Compromise Security (PCS):** After a key compromise, security is restored when the compromised member performs an Update or when any Commit advances the epoch.
- **Authentication:** All MLS messages are authenticated via the sender's Ed25519 leaf node signature. The `BasicCredential` binds each leaf to a Nostr secp256k1 identity.
- **Membership Integrity:** The group state (including the member list) is authenticated through the MLS transcript hash. Only valid Commits can alter membership.

These guarantees hold regardless of the transport layer, provided that messages are eventually delivered and processed in the correct order within each epoch.

### Nostr Transport Security

Running MLS over a decentralized relay network introduces challenges not addressed by the MLS specification. These are the primary contribution of this specification security analysis.

#### 1. Untrusted Delivery Service

MLS assumes a Delivery Service that reliably forwards messages to all group members. Nostr relays provide no such guarantee:

- **Message dropping:** A relay may silently discard events, causing some members to miss Commits or application messages. This can cause **epoch desynchronization** — some members advance to epoch N+1 while others remain at epoch N.
- **Selective withholding:** A malicious relay could deliver messages to some members but not others, creating a **split-view attack** where the group's state diverges.
- **Mitigation:** Members SHOULD connect to multiple relays from the group's relay list. Clients SHOULD detect epoch gaps (missing Commits) and attempt to re-fetch from alternative relays. As a last resort, a desynchronized member can leave and rejoin via a new Welcome.

#### 2. No Global Message Ordering

MLS requires strict message ordering within an epoch. Nostr relays have no global ordering mechanism:

- **Concurrent Commits:** If two members submit Commits at the same epoch, different relays may deliver them in different orders, causing state divergence among members. This is inherent to decentralized networks — without a central sequencer, there is no canonical "first" Commit.
- **Stale Commit rejection**: MLS rejects Commits targeting a stale epoch. When a member receives two Commits for the same epoch, the first one processed advances the epoch; the second is discarded as stale. The sender of the rejected Commit SHOULD re-propose based on the current epoch.
- **Divergence detection and recovery**: Clients SHOULD detect epoch mismatches (e.g., decryption failures from peers) as a signal of state divergence. The simplest recovery is for an admin to issue a fresh Welcome to the desynchronized member, re-establishing their group state from the current epoch.
- **Practical note**: In typical usage, concurrent Commits are rare — most state-changing operations (Add/Remove) are admin-initiated, and member-initiated Commits (self-update for key rotation) can use randomized delays to reduce collision probability.

#### 3. Decentralized Directory Service

MLS assumes a trusted Directory Service for KeyPackage distribution. On Nostr:

- **KeyPackage censorship:** A relay may refuse to store or serve a member's `kind: 10443` event, effectively preventing them from being added to any group served by that relay.
- **Stale KeyPackages:** Relays may serve expired or already-consumed KeyPackages. If a consumed KeyPackage is reused, the Welcome will fail for the new member.
- **Mitigation:** Members publish KeyPackages to multiple relays. Clients validate KeyPackage lifetime before use. After a KeyPackage is consumed, the member publishes a fresh one.

#### 4. Metadata Protection

MLS does not address transport-layer metadata. This specification employs several techniques to minimize metadata leakage on Nostr:

- **Random one-time sender keypairs:** Each message is signed by a freshly generated secp256k1 keypair (`generate_simple()`). Relays cannot correlate messages to a persistent sender identity.
- **Listen key rotation:** The group subscription address (`listen_key`) changes every epoch. Long-term traffic analysis on a single address is limited to one epoch's duration.
- **Kind reuse (`kind: 1059`):** MLS group messages and Signal 1:1 messages use the same event kind. Relays cannot distinguish group traffic from direct messages.
- **NIP-17 timestamp tweaking:** Welcome messages use randomized `created_at` timestamps (±2 days), preventing timing correlation.

**Residual metadata exposure:**
- Relays see the `listen_key` (p tag) and can correlate all events addressed to it within an epoch — they know "these N events are for the same group" but not which group, how many members, or the content. Periodic epoch advances (e.g., via scheduled self-updates) limit the correlation window.
- Message sizes may reveal whether a message is an application message vs. a Commit (Commits with Add proposals are larger). Implementations SHOULD pad messages to the nearest 256-byte boundary to reduce size-based classification.

## Implementation Reference

### Reference Implementation

The reference implementation is [libkeychat](https://github.com/nicobao/keychat-protocol) (`libkeychat/src/`):

- `mls.rs` — Core MLS operations: group creation, member add/remove, message encrypt/decrypt, Commit processing, self-update, self-leave
- `mls_extension.rs` — `NostrGroupDataExtension` definition and serialization
- `mls_provider.rs` — OpenMLS provider wrapper with persistent storage
- `nip44.rs` — NIP-44 v2 encryption/decryption
- `giftwrap.rs` — NIP-17 / NIP-59 gift wrap creation and unwrapping
- `transport.rs` — Relay connection and event publishing

### Dependencies

- [openmls](https://github.com/openmls/openmls) — Rust implementation of MLS (RFC 9420)
- [openmls-sqlite-storage](https://crates.io/crates/openmls-sqlite-storage) — Persistent MLS state storage
- [nostr-rs](https://github.com/rust-nostr/nostr) — Nostr protocol primitives (NIP-44, NIP-59)

### Event Kind Summary

| Kind | Name | Use | Encryption | Replaceable |
|------|------|-----|------------|-------------|
| `10443` | MLS KeyPackage | Publish KeyPackage for async group join | None (public) | Yes (per pubkey) |
| `444` | MLS Welcome | Invite member to group (via mlsGroupInvite) | Signal or NIP-59 Gift Wrap | No |
| `1059` | MLS Group Message | Application messages, Commits, Proposals | MLS | No |



## Appendix 

### Comparison with Signal Protocol Groups

| Property                     | Signal Protocol (NIP-17)               | MLS (this NIP)                  |
| ---------------------------- | -------------------------------------- | ------------------------------- |
| Group key update cost        | O(N) — sender encrypts for each member | O(log N) — TreeKEM ratchet tree |
| Add/Remove member            | Re-encrypt & distribute to all members | Single Commit + Welcome message |
| Forward Secrecy              | Per-session Double Ratchet             | Per-epoch TreeKEM ratchet       |
| Post-Compromise Security     | Per-message (DH ratchet step)          | Per-epoch (Update + Commit)     |
| Suitable group size          | ≤ 50 members                           | 1,000+ members                  |
| Message ordering requirement | Per-session (tolerant)                 | Strict within epoch             |

## Reference

[1] The Messaging Layer Security (MLS) Protocol, RFC 9420, https://www.rfc-editor.org/rfc/rfc9420

[2] TreeKEM: Asynchronous Decentralized Key Management for Large Groups, https://eprint.iacr.org/2019/1489

[3] NIP-17: Private Direct Messages, https://github.com/nostr-protocol/nips/blob/master/17.md

[4] NIP-44: Encrypted Payloads (Versioned), https://github.com/nostr-protocol/nips/blob/master/44.md

[5] NIP-59: Gift Wrap, https://github.com/nostr-protocol/nips/blob/master/59.md

[6] OpenMLS — A Rust Implementation of MLS, https://github.com/openmls/openmls

[7] Signal Protocol over Nostr (NIP Draft), Keychat, https://github.com/keychat-io/keychat-app/blob/main/docs/Signal-Protocol-over-Nostr-NIP-DRAFT.md

[8] Not in The Prophecies: Practical Attacks on Nostr, https://crypto-sec-n.github.io/
