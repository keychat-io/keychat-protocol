# KeychatClient API Guide

The `KeychatClient` is the high-level entry point for libkeychat. It wraps identity management, Signal Protocol encryption, Nostr relay transport, and group messaging into a single struct with a simple async API.

## Table of Contents

- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Identity](#identity)
- [Adding Friends](#adding-friends)
- [Sending Messages](#sending-messages)
- [Receiving Events](#receiving-events)
- [Event Types](#event-types)
- [Small Groups (Signal-based)](#small-groups-signal-based)
- [Media](#media)
- [MLS Large Groups](#mls-large-groups)
- [Contact Management](#contact-management)
- [Persistence](#persistence)
- [Error Handling](#error-handling)
- [Architecture](#architecture)
- [Complete Example](#complete-example)

## Getting Started

Add libkeychat to your `Cargo.toml`:

```toml
[dependencies]
libkeychat = { path = "../libkeychat" }
tokio = { version = "1", features = ["full"] }
```

Minimal example:

```rust
use libkeychat::client::{KeychatClient, ClientConfig, InboundEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        db_path: "my-keychat.db".into(),
        display_name: "Alice".into(),
        relays: vec!["wss://relay.damus.io".into()],
        mnemonic: None,
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    println!("Identity: {}", client.npub()?);

    Ok(())
}
```

## Configuration

`ClientConfig` fields:

| Field | Type | Description |
|-------|------|-------------|
| `db_path` | `String` | Path to the SQLite database file. Created if it doesn't exist. |
| `display_name` | `String` | Your display name, included in hello (friend request) messages. |
| `relays` | `Vec<String>` | Nostr relay WebSocket URLs to connect to. |
| `mnemonic` | `Option<String>` | BIP-39 mnemonic phrase. `None` = generate a new 12-word mnemonic. |
| `media_server` | `Option<String>` | Media upload server URL. `None` = `https://relay.keychat.io`. |

### Relay Selection

Use multiple relays for reliability. Messages are published to all connected relays concurrently. Recommended relays:

```rust
relays: vec![
    "wss://relay.keychat.io".into(),
    "wss://relay.damus.io".into(),
    "wss://relay.primal.net".into(),
    "wss://nos.lol".into(),
],
```

### Identity Persistence

To reuse the same identity across restarts, save and restore the mnemonic:

```rust
// First run — generate and save
let client = KeychatClient::init(config).await?;
let mnemonic = client.mnemonic().unwrap();
std::fs::write("mnemonic.txt", mnemonic)?; // ⚠️ store securely!

// Later runs — restore
let phrase = std::fs::read_to_string("mnemonic.txt")?;
let config = ClientConfig {
    mnemonic: Some(phrase),
    // ...other fields...
};
let client = KeychatClient::init(config).await?;
// Same npub as before
```

## Identity

After initialization, you can access your identity:

```rust
// Bech32-encoded public key (npub1...)
let npub = client.npub()?;

// Hex public key (64 chars)
let hex = client.pubkey_hex();

// BIP-39 mnemonic (if available)
if let Some(phrase) = client.mnemonic() {
    println!("Backup your mnemonic: {}", phrase);
}

// Raw Nostr keypair
let keypair = client.keypair();
```

## Adding Friends

Keychat uses a "hello" protocol to establish encrypted sessions. This is similar to adding a contact — it sends a friend request that includes your Signal Protocol prekey bundle.

```rust
// By npub
client.add_friend("npub1abc...", "Hey, let's chat!").await?;

// By hex pubkey
client.add_friend(
    "6fad5538ee4b3718a23c52c6caf8f327bf6450fe8e621652742b6cae7d7d8858",
    "Hello from my Rust client"
).await?;
```

**What happens under the hood:**

1. Generates a new Signal Protocol identity and prekey bundle
2. Builds a `QRUserModel` with your keys and metadata
3. Wraps it in a NIP-59 Gift Wrap (kind:1059) for privacy
4. Publishes to all connected relays
5. Subscribes to receiving addresses for the reply

The recipient (Keychat app or another libkeychat client) will see a friend request and can accept it, which establishes a bidirectional Signal session.

## Sending Messages

Once a Signal session is established (after a hello exchange), send encrypted messages:

```rust
let peer = "6fad5538ee4b3718a23c52c6caf8f327bf6450fe8e621652742b6cae7d7d8858";
client.send(peer, "Hello, world!").await?;
```

**What happens under the hood:**

1. Encrypts the plaintext with the Signal Protocol (Double Ratchet)
2. Generates an ephemeral Nostr keypair for the event (metadata privacy)
3. Publishes a kind:4 event with base64-encoded ciphertext
4. The p-tag points to the peer's current receiving address
5. Address rotation happens automatically as the ratchet advances

### Error Cases

```rust
match client.send(peer, "Hi").await {
    Ok(()) => println!("Sent!"),
    Err(KeychatError::MissingPeer(_)) => {
        println!("No session with this peer. Send a hello first.");
    }
    Err(KeychatError::MissingSendingAddress(_)) => {
        println!("Session exists but no sending address yet.");
    }
    Err(e) => eprintln!("Send failed: {}", e),
}
```

## Receiving Events

### Start Listening

Before receiving any events, call `start_listening()` to subscribe to your identity's addresses on all relays:

```rust
client.start_listening().await?;
```

This subscribes to:
- **kind:1059** events addressed to your pubkey (friend requests, MLS)
- **kind:4** events addressed to your pubkey (initial DMs)

As sessions are established, the client automatically subscribes to ratchet-derived addresses for each peer.

### Event Loop

Use `next_event()` to process inbound events:

```rust
while let Some(event) = client.next_event().await {
    match event {
        InboundEvent::DirectMessage { sender, plaintext, is_prekey } => {
            println!("[{}] {}", &sender[..12], plaintext);
            if is_prekey {
                println!("  (first message in new session)");
            }
        }
        InboundEvent::FriendRequest { sender, sender_name, message } => {
            println!("Friend request from {} ({}): {}", sender_name, &sender[..12], message);
        }
        InboundEvent::GroupEvent { from_peer, event } => {
            println!("Group event from {}: {:?}", &from_peer[..12], event);
        }
    }
}
// Returns None when all relay connections close
println!("Disconnected");
```

`next_event()` is a blocking async call — it waits until an event arrives. Use `tokio::select!` to combine it with other async tasks:

```rust
loop {
    tokio::select! {
        Some(event) = client.next_event() => {
            handle_event(event);
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down...");
            break;
        }
    }
}
```

## Event Types

### `InboundEvent::DirectMessage`

A Signal-encrypted direct message.

| Field | Type | Description |
|-------|------|-------------|
| `sender` | `String` | Peer's Nostr pubkey hex |
| `plaintext` | `String` | Decrypted message text |
| `is_prekey` | `bool` | `true` if this was a PreKey message (session establishment) |

### `InboundEvent::FriendRequest`

A hello (add-friend) request received via NIP-59 Gift Wrap.

| Field | Type | Description |
|-------|------|-------------|
| `sender` | `String` | Peer's Nostr pubkey hex |
| `sender_name` | `String` | Peer's display name |
| `message` | `String` | Greeting message |

When a `FriendRequest` is received, the client automatically:
- Establishes the Signal session
- Publishes an auto-reply (acknowledging the hello)
- Subscribes to the peer's receiving addresses

### `InboundEvent::GroupEvent`

A Signal-based small group event, delivered via the peer's 1:1 Signal session.

| Field | Type | Description |
|-------|------|-------------|
| `from_peer` | `String` | Peer who sent the event |
| `event` | `GroupEvent` | Parsed group event (see below) |

`GroupEvent` variants:

| Variant | Fields | Description |
|---------|--------|-------------|
| `Message` | `sender`, `content`, `group_pubkey` | Chat message in a group |
| `Invite` | `profile`, `inviter` | Group invite (contains `GroupProfile`) |
| `MemberRemoved` | `member_pubkey`, `by`, `group_pubkey` | Someone was kicked |
| `Dissolved` | `by`, `group_pubkey` | Group was dissolved by admin |
| `RoomNameChanged` | `new_name`, `by`, `group_pubkey` | Group renamed |
| `NicknameChanged` | `new_name`, `by`, `group_pubkey` | Member changed their nickname |

## Small Groups (Signal-based)

Small groups use fan-out encryption: each message is individually encrypted for each member via their 1:1 Signal sessions. Suitable for up to ~20 members.

### Creating a Group

```rust
let result = client.create_group("My Group")?;
let group_pubkey = result.profile.pubkey.clone();
let mut profile = result.profile;

// Add members to the profile
profile.add_member("peer_hex_pubkey", "Alice", false);
profile.add_member("another_peer_hex", "Bob", false);

println!("Group ID: {}", group_pubkey);
```

### Sending Invites

Send the group invite to each member via their existing Signal session:

```rust
// Peer must already be a friend (have a Signal session)
client.send_group_invite(&peer_hex, &profile, "Join my group!").await?;
```

The invite is a `KeychatMessage` with `type: 11, c: "group"` containing the `GroupProfile` JSON. The Keychat app will show a group invite notification.

### Sending Group Messages

```rust
// Send to all other members (fan-out)
let members = &["peer1_hex", "peer2_hex"];
client.send_group_message(&group_pubkey, members, "Hello group!").await?;
```

Each member receives the message individually via their Signal session. The message is wrapped in a `GroupMessage` with `type: 30, c: "group"`.

### Receiving Group Messages

Group messages arrive as `InboundEvent::GroupEvent`:

```rust
InboundEvent::GroupEvent { from_peer, event } => {
    match event {
        GroupEvent::Invite { profile, inviter } => {
            println!("Invited to group '{}' by {}", profile.name, inviter);
        }
        GroupEvent::Message { sender, content, group_pubkey } => {
            println!("[Group {}] {}: {}", &group_pubkey[..8], &sender[..8], content);
        }
        GroupEvent::MemberRemoved { member_pubkey, by, .. } => {
            println!("{} was removed by {}", &member_pubkey[..8], &by[..8]);
        }
        GroupEvent::Dissolved { by, .. } => {
            println!("Group dissolved by {}", &by[..8]);
        }
        _ => {}
    }
}
```

### GroupProfile Format

The `GroupProfile` uses camelCase JSON serialization to match the Keychat app:

```json
{
  "pubkey": "group_nostr_pubkey_hex",
  "name": "Group Name",
  "users": [
    {"idPubkey": "member1_hex", "name": "Alice", "isAdmin": true},
    {"idPubkey": "member2_hex", "name": "Bob", "isAdmin": false}
  ],
  "groupType": "sendAll",
  "updatedAt": 1772708000000,
  "oldToRoomPubKey": "group_nostr_pubkey_hex"
}
```

### Group Management

```rust
// Rename a group
client.rename_group(&group_pubkey, "New Name", &member_pubkeys).await?;

// Remove a member (notify remaining members)
client.remove_group_member(&group_pubkey, &removed_peer, &remaining_members).await?;

// Dissolve the group
client.dissolve_group(&group_pubkey, &member_pubkeys).await?;
```

Management events are sent as regular group messages (`type=30`) with a `subtype` inside the `GroupMessage` JSON. The Keychat app processes them through the same `processGroupMessage` code path.

### Limitations

- Members must have existing 1:1 Signal sessions (add as friend first)
- No automatic member discovery — the creator manages the member list
- Fan-out means O(N) encryptions per message — use MLS for larger groups

## Media

Send encrypted media files (images, videos, documents) to peers:

```rust
let image_bytes = std::fs::read("photo.jpg")?;
client.send_media(&peer_hex, &image_bytes, "jpg", "photo.jpg", "image").await?;
```

**What happens under the hood:**
1. PKCS7 padding + AES-256-CTR encryption (random key + IV)
2. Upload to media server (S3 relay → Blossom fallback)
3. Build Keychat media URL with query params (`kctype`, `key`, `iv`, `hash`, etc.)
4. Send the URL as a Signal-encrypted message

### Media Types

| Type | Description |
|------|-------------|
| `"image"` | Images (jpg, png, gif, webp) |
| `"video"` | Videos (mp4, mov, mkv) |
| `"file"` | Generic files |
| `"voiceNote"` | Voice messages |

### Media Server

Configure via `ClientConfig::media_server`. Defaults to `https://relay.keychat.io`.

```rust
let config = ClientConfig {
    media_server: Some("https://my-blossom.example.com".into()),
    // ...
};
```

### Receiving Media

Inbound media messages arrive as `InboundEvent::DirectMessage` where `plaintext` is a URL with encryption params. Parse it with:

```rust
use libkeychat::media::{parse_media_url, decrypt_file};

if let Some(info) = parse_media_url(&plaintext) {
    println!("Media: {} ({})", info.kctype, info.source_name.unwrap_or_default());
    // Download the encrypted file from info.url, then:
    // let decrypted = decrypt_file(&encrypted_bytes, &info.key, &info.iv)?;
}
```

## Ecash Stamps

Ecash stamps are anonymous per-event micropayments to Nostr relays, using Cashu ecash tokens. When a relay requires stamps, the client attaches a token as the third element of the EVENT message: `["EVENT", <event>, "<cashu_token>"]`. See [NIP-XX: Ecash Token as Nostr Note Stamp](../NIP-ESTAMP.md) for the full specification.

### Discovering Relay Fees

Fetch a relay's stamp requirements from its NIP-11 document:

```rust
use libkeychat::stamp::{fetch_relay_stamp_info, StampConfig};

// Fetch fee info for a relay
let fee = fetch_relay_stamp_info("wss://relay.keychat.io").await?;
if let Some(fee) = &fee {
    println!("Relay requires {} {} per event", fee.amount, fee.unit);
    println!("Accepted mints: {:?}", fee.mints);
}

// Build a StampConfig from discovered fees
let mut stamp_config = StampConfig::new();
if let Some(fee) = fee {
    stamp_config.insert("wss://relay.keychat.io", fee);
}
```

### Implementing a Stamp Provider

libkeychat does not bundle a Cashu wallet. You provide your own by implementing the `StampProvider` trait:

```rust
use libkeychat::stamp::{StampProvider, RelayStampFee};
use libkeychat::error::Result;

struct MyCashuWallet {
    // your Cashu wallet state (e.g. from the `cdk` crate)
}

impl StampProvider for MyCashuWallet {
    fn create_stamp(&self, amount: u64, unit: &str, mints: &[String]) -> Result<String> {
        // 1. Select proofs from your wallet matching one of the mints
        // 2. Create a Cashu token of the required amount
        // 3. Return the encoded token string (e.g. "cashuAeyJ...")
        todo!("integrate with your Cashu wallet")
    }
}
```

A `NoopStampProvider` is included for development/testing — it returns an error if stamps are requested.

### Using Stamps with RelayPool

```rust
use libkeychat::stamp::{StampConfig, NoopStampProvider};
use std::sync::Arc;

let stamp_provider: Arc<dyn StampProvider> = Arc::new(MyCashuWallet::new());

// Publish with per-relay stamps
relay_pool.publish_with_stamps(&event, &stamp_config, stamp_provider.as_ref()).await?;
// For each relay: checks StampConfig → if fee required, calls provider → attaches token
// Free relays get the event without a stamp
```

### Using Stamps with KeychatClient

```rust
let config = ClientConfig {
    display_name: "Alice".into(),
    relays: vec!["wss://relay.keychat.io".into()],
    db_path: "alice.db".into(),
    ..Default::default()
};

let mut client = KeychatClient::init(config).await?;

// Set stamp provider
client.set_stamp_provider(Box::new(MyCashuWallet::new()));

// Messages sent via client.send() will automatically attach stamps
// when the relay requires them and a provider is configured
client.send(&peer_pubkey, "Hello with stamps!").await?;
```

### Configuration Reference

| Field | Type | Description |
|-------|------|-------------|
| `StampConfig` | `BTreeMap<relay_url, RelayStampFee>` | Per-relay fee requirements |
| `RelayStampFee.amount` | `u64` | Cost per event |
| `RelayStampFee.unit` | `String` | `"sat"` or `"msat"` |
| `RelayStampFee.mints` | `Vec<String>` | Accepted Cashu mint URLs |

## MLS Large Groups

MLS (Messaging Layer Security) provides scalable group messaging with forward secrecy. The Client API wraps all MLS operations with proper async/`spawn_blocking` handling.

### Setup

MLS requires a separate database:

```rust
client.init_mls("mls.db").await?;
```

### Creating a Group

```rust
// Create group
let group_id = client.create_mls_group("My Group").await?;

// Publish your key package to relays (so others can invite you)
let kp = client.create_key_package().await?;
println!("Key package: {}", kp.key_package);
```

### Adding Members

```rust
// Fetch the member's key package from a relay, then:
let result = client.mls_add_member(&group_id, &member_key_package_hex).await?;
// result.welcome — send to the new member via relay
// result.commit_message — broadcast to existing members
```

### Joining a Group

```rust
let group_id = client.mls_join_group(&welcome_bytes).await?;
println!("Joined group: {}", group_id);
```

### Sending and Receiving

```rust
// Encrypt
let ciphertext = client.mls_encrypt(&group_id, "Hello group!").await?;

// Decrypt (after receiving from relay)
let decrypted = client.mls_decrypt(&group_id, &ciphertext).await?;
println!("[{}] {}", decrypted.sender_nostr_id, decrypted.plaintext);

// Unified processing (handles both messages and commits)
let result = client.mls_process_message(&group_id, &raw_bytes).await?;
```

### Group Management

```rust
// List groups
let groups = client.mls_groups().await?;

// Get listen key (for subscribing on relays)
let listen_key = client.mls_listen_key(&group_id).await?;

// Get export secret keypair (for NIP-44 encryption)
let es_keypair = client.mls_export_secret_keypair(&group_id).await?;

// Remove member
client.mls_remove_member(&group_id, &member_nostr_id).await?;

// Leave group
client.mls_leave_group(&group_id).await?;
```

### Note on Threading

MLS functions use an internal `RUNTIME.block_on()`, so they are automatically dispatched via `tokio::task::spawn_blocking` by the Client API. You don't need to handle this yourself.

## Contact Management

```rust
// List all peers with established Signal sessions
let peers = client.peers();
for peer in &peers {
    println!("Peer: {}", peer);
}

// Check if a specific session exists
if client.has_session("6fad5538...") {
    println!("Can send messages to this peer");
}
```

## Persistence

`KeychatClient` automatically saves all state to SQLite after every state-changing operation:
- After `add_friend()` — saves the new Signal session and address state
- After `send()` — saves the advanced ratchet state
- After receiving a `FriendRequest` or `DirectMessage` — saves the updated session

### How It Works

All Signal sessions, remote addresses, and the address manager are serialized into a `ClientSnapshot` and stored as a JSON blob in the `client_state` SQLite table. On `init()`, the snapshot is automatically restored if found.

### Manual Save

You can also call `save()` explicitly:

```rust
client.save()?;
```

### Restart Survival

```rust
// Session 1: establish connections
let mut client = KeychatClient::init(config.clone()).await?;
client.add_friend("npub1...", "Hi").await?;
// State is auto-saved to keychat.db

// Session 2: restore and continue
let mut client = KeychatClient::init(config.clone()).await?;
assert!(client.has_session("6fad5538...")); // Sessions survived restart
client.send("6fad5538...", "Still here!").await?; // Works immediately
```

### Storage Schema

The client uses a `client_state` key-value table alongside existing Signal and peer tables:

| Table | Purpose |
|-------|---------|
| `client_state` | Serialized `ClientSnapshot` (signals + addresses) |
| `signal_sessions` | Raw Signal Protocol session records |
| `peers` | Peer metadata (pubkey, name) |
| `receiving_addresses` | Address → peer mapping |
| `processed_events` | Deduplication of processed Nostr events |

## Error Handling

All fallible methods return `Result<T, KeychatError>`. Key error variants:

| Error | When |
|-------|------|
| `KeychatError::MissingPeer(id)` | `send()` called with no Signal session for this peer |
| `KeychatError::MissingSendingAddress(id)` | Session exists but no sending address (race condition) |
| `KeychatError::InvalidArgument(msg)` | Bad pubkey format passed to `add_friend()` |
| `KeychatError::Signal(msg)` | Signal Protocol error (encrypt/decrypt failure) |
| `KeychatError::Transport(msg)` | Relay connection error |
| `KeychatError::Nostr(msg)` | Event parsing or NIP-44 encryption error |

## Architecture

```
┌──────────────────────────────────────────────┐
│                KeychatClient                  │
│                                               │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ Identity  │  │  Signal   │  │  Address   │ │
│  │ (Nostr    │  │ Sessions  │  │  Manager   │ │
│  │  keypair) │  │ (per peer)│  │ (ratchet)  │ │
│  └──────────┘  └──────────┘  └────────────┘ │
│                                               │
│  ┌──────────────────────────────────────────┐ │
│  │              RelayPool                    │ │
│  │  ┌───────┐ ┌───────┐ ┌───────┐          │ │
│  │  │Relay 1│ │Relay 2│ │Relay 3│  ...      │ │
│  │  └───────┘ └───────┘ └───────┘          │ │
│  └──────────────────────────────────────────┘ │
│                                               │
│  ┌──────────┐  ┌──────────────────────────┐  │
│  │  SQLite   │  │  Subscriptions Manager   │  │
│  │  Store    │  │  (auto rotate addresses) │  │
│  └──────────┘  └──────────────────────────┘  │
└──────────────────────────────────────────────┘
```

**Data flow — sending a message:**

```
"Hello" → Signal encrypt → base64 → kind:4 Nostr event → all relays
```

**Data flow — receiving a message:**

```
Relay → kind:4 event → p-tag lookup → Signal decrypt → InboundEvent::DirectMessage
```

**Data flow — friend request:**

```
QRUserModel + greeting → KeychatMessage → NIP-59 Gift Wrap → kind:1059 → relays
```

## Complete Example

A simple echo bot that accepts all friend requests and echoes back messages:

```rust
use libkeychat::client::{KeychatClient, ClientConfig, InboundEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        db_path: "echo-bot.db".into(),
        display_name: "Echo Bot".into(),
        relays: vec![
            "wss://relay.keychat.io".into(),
            "wss://relay.damus.io".into(),
        ],
        mnemonic: None,
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    println!("Echo Bot started!");
    println!("npub: {}", client.npub()?);
    println!("Send a friend request to start chatting.\n");

    client.start_listening().await?;

    while let Some(event) = client.next_event().await {
        match event {
            InboundEvent::FriendRequest { sender, sender_name, message } => {
                println!("✅ New friend: {} ({})", sender_name, &sender[..12]);
                println!("   Message: {}", message);
                // Session is auto-established, can send messages now
            }
            InboundEvent::DirectMessage { sender, plaintext, .. } => {
                println!("📨 [{}]: {}", &sender[..12], plaintext);

                // Echo it back
                let reply = format!("Echo: {}", plaintext);
                match client.send(&sender, &reply).await {
                    Ok(()) => println!("📤 Replied: {}", reply),
                    Err(e) => eprintln!("❌ Send error: {}", e),
                }
            }
            InboundEvent::GroupEvent { from_peer, event } => {
                println!("👥 Group event from {}: {:?}", &from_peer[..12], event);
            }
        }
    }

    println!("All relays disconnected. Goodbye!");
    Ok(())
}
```

Run it:

```bash
cargo run --example echo_bot
```
