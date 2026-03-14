# libkeychat Developer Guide

Build E2E encrypted messaging clients with Keychat Protocol v2.

**Reference implementation**: [keychat-cli](../keychat-cli/) — a full-featured CLI client built on this library.

## Quick Start

```toml
[dependencies]
libkeychat = { path = "../libkeychat-claude" }  # or git URL
tokio = { version = "1", features = ["full"] }
nostr-sdk = "0.37"
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Your Client                       │
├─────────────────────────────────────────────────────┤
│                   libkeychat                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Identity  │  │ KCMessage│  │ AddressManager   │  │
│  │ (BIP-39)  │  │ v2       │  │ (ratchet addrs)  │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│  ┌──────────────────────────────────────────────┐   │
│  │        SignalParticipant (PQXDH)             │   │
│  │   encrypt/decrypt + address derivation       │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ MLS Group│  │ Media    │  │ SecureStorage    │  │
│  │ (OpenMLS)│  │ (AES-CTR)│  │ (SQLCipher)      │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────┤
│  libsignal-protocol  │  OpenMLS (kc4)  │  Nostr    │
└─────────────────────────────────────────────────────┘
```

## Core Concepts

### 1. Everything is kind:1059

All Keychat v2 messages use Nostr event kind 1059. No more kind:4. Two transport modes:

- **Mode 1 (Direct)**: `content = base64(signal_ciphertext)`, p-tag = receiver address. Used for all 1:1 and group messages after session establishment.
- **Mode 2 (NIP-17 Gift Wrap)**: Three-layer encryption (Rumor → Seal → Gift Wrap). Used only for friend requests.

### 2. Signal Identity ≠ Nostr Identity

Each peer gets a fresh Signal identity (Curve25519 keypair). Signal identities are:
- **Per-peer**: Different Signal identity for each contact
- **Ephemeral**: Regenerated on each new friend request
- **Decoupled from Nostr**: Your nostr keypair is your long-term identity; Signal is just the encryption layer

### 3. Address Rotation

Messages are NOT sent to the receiver's nostr pubkey (except as last resort). Instead:

```
firstInbox → ratchet-derived addresses (rotating) → nostr pubkey (fallback)
```

After each encrypt/decrypt, the Double Ratchet produces new keys. These derive new Nostr keypairs used as ephemeral receiving addresses. Your client must:
- Track receiving addresses per peer
- Subscribe to each address on the relay
- Use `AddressManager` to handle this automatically

---

## Step-by-Step: Building a Client

### Step 1: Identity

```rust
use libkeychat::{Identity, Keys};

// Generate new identity
let identity = Identity::generate()?;
println!("Mnemonic: {}", identity.mnemonic());
println!("npub: {}", identity.pubkey_hex());

// Restore from mnemonic
let identity = Identity::from_mnemonic_str("word1 word2 ... word12")?;

// Access Nostr keys
let keys: &Keys = identity.keys();
```

### Step 2: Connect to Relay

```rust
use nostr_sdk::Client;

let client = Client::new(identity.keys().clone());
client.add_relay("wss://nos.lol").await?;
client.connect().await;
```

### Step 3: Send Friend Request

```rust
use libkeychat::{send_friend_request, AddressManager};

let (event, fr_state) = send_friend_request(
    &identity,
    "<peer_nostr_pubkey_hex>",  // who to add
    "Alice",                      // your display name
    "my-app",                     // device ID
).await?;

// Publish to relay
client.send_event(event).await?;

// fr_state contains:
//   .signal_participant  — your Signal session (KEEP THIS, need it to decrypt their reply)
//   .first_inbox_keys    — ephemeral keypair for receiving the acceptance

// CRITICAL: Subscribe to firstInbox address to receive the acceptance reply
let first_inbox_pubkey = fr_state.first_inbox_keys.pubkey_hex();
subscribe_to_address(&client, &first_inbox_pubkey).await;
```

### Step 4: Receive Friend Request

```rust
use libkeychat::{receive_friend_request, accept_friend_request};

// When you receive a kind:1059 event:
if let Ok(fr) = receive_friend_request(&identity, &event) {
    println!("Friend request from: {}", fr.payload.name);
    println!("Nostr pubkey: {}", fr.sender_pubkey.to_hex());
    
    // Accept it
    let accepted = accept_friend_request(&identity, &fr, "Bob").await?;
    client.send_event(accepted.event).await?;
    
    // accepted.signal_participant has the established Signal session
    // Store it — you'll use it for all future messages with this peer
    
    // The peer's Signal identity (for ProtocolAddress):
    let peer_signal_id = fr.payload.signal_identity_key.clone();
    //                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  NOT accepted.signal_participant.identity_public_key_hex() — that's YOUR key
    
    // Initialize address tracking
    let mut addr_mgr = AddressManager::new();
    addr_mgr.add_peer(
        &peer_signal_id,
        Some(fr.payload.first_inbox.clone()),  // their firstInbox
        Some(fr.sender_pubkey.to_hex()),        // their nostr pubkey
    );
}
```

### Step 5: Receive Friend Request Acceptance

When you sent the request (Step 3), the peer's acceptance arrives as a Mode 1 event on your `firstInbox`:

```rust
use libsignal_protocol::PreKeySignalMessage;

// The event content is base64(Signal PreKey ciphertext)
let ciphertext = base64_decode(&event.content)?;

if SignalParticipant::is_prekey_message(&ciphertext) {
    // Extract sender's Signal identity from the PreKeySignalMessage
    let prekey_msg = PreKeySignalMessage::try_from(ciphertext.as_slice())?;
    let peer_signal_id = hex::encode(prekey_msg.identity_key().serialize());
    
    let remote_addr = ProtocolAddress::new(peer_signal_id.clone(), DeviceId::from(1));
    
    // Decrypt using the SignalParticipant from Step 3
    let result = fr_state.signal_participant
        .decrypt(&remote_addr, &ciphertext)?;
    
    let msg = KCMessage::try_parse(&String::from_utf8_lossy(&result.plaintext))?;
    
    // msg.signal_prekey_auth contains the peer's identity binding:
    //   .nostr_id  — peer's nostr pubkey
    //   .signal_id — peer's signal identity key
    //   .name      — peer's display name
    //   .sig       — Schnorr signature proving ownership
    
    // Initialize address tracking
    let mut addr_mgr = AddressManager::new();
    addr_mgr.add_peer(&peer_signal_id, None, Some(peer_nostr_id));
    addr_mgr.on_decrypt(&peer_signal_id, 
        result.bob_derived_address.as_deref(),
        result.alice_addrs.as_deref())?;
    // Subscribe to new receiving addresses from the update
}
```

### Step 6: Send Messages

```rust
use libkeychat::{KCMessage, SignalParticipant, AddressManager};
use libsignal_protocol::{ProtocolAddress, DeviceId};

let msg = KCMessage::text("Hello!");
let json = msg.to_json()?;

let addr = ProtocolAddress::new(peer_signal_id.clone(), DeviceId::from(1));

// Encrypt (returns address metadata for ratchet tracking)
let ct = signal_participant.encrypt(&addr, json.as_bytes())?;

// Resolve WHERE to send (ratchet address → firstInbox → npub fallback)
let to_address = addr_mgr.resolve_send_address(&peer_signal_id)?;

// Update address state (may produce new receiving addresses to subscribe to)
let update = addr_mgr.on_encrypt(&peer_signal_id, ct.sender_address.as_deref())?;
for new_addr in &update.new_receiving {
    subscribe_to_address(&client, new_addr).await;
}

// Build and send Mode 1 event
let sender = EphemeralKeypair::generate();  // random sender per message!
let event = EventBuilder::new(Kind::GiftWrap, base64_encode(&ct.bytes))
    .tag(Tag::public_key(PublicKey::from_hex(&to_address)?))
    .sign(sender.keys())
    .await?;
client.send_event(event).await?;
```

### Step 7: Receive Messages

```rust
// Subscribe to your npub + all receiving addresses
let filter = Filter::new()
    .kind(Kind::GiftWrap)
    .custom_tag(SingleLetterTag::lowercase(Alphabet::P), [my_npub])
    .since(Timestamp::now() - 300);
client.subscribe(vec![filter], None).await?;

// In your event loop:
let ciphertext = base64_decode(&event.content)?;
let addr = ProtocolAddress::new(peer_signal_id, DeviceId::from(1));

let result = signal_participant.decrypt(&addr, &ciphertext)?;

// Update address state
let update = addr_mgr.on_decrypt(
    &peer_signal_id,
    result.bob_derived_address.as_deref(),
    result.alice_addrs.as_deref(),
)?;
// Subscribe to new receiving addresses
for new_addr in &update.new_receiving {
    subscribe_to_address(&client, new_addr).await;
}

// Parse message
let msg = KCMessage::try_parse(&String::from_utf8_lossy(&result.plaintext))?;
match &msg.kind {
    KCMessageKind::Text => println!("{}", msg.text.unwrap().content),
    KCMessageKind::FriendApprove => { /* handle acceptance */ },
    _ => { /* other message types */ },
}
```

---

## Address Management — The Critical Part

This is where most bugs happen. The rules:

```
┌─────────── Sending ───────────┐   ┌─────────── Receiving ──────────┐
│                               │   │                                │
│  resolve_send_address(peer)   │   │  Subscribe to:                 │
│    1. ratchet-derived addr    │   │    1. Your nostr npub           │
│    2. peer's firstInbox       │   │    2. All receiving addrs from  │
│    3. peer's nostr npub       │   │       on_encrypt / on_decrypt   │
│                               │   │    3. firstInbox (if sent FR)   │
└───────────────────────────────┘   └────────────────────────────────┘
```

**After every encrypt**: call `addr_mgr.on_encrypt(peer_id, ct.sender_address)` → subscribe to `update.new_receiving`

**After every decrypt**: call `addr_mgr.on_decrypt(peer_id, result.bob_derived_address, result.alice_addrs)` → subscribe to `update.new_receiving`

**When sending**: always use `addr_mgr.resolve_send_address(peer_id)` — never hardcode the peer's npub.

---

## Signal Group (Small, <50 members)

Fan-out encryption: each message is individually encrypted for each member using their 1:1 Signal session.

```rust
use libkeychat::group::*;

// Create group
let group = create_signal_group("My Group", &my_signal_id, &my_npub, "Alice", vec![]);

// Add to manager
let mut gm = GroupManager::new();
gm.add_group(group);

// Invite a peer (sends group info via their 1:1 session)
let event = send_group_invite(&mut peer_signal, &group, &peer_signal_id, &addr_mgr).await?;

// Send message to all members
let mut msg = KCMessage::text("Hello group!");
msg.group_id = Some(group_id.clone());
let results = send_group_message(&mut peer_signal, &group, &msg, &addr_mgr).await?;
for (_, event) in &results {
    client.send_event(event.clone()).await?;
}

// Leave, dissolve, rename...
send_group_self_leave(&mut signal, &group, &addr_mgr).await?;
send_group_dissolve(&mut signal, &group, &addr_mgr).await?;
send_group_name_changed(&mut signal, &group, "New Name", &addr_mgr).await?;
```

## MLS Group (Large)

Uses OpenMLS (RFC 9420) for scalable group encryption. One ciphertext for the whole group.

```rust
use libkeychat::mls::*;

let mut mls = MlsParticipant::new(my_npub);

// Create group
mls.create_group("group-id", "My MLS Group")?;

// Publish KeyPackage (kind:10443) for others to add you
let kp = mls.generate_key_package()?;
let event = publish_key_package(&kp)?;
client.send_event(event).await?;

// Add member (need their KeyPackage)
let (commit, welcome) = mls.add_member("group-id", key_package)?;
// Broadcast commit to existing members, send welcome to new member

// Send message
let msg = KCMessage::text("Hello MLS!");
let inbox = mls.derive_temp_inbox("group-id")?;
let event = send_mls_message(&mls, "group-id", &msg, &inbox)?;

// Receive
let (plaintext, metadata) = receive_mls_message(&mut mls, "group-id", &ciphertext)?;

// Leave
let commit = mls.leave_group("group-id")?;
```

## Media

```rust
use libkeychat::media::*;

// Encrypt a file
let data = std::fs::read("photo.jpg")?;
let encrypted = encrypt_file(&data);
// encrypted.ciphertext, encrypted.key, encrypted.iv

// Build message (upload encrypted data somewhere, pass URL)
let msg = build_file_message(
    "https://cdn.example.com/abc123",  // URL to encrypted blob
    FileCategory::Image,
    Some("image/jpeg"),
    data.len() as u64,
    &encrypted,
);

// Voice message
let msg = build_voice_message(
    "https://cdn.example.com/voice123",
    data.len() as u64,
    5.2,       // duration in seconds
    vec![],    // waveform samples
    &encrypted,
);

// Decrypt received file
let plaintext = decrypt_file(&encrypted_data, &key, &iv)?;
```

## Payment

```rust
use libkeychat::payment::*;

// Cashu ecash
let msg = build_cashu_message("https://mint.example", "cashuABC...", 1000, Some("sat"), None);

// Lightning invoice
let msg = build_lightning_message("lnbc10u1p...", 1000, None);

// Validate cashu token format
validate_cashu_token("cashuABC...")?;
```

## Persistent Storage (SQLCipher)

```rust
use libkeychat::storage::SecureStorage;

let db = SecureStorage::open("/path/to/keychat.db", "encryption-key")?;

// Signal sessions
db.save_session("peer_signal_id", 1, &session_bytes)?;
let session = db.load_session("peer_signal_id", 1)?;

// PreKeys
db.save_pre_key(1, &prekey_bytes)?;
db.save_signed_pre_key(1, &signed_bytes)?;
db.save_kyber_pre_key(1, &kyber_bytes)?;

// Peer addresses (serialize AddressManager state)
db.save_peer_addresses("peer_id", &PeerAddressStateSerialized { ... })?;
let all = db.load_all_peer_addresses()?;

// Event deduplication
if !db.is_event_processed("event_id_hex")? {
    db.mark_event_processed("event_id_hex")?;
    // process event...
}

// Peer directory
db.save_peer_mapping("nostr_pubkey", "signal_id", "Display Name")?;
let peers = db.list_peers()?;
```

---

## Common Mistakes

### ❌ Using `identity_public_key_hex()` as peer's signal ID
```rust
// WRONG — this is YOUR signal identity, not the peer's
let peer_signal_id = accepted.signal_participant.identity_public_key_hex();

// RIGHT — use the payload from the friend request
let peer_signal_id = fr.payload.signal_identity_key.clone();
```

### ❌ Sending to random/npub address
```rust
// WRONG — nobody is listening on a random address
let to = Keys::generate().public_key().to_hex();
send_encrypted_message(&mut signal, &addr, &msg, &to).await?;

// WRONG — only works if peer subscribes to their npub (not guaranteed)
send_encrypted_message(&mut signal, &addr, &msg, &peer_npub).await?;

// RIGHT — let AddressManager resolve the correct address
let to = addr_mgr.resolve_send_address(&peer_signal_id)?;
```

### ❌ Using `encrypt_bytes()` instead of `encrypt()` and losing address info
```rust
// WRONG — encrypt_bytes() discards ratchet addresses, you'll lose track of receiving addresses
let ct = signal.encrypt_bytes(&addr, &plaintext)?;

// RIGHT — encrypt() returns SignalCiphertext with address info
let ct = signal.encrypt(&addr, &plaintext)?;
let update = addr_mgr.on_encrypt(&peer_id, ct.sender_address.as_deref())?;
for a in &update.new_receiving { subscribe(&client, a).await; }
```

> `encrypt_bytes()`/`decrypt_bytes()` exist only for tests that don't need address tracking.
> Production code should always use `encrypt()`/`decrypt()`.

### ❌ Not handling PreKey acceptance response
After sending a friend request, the acceptance comes as a Mode 1 PreKey message on your `firstInbox`. You must:
1. Subscribe to `firstInbox` address
2. Detect PreKeySignalMessage in incoming events
3. Extract sender identity from it
4. Decrypt with the SignalParticipant from `send_friend_request`
5. Upgrade from pending to active peer

### ❌ Using the same Nostr keypair as event sender
```rust
// WRONG — reveals your identity in the event
let event = EventBuilder::new(Kind::GiftWrap, &content)
    .sign(my_identity.keys()).await?;

// RIGHT — ephemeral sender per message (metadata protection)
let sender = EphemeralKeypair::generate();
let event = EventBuilder::new(Kind::GiftWrap, &content)
    .sign(sender.keys()).await?;
```

---

## KCMessage v2 Kinds

| Kind | Description | Key Fields |
|------|-------------|------------|
| `text` | Text message | `text.content` |
| `friendRequest` | Add contact request | `friendRequest.*` (Signal keys, globalSign) |
| `friendApprove` | Accept contact | `friendApprove.requestId` + `signalPrekeyAuth` |
| `friendReject` | Reject contact | `friendReject.requestId` |
| `file` | File transfer | `files.items[]` (url, category, size, encryption key/iv) |
| `groupInvite` | Signal group invite | `group_id` + `roomProfile` |
| `groupDissolve` | Dissolve group | `group_id` |
| `groupNameChanged` | Rename group | `group_id` + new name |
| `groupMemberRemoved` | Remove member | `group_id` + removed member |
| `selfLeave` | Leave group | `group_id` |

## API Reference

### Identity
| Function | Description |
|----------|-------------|
| `Identity::generate()` | New BIP-39 identity |
| `Identity::from_mnemonic_str(words)` | Restore identity |
| `identity.keys()` | Nostr Keys |
| `identity.pubkey_hex()` | Nostr pubkey hex |
| `identity.mnemonic()` | BIP-39 mnemonic |

### Friend Request Flow
| Function | Description |
|----------|-------------|
| `send_friend_request(identity, peer_npub, name, device)` | Send (Mode 2 Gift Wrap) |
| `receive_friend_request(identity, event)` | Parse incoming |
| `accept_friend_request(identity, fr, name)` | Accept (Mode 1 PreKey) |

### Messaging
| Function | Description |
|----------|-------------|
| `send_encrypted_message(signal, addr, msg, to)` | Encrypt + build Mode 1 event |
| `receive_encrypted_message(signal, addr, event)` | Decrypt Mode 1 event |
| `KCMessage::text(content)` | Build text message |
| `KCMessage::try_parse(json)` | Parse JSON to KCMessage |
| `KCMessage::to_json()` | Serialize to JSON |

### Signal
| Function | Description |
|----------|-------------|
| `SignalParticipant::new(id, device)` | New participant with PQXDH keys |
| `signal.encrypt(addr, data)` | Encrypt → `SignalCiphertext` (bytes + addresses) |
| `signal.decrypt(addr, data)` | Decrypt → `SignalDecryptResult` (plaintext + addresses) |
| `signal.encrypt_bytes(addr, data)` | Encrypt → bytes only (tests, no address info) |
| `signal.decrypt_bytes(addr, data)` | Decrypt → plaintext only (tests, no address info) |
| `SignalParticipant::is_prekey_message(bytes)` | Detect PreKey message |
| `signal.process_prekey_bundle(addr, bundle)` | X3DH/PQXDH handshake |

### Address Management
| Function | Description |
|----------|-------------|
| `AddressManager::new()` | New manager |
| `addr_mgr.add_peer(id, first_inbox, npub)` | Register peer |
| `addr_mgr.on_encrypt(id, sender_addr)` | Post-encrypt update |
| `addr_mgr.on_decrypt(id, bob_addr, alice_addrs)` | Post-decrypt update |
| `addr_mgr.resolve_send_address(id)` | Get correct send address |

### Storage
| Function | Description |
|----------|-------------|
| `SecureStorage::open(path, key)` | Open SQLCipher DB |
| `db.save_session / load_session` | Signal session CRUD |
| `db.save_peer_mapping / list_peers` | Peer directory |
| `db.mark_event_processed / is_event_processed` | Dedup |
| `db.save_peer_addresses / load_all_peer_addresses` | Address state |

---

## Cargo.toml Template

```toml
[dependencies]
libkeychat = { git = "https://github.com/keychat-io/libkeychat" }
libsignal-protocol = { git = "https://github.com/nickolay/libsignal", path = "rust/protocol" }
tokio = { version = "1", features = ["full"] }
nostr = { version = "0.37", features = ["nip44"] }
nostr-sdk = "0.37"
base64 = "0.22"
hex = "0.4"
serde_json = "1"
```

## Further Reading

- [Keychat Protocol Spec v2](../keychat-protocol-spec-v2.md) — full protocol specification
- [keychat-cli source](../keychat-cli/src/) — reference client implementation
- [libkeychat-interop](../libkeychat-interop/) — cross-implementation network tests
