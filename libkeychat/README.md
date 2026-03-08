# libkeychat

A Rust implementation of the Keychat protocol — sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption.

## Features

- **Identity**: BIP-39 mnemonic → deterministic Nostr secp256k1 keypair (NIP-06)
- **Signal Crypto**: Per-peer disposable Signal sessions, Double Ratchet encryption
- **Nostr Transport**: Multi-relay WebSocket connections with concurrent publish, auto-reconnect, subscription management
- **Hello Protocol**: Add-friend flow with NIP-17 Gift Wrap (kind:1059), X3DH key exchange
- **Messaging**: Signal-encrypted kind:4 events, ephemeral sender keypairs, ratchet-derived addresses
- **Address Management**: Automatic `my_inbox` / `peer_inbox` rotation with Signal ratchet advancement
- **Small Groups**: Signal-based fan-out encryption with group management (invite, remove, rename, dissolve)
- **MLS Large Groups**: OpenMLS-based group messaging with NIP-44 transport encryption, listen key rotation, and commit/application message handling
- **Media**: AES-256-CTR + PKCS7 encryption, S3 relay / Blossom upload, Keychat media URL format
- **Client API**: Unified `KeychatClient` entry point — init, add friend, send message/media, listen for events
- **Storage**: In-memory (testing) and SQLite (production) backends via trait abstraction

## Architecture

```
┌─────────────────────────┐
│   Protocol Layer        │  Hello flow / address mgmt / message routing
├─────────────────────────┤
│   Crypto Layer          │  Signal (libsignal) / NIP-04 / NIP-17 (NIP-44 + NIP-59)
├─────────────────────────┤
│   Transport Layer       │  Multi-relay WebSocket / concurrent publish / 10s ack timeout
├─────────────────────────┤
│   Storage Layer         │  SQLite (default) / trait-based abstraction
├─────────────────────────┤
│   Identity Layer        │  BIP-39 mnemonic → Nostr keypair (root of trust)
└─────────────────────────┘
```

## Quick Start

### Using the Client API

```rust
use libkeychat::client::{KeychatClient, ClientConfig, InboundEvent};

#[tokio::main]
async fn main() {
    let config = ClientConfig {
        db_path: "keychat.db".into(),
        display_name: "Alice".into(),
        relays: vec!["wss://relay.damus.io".into()],
        mnemonic: None, // generates new identity
    };
    let mut client = KeychatClient::init(config).await.unwrap();
    println!("My npub: {}", client.npub().unwrap());

    // Start listening for messages
    client.start_listening().await.unwrap();

    // Add a friend
    client.add_friend("npub1...", "Hi!").await.unwrap();

    // Process inbound events
    while let Some(event) = client.next_event().await {
        match event {
            InboundEvent::DirectMessage { sender, plaintext, .. } => {
                println!("[DM from {}]: {}", &sender[..12], plaintext);
            }
            InboundEvent::FriendRequest { sender_name, .. } => {
                println!("Friend request from {}", sender_name);
            }
            _ => {}
        }
    }
}
```

### Generate an identity

```bash
cargo run --example interop_test -- generate
```

Outputs mnemonic, npub, nsec, and pubkey hex. State is stored in `interop_test.db`.

### Listen for messages (receive hello + echo reply)

```bash
# Single relay
cargo run --example interop_test -- listen --relay wss://relay.damus.io

# Multiple relays (concurrent publish, best-effort)
cargo run --example interop_test -- listen
```

This will:
1. Subscribe to kind:1059 (Gift Wrap) on your npub for incoming hello requests
2. Auto-accept hello and reply with Signal-encrypted kind:4 message
3. Echo back any received messages
4. Manage ratchet address rotation automatically

### Send a hello (add friend)

```bash
cargo run --example interop_test -- hello <recipient_npub_or_hex>
```

Sends a hello via NIP-17 Gift Wrap, waits for the recipient's reply, then enters echo mode.

### MLS Group Messaging

```bash
# Create a group and invite a peer (by npub or hex pubkey)
cargo run --example interop_test -- mls-create-invite <peer_npub> --relay wss://relay.keychat.io

# Join a group and listen (used by invited peer)
cargo run --example interop_test -- mls-join-and-listen --relay wss://relay.keychat.io
```

The `mls-create-invite` command:
1. Fetches the peer's KeyPackage from relay
2. Creates an MLS group and adds the peer
3. Sends a Welcome message via NIP-59 Gift Wrap (kind:1059, inner kind:444)
4. Listens for commits and application messages with listen key rotation
5. Echoes received messages back

### MLS E2E Relay Test

```bash
# Full Alice→Bob MLS test through a real relay (no external peers needed)
cargo run --example mls_relay_test -- --relay wss://relay.damus.io
```

### Small Group Interop Test

```bash
# Create a group, invite a Keychat app user, exchange group messages
cargo run --example group_interop_test -- --peer <npub_or_hex>
```

The test:
1. Sends a hello (friend request) and waits for acceptance
2. Creates a sendAll small group and invites the peer
3. Waits for the peer's group messages
4. Sends a group message and waits for the reply

### Send a One-Off Message

```bash
# Restore an existing session and send a single message
cargo run --example send_once -- --peer <hex> --db <path> --mnemonic "<words>" --msg "Hello!"
```

### Echo Bot

```bash
# Auto-accept friends and echo back every message
cargo run --example echo_bot -- --name "My Bot" --db bot.db
```

### Group Management Test

```bash
# Test rename and dissolve operations against a real peer
cargo run --example group_mgmt_test -- --peer <npub> --db <path> --mnemonic "<words>"
```

### Media Receive Test

```bash
# Listen for incoming media messages, download and decrypt
cargo run --example media_recv_test -- --db <path> --mnemonic "<words>"
```

## Interop with Keychat App

libkeychat is fully interoperable with the [Keychat](https://keychat.io) mobile app.

### Verified Interop Scenarios

| Scenario | Status | Notes |
|----------|--------|-------|
| 1:1 Hello (add friend) | ✅ Verified | Both directions: libkeychat→app and app→libkeychat |
| 1:1 Signal DM | ✅ Verified | Bidirectional, ratchet address rotation works |
| Small group create + invite | ✅ Verified | libkeychat creates group, app user joins via invite |
| Small group bidirectional messaging | ✅ Verified | Fan-out encryption, both sides receive messages |
| Small group management (rename/dissolve) | ✅ Verified | Sent to app peer, clean session |
| Media send (image) | ✅ Verified | PKCS7 + base64, S3 relay upload, agent downloaded |
| MLS large group | ✅ Verified | Bidirectional with Keychat OpenClaw agent |

### Quick Start

1. Generate identity with `interop_test generate`
2. Share your npub with the Keychat app user (or scan QR)
3. Run `interop_test listen`
4. App user adds your npub as a contact
5. libkeychat auto-accepts and establishes a bidirectional Signal session
6. Messages flow both ways with full E2E encryption

## Protocol Specification

See [SPEC.md](SPEC.md) for the complete protocol specification, including:
- Identity derivation (NIP-06)
- Signal session lifecycle
- Hello (add-friend) protocol
- Address management and ratchet rotation
- Message format (KeychatMessage JSON + plain text fallback)
- Known pitfalls and lessons learned

## Project Structure

```
src/
├── identity/       BIP-39 mnemonic, Nostr keypair derivation, bech32 encoding
├── signal/         Signal Protocol wrapper (encrypt/decrypt, session management)
│   ├── mod.rs      SignalParticipant — high-level Signal API
│   ├── keys.rs     PreKey material generation
│   ├── session_store.rs  CapturingSessionStore (tracks bobAddress from ratchet)
│   └── store.rs    Store trait definitions
├── nostr/          NIP-04, NIP-44, NIP-59 (Gift Wrap) implementations
├── protocol/       Hello flow, messaging, address management, message types
│   ├── hello.rs    create_hello / receive_hello
│   ├── messaging.rs  send/receive Signal-encrypted messages
│   ├── address.rs  AddressManager + generate_seed_from_ratchetkey_pair
│   └── message_types.rs  KeychatMessage, QRUserModel, PrekeyMessageModel
├── media/          AES-256-CTR + PKCS7 encryption, S3/Blossom upload, media URL format
├── client/         Unified KeychatClient API (init, friends, messaging, events)
│   ├── mod.rs      KeychatClient struct + all public methods
│   └── types.rs    ClientConfig, InboundEvent
├── group/          Signal-based small group support (fan-out encryption)
│   ├── mod.rs      Create/invite/message/manage groups, parse inbound events
│   └── types.rs    GroupProfile, GroupEvent, GroupMember, event kind constants
├── mls/            MLS large group support (OpenMLS)
│   ├── mod.rs      Public API (init, create, join, encrypt, decrypt, process)
│   ├── group.rs    MlsManagedUser — group lifecycle, commit processing
│   ├── transport.rs  NIP-44 encrypted relay send/receive for MLS messages
│   └── types.rs    Result types (ProcessedMlsMessage, CommitResult, etc.)
├── transport/      Nostr relay WebSocket connections
│   ├── mod.rs      RelayPool (multi-relay, concurrent publish)
│   └── relay.rs    RelayConnection (single relay, reconnect, ack timeout)
├── storage/        Persistence backends
│   ├── memory.rs   In-memory (testing)
│   └── sqlite.rs   SQLite (production)
└── error.rs        Error types
```

## Dependencies

- **libsignal-protocol**: Keychat's fork with extended `store_session` API (ratchet address tracking)
- **nostr**: NIP-44 encryption support
- **tokio + tokio-tungstenite**: Async WebSocket relay connections
- **rusqlite**: SQLite storage backend
- **bip39 + bitcoin**: BIP-39 mnemonic and BIP-32 HD key derivation
- **reqwest**: HTTP client for media upload (S3 relay + Blossom)
- **aes + ctr**: AES-256-CTR encryption for media files
- **openmls**: MLS group messaging (Keychat's `kc4` fork)

## License

MIT
