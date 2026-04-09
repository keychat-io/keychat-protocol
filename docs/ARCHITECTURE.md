# Keychat Protocol — Architecture

## Overview

Keychat Protocol is a Rust workspace containing four crates, organized in three layers. The design goal is to let any type of client — from a full-featured mobile app to a headless agent — reuse the exact protocol logic it needs, without pulling in unnecessary dependencies.

```
┌──────────────────────────────────────────────────────────────┐
│                        libkeychat                            │
│                  (protocol primitives + orchestration)        │
│                                                              │
│  Rust API          C ABI (ffi.rs)         UniFFI interface   │
│    │                    │                      │             │
└────┼────────────────────┼──────────────────────┼─────────────┘
     │                    │                      │
     │                    │               ┌──────┴───────┐
     │                    │               │keychat-uniffi │
     │                    │               │ (thin FFI     │
     │                    │               │  annotations) │
     │                    │               └──────┬───────┘
     │                    │                      │
     ▼                    ▼                      ▼
  Rust               C / C++              Swift (official)
  (keychat-cli,      Go (cgo)             Kotlin (official)
   agents)           Zig                  Python (official)
                     Dart (FFI)           Ruby (official)
                     any language          C# (third-party)
                     with C FFI           ...
```

Three integration paths, covering all programming languages:

- **Rust API** — direct crate dependency, zero overhead
- **C ABI** — `ffi.rs` + `libkeychat.h`, usable from almost any language
- **UniFFI** — generates native-style bindings (Swift, Kotlin, Python, Ruby)

## Crate Dependency Graph

```
Swift / Kotlin App (UI)
       │
keychat-uniffi        (~2,500 lines, thin UniFFI annotations + type conversion)
       │
keychat-app-core      (~6,500 lines, shared app data layer)
       │
libkeychat            (~17,800 lines, protocol primitives + orchestration + C ABI)
```

- **keychat-cli** depends on `libkeychat` + `keychat-app-core` directly (no UniFFI overhead).
- A lightweight agent can depend on `libkeychat` alone (skip app-core entirely).

## Crate Details

### libkeychat (~17,800 lines)

Core protocol implementation. Every client — mobile app, CLI, agent — depends on this crate.

**Protocol Primitives**

| File | Lines | Content |
|------|------:|---------|
| identity.rs | 297 | BIP-39 mnemonic, Nostr keypair generation (NIP-06) |
| signal_keys.rs | 665 | Signal key generation (PQXDH key bundles) |
| signal_session.rs | 897 | X3DH key exchange, Double Ratchet encryption/decryption |
| signal_store.rs | 433 | In-memory Signal protocol stores |
| persistent_signal_store.rs | 481 | SQLite-backed persistent Signal stores |
| session.rs | 436 | ChatSession: Signal session + address rotation |
| nip44.rs | 117 | NIP-44 authenticated encryption |
| giftwrap.rs | 251 | NIP-17 three-layer gift wrapping |
| message.rs | 883 | KCMessage v2 with typed payloads |
| address.rs | 1,225 | Per-peer ratchet-derived address tracking, sliding window |
| chat.rs | 1,165 | Send/receive encrypted messages (Mode 1) |
| friend_request.rs | 616 | Friend request protocol (send/receive/accept) |
| group.rs | 1,531 | Signal-based small group (fan-out) |
| mls.rs | 1,300 | MLS large group messaging (RFC 9420) |
| mls_extension.rs | 302 | OpenMLS custom extensions |
| mls_provider.rs | 83 | OpenMLS crypto provider |
| media.rs | 421 | AES-256-CTR file encryption/decryption |
| transport.rs | 769 | Nostr relay connectivity, subscriptions, publishing |
| storage.rs | 2,230 | SQLite persistence (protocol-level data) |
| payment.rs | 169 | Cashu ecash, Lightning invoice parsing |
| stamp.rs | 716 | Relay fee checking, ecash stamp creation |
| error.rs | 84 | `KeychatError` enum |

**Protocol Orchestration** — `orchestrator.rs` (1,964 lines)

The orchestrator is the high-level API that all clients use. It provides:

- **`ProtocolClient`** — multi-session state management (sessions HashMap, peer-to-signal/signal-to-peer bidirectional mapping, receiving-address-to-peer routing index, `restore_sessions`)
- **Event loop core** — receive GiftWrap → deduplicate → try decrypt route (friend request → approve → session message) → update addresses → notify upper layer via trait callback
- **Message sending core** — find session → encrypt → build Nostr event → publish to relay → update address index
- **Subscription address collection** — aggregate all receiving addresses for relay subscriptions
- **`OrchestratorDelegate` trait** — callback interface for notifying upper layers (app persistence, UI) without depending on them

**C ABI** — `ffi.rs` (642 lines) + `include/libkeychat.h`

Exposes an opaque `KeychatContext` with C-callable functions:

| Function | Purpose |
|----------|---------|
| `keychat_init` / `keychat_init_generate` | Initialize from mnemonic or generate new identity |
| `keychat_destroy` | Clean up context |
| `keychat_get_pubkey` | Get Nostr public key (hex) |
| `keychat_send_friend_request` | Send friend request → returns event JSON + firstInbox |
| `keychat_receive_friend_request` | Receive and auto-accept friend request |
| `keychat_send_text` | Encrypt and send text → returns event JSON + new addresses |
| `keychat_receive_event` | Decrypt received event → returns plaintext + sender |
| `keychat_list_peers` | JSON array of known peers |
| `keychat_resolve_send_address` | Get current sending address for a peer |
| `keychat_fetch_relay_info` | NIP-11 relay info |
| `keychat_check_relay_fee` | Check ecash stamp requirements |
| `keychat_free_string` / `keychat_free_buffer` | Memory management |

Build outputs: `libkeychat.dylib` / `libkeychat.so` / `libkeychat.a` (crate-type: `lib`, `cdylib`, `staticlib`).

---

### keychat-app-core (~6,500 lines)

Shared application data layer for all UI clients (Swift app, Kotlin app, keychat-cli daemon). Provides message history, room management, contact storage, and relay tracking — logic that every "app with a UI" needs, written once in Rust.

| File | Lines | Content |
|------|------:|---------|
| app_client.rs | 1,146 | `AppClient`: composes `ProtocolClient` + `AppStorage` + `RelaySendTracker` |
| app_storage.rs | 1,455 | SQLCipher persistence (rooms, messages, contacts, attachments, settings) |
| event_loop.rs | 1,091 | App-level event loop: receive events → write app_storage → update rooms → notify UI |
| relay_tracker.rs | 675 | `RelaySendTracker`: track which relays accepted/rejected each published event |
| data_store.rs | 238 | In-memory cache layer wrapping app_storage |
| types.rs | 471 | Room, Message, Contact, Group, RoomStatus, MessageStatus, DataChange, etc. |
| messaging.rs | 392 | App-level message sending (protocol send + DB write + UI notification) |
| media.rs | 436 | File upload/download, encryption/decryption routing (Blossom HTTP) |
| friend_request.rs | 194 | App-level friend request handling (protocol + DB + UI notification) |
| group.rs | 387 | App-level group management (protocol + DB + UI notification) |

`AppClient` implements the `OrchestratorDelegate` trait from libkeychat, bridging protocol events to app-layer persistence and UI notifications.

---

### keychat-uniffi (~2,500 lines)

Thin UniFFI annotation layer. Contains no business logic — only `#[uniffi::export]` annotations, UniFFI Record/Enum definitions, and `From` conversions between app-core types and UniFFI-compatible types.

| File | Lines | Content |
|------|------:|---------|
| client.rs | 911 | `KeychatClient` (Arc-wrapped `AppClient`), UniFFI-exported methods |
| types.rs | 488 | UniFFI Record/Enum definitions, `From` conversions |
| data_store.rs | 377 | UniFFI wrapper around `keychat-app-core::DataStore` |
| media.rs | 175 | File operations with UniFFI annotations |
| group.rs | 126 | Group operations with UniFFI annotations |
| error.rs | 116 | `KeychatUniError` enum with UniFFI derive |
| address.rs | 95 | Address types with UniFFI annotations |
| lib.rs | 71 | scaffolding + utility functions (npub/hex conversion) |
| messaging.rs | 65 | Message sending with UniFFI annotations |
| friend_request.rs | 55 | Friend request operations with UniFFI annotations |
| event_loop.rs | 51 | Event loop integration with UniFFI annotations |
| app_storage.rs | 2 | Re-export from keychat-app-core |
| relay_tracker.rs | 2 | Re-export from keychat-app-core |

Build output: XCFramework for iOS (via `build-xcframework.sh`), Kotlin bindings for Android.

---

### keychat-cli

Terminal client with multiple modes: TUI (ratatui), interactive REPL, HTTP daemon, and AI agent daemon. Depends on `libkeychat` + `keychat-app-core` directly — no UniFFI overhead.

---

## Usage Paths

| Consumer | Depends on | Notes |
|----------|-----------|-------|
| **iOS / Android app** | libkeychat → keychat-app-core → keychat-uniffi | Full stack, UniFFI-generated Swift/Kotlin bindings |
| **keychat-cli** | libkeychat → keychat-app-core | Direct Rust API, no FFI overhead |
| **Lightweight agent** | libkeychat only | No storage, no UI — protocol primitives + orchestrator |
| **C/C++/Go/Zig client** | libkeychat (C ABI) | Via `libkeychat.h` and dynamic/static library |
| **Python/Ruby script** | libkeychat → keychat-uniffi | UniFFI-generated native bindings |

## Lock Ordering

When multiple locks are held concurrently (in `AppClient`):

1. `inner: RwLock<AppClientInner>` — outermost
2. `inner.protocol.storage: Mutex<SecureStorage>`
3. `inner.app_storage: Mutex<AppStorage>`
4. `inner.protocol.sessions[*]: tokio::Mutex<ChatSession>` — per-peer
5. `relay_tracker: Mutex<RelaySendTracker>`

Rules:
- Never hold a higher-numbered lock when acquiring a lower-numbered one.
- Drop `RwLock` guards before any `.await` that acquires session mutexes.
- Clone `Arc<Mutex<...>>` out of the guard, drop the guard, then lock.
