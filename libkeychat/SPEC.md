# libkeychat Protocol Specification

> This document is the authoritative specification for libkeychat. It is continuously updated as implementation progresses and bugs are discovered. All implementations MUST conform to this spec.

**Version**: 0.4.0-draft
**Last Updated**: 2026-03-04

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Identity Layer](#3-identity-layer)
4. [Signal Crypto Layer](#4-signal-crypto-layer)
5. [Nostr Transport Layer](#5-nostr-transport-layer)
6. [Add-Friend (Hello) Protocol](#6-add-friend-hello-protocol)
7. [Message Format](#7-message-format)
8. [Address Management](#8-address-management)
9. [PreKey Message Handling](#9-prekey-message-handling)
10. [Media & File Transfer](#10-media--file-transfer)
11. [Small Groups (Signal-based)](#11-small-groups-signal-based)
12. [Ecash Stamps](#12-ecash-stamps)
13. [Large Groups (MLS)](#13-large-groups-mls)
14. [Cryptographic Primitives Reference](#14-cryptographic-primitives-reference)
15. [Storage](#15-storage)
16. [Appendix: Known Pitfalls](#appendix-known-pitfalls)

---

## Naming Conventions

All address-related terms in this spec use a consistent naming scheme. The prefix indicates **whose** address, and the suffix indicates **purpose**.

| Name | Storage | Direction | Meaning |
|------|---------|-----------|---------|
| `peer_inbox` | DB `peer_mapping` column | **Outbound** (I send TO here) | The address I send messages to for this peer. Updated from `session.bobAddress` after every decrypt via `generate_seed_from_ratchetkey_pair`. |
| `my_inbox` | DB `my_inboxes` rows | **Inbound** (I receive FROM here) | My receiving addresses. Each peer has up to N (default 3). Derived from ratchet after encrypt/decrypt. |
| `my_new_inbox` | encrypt return value | **Inbound** (new) | A ratchet key pair seed returned by encrypt. Must be derived via `generate_seed_from_ratchetkey_pair`, then added to `my_inbox` list + subscribed on relay. |
| `my_first_inbox` | `send_hello` return | **Inbound** (one-time) | My onetimekey — a random Nostr pubkey I generate during Hello. Peer's first reply arrives here. Discarded after use. |
| `peer_first_inbox` | DB `peer_mapping` column | **Outbound** (one-time) | Peer's onetimekey — from their QRUserModel. I send my first message here. Cleared to NULL after use. |
| `arrived_at` | InboundMessage field | **Inbound** | Which of my `my_inbox` addresses this message was delivered to. Used to route to the correct peer. |
| `my_signal_key` | DB `peer_mapping` column | — | My per-peer Signal identity pubkey (curve25519). Generated fresh for each peer relationship. |
| `peer_signal_key` | DB `peer_mapping` column | — | Peer's Signal identity pubkey (curve25519). From their QRUserModel. |

**Key rule**: `peer_*` = their address (I send to). `my_*` = my address (I receive on). Never cross these.

### Sending Runtime Variables

These are per-message transient values, not persisted:

| Name | Scope | Meaning |
|------|-------|---------|
| `dest_pubkey` | send_message | Final resolved sending target. Result of the 3-level fallback: `peer_inbox ?? peer_first_inbox ?? peer_nostr_pubkey`. This becomes the p-tag of the kind:4 event. |
| `receiver_pubkeys` | send_message | The p-tag list of the kind:4 event. Currently `[dest_pubkey]` (single element). Reserved as `Vec` for future dual p-tag support (e.g., public-service agents: `[agent_npub, ratchet_addr]`). |
| `ephemeral_sender` | send_message | A random one-time Nostr keypair (`Keys::generate()`) used as the event's `pubkey` field. Generated fresh for **every** message. NOT the sender's main Nostr identity. Purpose: metadata minimization — relay observers cannot link messages to a specific sender. |

---

## 1. Overview

libkeychat is a Rust library implementing the Keychat protocol — a sovereign, end-to-end encrypted messaging protocol built on Signal Protocol encryption over Nostr relay transport.

**Core principles:**
- Nostr identity (secp256k1) is the long-term identity
- Signal Protocol is purely an encryption engine (disposable keys per relationship)
- Nostr relays are the transport layer (replaceable, no single point of failure)
- Every message uses a random ephemeral Nostr sender keypair (metadata minimization)
- Receiving addresses (`my_inbox`) are derived from Signal ratchet keys (unlinkable)

**Target platforms:**
- Native (iOS, Android, Desktop) via FFI
- Node.js via N-API binding
- WASM via wasm-bindgen (I/O layer adapted separately)

---

## 2. Architecture

```
┌─────────────────────────┐
│   Application API       │  KeychatClient / high-level methods
├─────────────────────────┤
│   Protocol Layer        │  Hello flow / address mgmt / message routing
├─────────────────────────┤
│   Crypto Layer          │  Signal (libsignal) / NIP-04 / NIP-17 (NIP-44 + NIP-59)
├─────────────────────────┤
│   Transport Layer       │  Nostr relay connections / event pub-sub
├─────────────────────────┤
│   Storage Layer         │  SQLite (default) / trait-based abstraction
├─────────────────────────┤
│   Identity Layer        │  Mnemonic → Nostr keypair (root of trust)
└─────────────────────────┘
```

**Dependency direction**: Each layer depends only on layers below it. Identity is the root — it depends on nothing.

---

## 3. Identity Layer

### 3.1 Nostr Identity (Long-term)

The user's permanent identity is a Nostr secp256k1 keypair derived from a BIP-39 mnemonic.

**Derivation (NIP-06):**

```
BIP-39 mnemonic (12 or 24 words)
    ↓ mnemonic.to_seed("")  (empty passphrase by default)
    ↓ BIP-32 HD key derivation
    ↓ Path: m/44'/1237'/{account}'/0/0
    ↓     coin_type = 1237 (Nostr, per NIP-06)
    ↓     account = 0 (default), supports multi-account
    ↓
secp256k1 private key (32 bytes)
    ↓
secp256k1 public key → x-only (Schnorr) = Nostr pubkey (32 bytes)
```

**Encoding:**
- `npub1...` — bech32-encoded x-only public key (NIP-19)
- `nsec1...` — bech32-encoded secret key (NIP-19)
- Hex — 64-character lowercase hex string of x-only public key

**⚠️ CRITICAL**: MUST use BIP-32 derivation with path `m/44'/1237'/0'/0/0`. Do NOT use SHA-256 hashing of the seed. Do NOT use coin type 1238 (that was for a legacy Signal key derivation path, now obsolete).

**Multi-account**: Different accounts use different `account` index in the path. Account 0 is the default. Same mnemonic + different account → different Nostr identity.

### 3.2 Signal Identity (Disposable, Per-Relationship)

In Keychat, Signal Protocol keypairs are **one-time-use**. A fresh curve25519 identity keypair is generated randomly (`OsRng`) for each new contact relationship (each "add friend" operation). This per-peer Signal keypair is stored as `my_signal_key` in the peer mapping.

This is a key design difference from standard Signal:
- **Standard Signal**: Signal identity key is permanent, tied to your phone number
- **Keychat**: Signal identity key is ephemeral, tied to a specific peer relationship

**Implications:**
- Compromising one Signal session does not affect other relationships
- No "Signal fingerprint" verification needed (identity verified via Nostr signature / `globalSign`)
- Signal is purely an encryption engine, identity is handled by Nostr layer

### 3.3 SecretStore Trait

Mnemonic storage is platform-specific and abstracted via trait:

```rust
pub trait SecretStore: Send + Sync {
    fn save_mnemonic(&self, account_id: &str, mnemonic: &str) -> Result<()>;
    fn load_mnemonic(&self, account_id: &str) -> Result<Option<String>>;
    fn delete_mnemonic(&self, account_id: &str) -> Result<()>;
}
```

Platform implementations (NOT in libkeychat core):
- iOS/macOS → Keychain Services
- Android → Android Keystore
- Desktop/Server → encrypted file or OS keyring
- WASM/Browser → Web Crypto API + IndexedDB

---

## 4. Signal Crypto Layer

### 4.1 Key Generation

For each new peer relationship, generate:

1. **Signal Identity Keypair** (`my_signal_key`): `IdentityKeyPair::generate(&mut OsRng)`
   - curve25519 keypair, random, disposable
2. **Signed PreKey**: `KeyPair::generate(&mut OsRng)`
   - Signed with the Signal identity key
   - ID: random u32
3. **One-time PreKey**: `KeyPair::generate(&mut OsRng)`
   - ID: random u32
   - Used once during X3DH, then discarded

### 4.2 Session Establishment (X3DH)

When Alice wants to communicate with Bob:

1. Alice generates her Signal key set (`my_signal_key` + signed prekey + one-time prekey)
2. Alice sends her key material to Bob via the Hello protocol (§6)
3. Bob receives Alice's keys (`peer_signal_key`), calls `process_prekey_bundle()` to establish a Signal session
4. Bob can now encrypt messages to Alice
5. Alice receives Bob's first message (PreKey message), completes session establishment

### 4.3 Message Encryption

```
plaintext (UTF-8 string)
    ↓ encrypt_signal(plaintext, remote_address)
    ↓ Double Ratchet encryption
    ↓
SignalMessage or PreKeySignalMessage (binary)
    ↓ base64 encode
    ↓
content field of kind:4 Nostr event

Returns: (ciphertext, my_new_inbox, msg_key_hash, ...)
  my_new_inbox = ratchet key pair seed for new receiving address (may be None)
```

### 4.4 Message Decryption

```
kind:4 Nostr event content (base64 string)
    ↓ base64 decode
    ↓
Signal ciphertext (binary)
    ↓ Detect message type:
    ↓   PreKeySignalMessage::try_from(&bytes).is_ok() → PreKey message
    ↓   Otherwise → normal SignalMessage
    ↓ decrypt (with appropriate method)
    ↓
plaintext (UTF-8 string, usually KeychatMessage JSON)

Returns: (plaintext, msg_key_hash, alice_addrs)
  alice_addrs = our new my_inbox seeds (from ratchet advancement)
```

**⚠️ CRITICAL**: Detect PreKey messages using `PreKeySignalMessage::try_from()`, NOT by inspecting `bytes[0]`. The first byte is a protobuf field tag (varies), not a fixed type indicator.

### 4.5 Signal Stores

Signal Protocol requires four persistent stores:

| Store | Purpose |
|-------|---------|
| `IdentityKeyStore` | Our identity keypair + trusted peer identities |
| `SessionStore` | Active Signal sessions (ratchet state) |
| `PreKeyStore` | Unused one-time prekeys |
| `SignedPreKeyStore` | Signed prekeys |

libkeychat provides:
- `CapturingSessionStore` — wraps `InMemSessionStore` to capture `bobAddress` (the peer's ratchet-derived sending address) from `store_session` callbacks. Returns flag ≥ 3 when `alice_addresses` change, enabling `message_encrypt` to return `my_new_inbox`. The captured `bobAddress` is used to derive `peer_inbox` after each decrypt.
- `InMem*Store` — in-memory stores for identity, prekey, signed prekey, kyber prekey, ratchet key
- `SignalParticipant` — high-level wrapper that combines all stores, provides `encrypt_with_metadata` / `decrypt_with_metadata` returning address change information
- State persistence via `SignalParticipantSnapshot` (serializable sessions + keys) stored in SQLite

**Note**: The `CapturingSessionStore` flag values match Keychat's `signal-storage` crate convention: 0 = new session (insert), 1 = record unchanged, 2 = bobAddress updated, 3 = alice_addresses first write, 4 = alice_addresses appended. `message_encrypt` checks `flag >= 3` to decide whether to return `Some(my_new_inbox)`.

---

## 5. Nostr Transport Layer

### 5.1 Event Kinds Used

| Kind | Purpose | Encryption |
|------|---------|-----------|
| **4** | Signal-encrypted DM | Signal Protocol (content = raw base64 ciphertext) |
| **4** | NIP-04 DM (legacy) | NIP-04 (content format: `ciphertext?iv=xxx`) |
| **1059** | Gift Wrap (Hello / MLS) | NIP-44 + NIP-59 |
| **10443** | MLS KeyPackage | None (public) |
| **444** | MLS Welcome | NIP-44 |

### 5.2 Distinguishing kind:4 Messages (CRITICAL)

Kind:4 events carry two completely different encryption types. You MUST distinguish them correctly:

```
if content.contains("?iv=") → NIP-04 (legacy AES-CBC encryption)
    Format: "<base64_ciphertext>?iv=<base64_iv>"
else → Signal Protocol (raw base64 of Signal ciphertext)
    Format: plain base64 string, no "?iv=" substring
```

**⚠️ CRITICAL**: Do NOT attempt NIP-04 decryption on Signal messages or vice versa. The `?iv=` check is the ONLY reliable way to distinguish them. NIP-04 messages have an initialization vector appended with `?iv=` separator; Signal messages are raw base64-encoded Signal Protocol ciphertext with no such marker.

### 5.3 Ephemeral Sender

Every Signal-encrypted message (kind:4) uses a **random, one-time Nostr keypair** as the event sender (`pubkey` field). This is NOT the user's main Nostr identity. Purpose: metadata minimization — observers cannot link messages to a specific sender.

### 5.4 Relay Connection

Implemented in `transport/relay.rs` and `transport/mod.rs`.

**RelayPool** (multi-relay):
- Publish to all relays concurrently (`futures::join_all`), succeed if at least one accepts
- Subscribe/unsubscribe propagated to all relays
- Single event stream aggregated from all relays via `mpsc` channel

**RelayConnection** (single relay):
- Async WebSocket via `tokio-tungstenite`
- NIP-01 protocol: `EVENT`, `REQ`, `CLOSE`, `OK`, `EOSE` handling
- Publish with 10-second ack timeout (prevents blocking on unresponsive relays)
- Auto-reconnect with exponential backoff (1s → 2s → 4s → ... → 30s max)
- Background task communicates with caller via `mpsc` channels
- Event deduplication across relays (caller-side via `BTreeSet<event_id>`)

---

## 6. Add-Friend (Hello) Protocol

### 6.1 Overview

Adding a contact requires exchanging Signal key material via the Hello protocol. This establishes the initial Signal session and the initial address mappings.

### 6.2 QRUserModel

The Hello message contains a `QRUserModel` JSON with all information needed to establish a Signal session:

```json
{
  "name": "<display_name>",
  "pubkey": "<sender_nostr_pubkey_hex>",
  "curve25519PkHex": "<my_signal_key_hex_33bytes>",
  "onetimekey": "<my_first_inbox>",
  "signedId": "<signed_prekey_id>",
  "signedPublic": "<signed_prekey_public_hex>",
  "signedSignature": "<signed_prekey_signature_hex>",
  "prekeyId": "<one_time_prekey_id>",
  "prekeyPubkey": "<one_time_prekey_public_hex>",
  "time": "<unix_timestamp>",
  "globalSign": "<schnorr_signature_of_nostrId+signalId+time>",
  "relay": "",
  "lightning": "",
  "avatar": ""
}
```

**Field mapping to standard naming:**
- `curve25519PkHex` = `my_signal_key` (sender's per-peer Signal identity)
- `onetimekey` = `my_first_inbox` (sender's one-time receiving address)
- From the receiver's perspective: `curve25519PkHex` = `peer_signal_key`, `onetimekey` = `peer_first_inbox`

### 6.3 Scenario A: I Send Hello (Outbound)

**Alice → Bob:**

1. Generate fresh Signal key set: `my_signal_key` + signed prekey + one-time prekey
2. Generate `my_first_inbox` — a random Nostr keypair pubkey. This is where Bob's first reply will arrive.
3. Build QRUserModel JSON (with `onetimekey = my_first_inbox`, `curve25519PkHex = my_signal_key`)
4. Create `globalSign`:
   ```
   message = "Keychat-<alice_nostr_pubkey_hex>-<my_signal_key_hex>-<time>"
   globalSign = schnorr_sign(alice_nostr_private_key, sha256(message))
   ```
5. Wrap as KeychatMessage: `{"c":"signal","type":101,"msg":"Hi...","name":"<QRUserModel JSON>"}`
6. Send via NIP-17 Gift Wrap (kind:1059) to Bob's Nostr pubkey

   **⚠️ CRITICAL**: Do NOT tweak the timestamp (`timestamp_tweaked = false`). NIP-59 allows random timestamp offset (0-2 days in the past) for metadata privacy, but relays filter events by `since`. A tweaked timestamp may cause the event to be invisible to receivers whose subscription started recently.

7. **Subscribe to `my_first_inbox` for Bob's reply** (this is the only address Bob can reply to initially)
8. Create placeholder peer_mapping in DB: `(nostr_pubkey=Bob, peer_signal_key="", my_signal_key=<key>, peer_first_inbox=NULL)`
9. Queue any outbound messages in `pending_hello_messages` — cannot send until session established
10. Set state → `WAIT_ACCEPT`

### 6.4 Scenario A Continued: Receiving Bob's Accept-First (PreKey Message)

After Bob accepts our hello, he sends a kind:4 PreKey message to `my_first_inbox`:

1. Inbound kind:4 arrives on `my_first_inbox` (the `arrived_at` field matches)
2. Detect it's a PreKey message: `PreKeySignalMessage::try_from(ciphertext).is_ok()`
3. Extract `(peer_signal_key, signed_prekey_id)` from the PreKey message
4. Look up our `my_signal_key` via `signed_prekey_id` → identifies which hello this reply belongs to
5. Decrypt using `my_signal_key`'s Signal store: `decrypt_signal(ciphertext, is_prekey=true)`
6. **Update `peer_inbox`** from session's `bobAddress`:
   ```
   bob_address = session.bobAddress
   if bob_address starts with "05":
       // Raw curve25519 pubkey — not a valid Nostr address, skip
       peer_inbox = NULL (will fallback to peer nostr pubkey on next send)
   else:
       peer_inbox = generate_seed_from_ratchetkey_pair(bob_address)
       save peer_inbox to DB
   ```
7. Update peer_mapping: fill in `peer_signal_key`
8. Clear `my_signal_key` private key material from DB (no longer needed after session established)
9. State → `SESSION_ESTABLISHED`
10. Flush `pending_hello_messages` → send each via normal `send_message` flow

### 6.5 Scenario B: I Receive Hello (Inbound)

**Bob → Alice (I am Alice, receiving):**

1. Kind:1059 Gift Wrap arrives on my Nostr pubkey
2. Unwrap: NIP-44 decrypt → Seal → NIP-44 decrypt → Rumor → KeychatMessage (type=101)
3. Parse `km.name` as QRUserModel
4. Verify `globalSign`:
   ```
   message = "Keychat-<qr.pubkey>-<qr.curve25519PkHex>-<qr.time>"
   verify_schnorr(qr.pubkey, qr.globalSign, sha256(message))
   ```
5. Extract from QRUserModel:
   - `peer_signal_key` = `qr.curve25519PkHex` (Bob's Signal identity)
   - `peer_first_inbox` = `qr.onetimekey` (Bob's one-time receiving address — where I send my first reply)
6. Generate my `my_signal_key` for this peer
7. Call `process_prekey_bundle(peer_signal_key, signedPreKey, oneTimePreKey)` → Signal session established
8. Save peer_mapping: `(nostr_pubkey=Bob, peer_signal_key, my_signal_key, peer_first_inbox)`
9. **Send accept-first reply** (see §6.6)

### 6.6 Sending Accept-First Reply

After establishing the Signal session from an inbound hello:

1. Determine destination address using the **3-level fallback chain** (§8.3):
   - `peer_inbox` → empty (new session, no decrypt yet) → skip
   - `peer_first_inbox` → Bob's onetimekey → **use this** ✓
   - (fallback: Bob's nostr pubkey — not reached)
2. Because `sending_to_peer_first_inbox = true`, wrap message in **PrekeyMessageModel**:
   ```json
   {
     "nostrId": "<my_nostr_pubkey>",
     "signalId": "<my_signal_key>",
     "time": <unix_ms>,
     "sig": "<schnorr_sign('Keychat-nostrId-signalId-time')>",
     "name": "<display_name>",
     "message": "<KeychatMessage JSON or greeting text>"
   }
   ```
3. Signal encrypt → base64 → kind:4 event with p-tag = `peer_first_inbox`
4. After encrypt, if `my_new_inbox` returned:
   - Derive address: `generate_seed_from_ratchetkey_pair(my_new_inbox)`
   - Save to `my_inbox` list + subscribe on relay
5. **Clear `peer_first_inbox` to NULL** — it's one-time use, never send to it again

### 6.7 NIP-17 Gift Wrap Structure

The `create_gift_json` function produces a double-encrypted Nostr event (two layers of NIP-44):

```
Layer 1 — Rumor (unsigned event, NOT encrypted):
  pubkey = alice_nostr_pubkey
  content = KeychatMessage JSON (plaintext)
  tags = [["p", bob_nostr_pubkey]]
  (no signature — this is just a data structure)

Layer 2 — Seal (kind:13, NIP-44 encrypted rumor):
  pubkey = alice_nostr_pubkey
  content = nip44_encrypt(alice_privkey, bob_pubkey, rumor_json)
  signed by alice

Layer 3 — Gift Wrap (kind:1059, NIP-44 encrypted seal):
  pubkey = random_ephemeral_pubkey  // NOT alice's
  content = nip44_encrypt(ephemeral_privkey, bob_pubkey, seal_json)
  tags = [["p", bob_nostr_pubkey]]
  timestamp = NOT tweaked for Hello (see §6.3 step 6)
  signed by random_ephemeral_key
```

**Two layers of encryption** (Seal encrypts the Rumor, Gift Wrap encrypts the Seal). The Rumor itself is plaintext — it only becomes protected once wrapped by the Seal.

### 6.8 Unwrapping a Gift Wrap (Receiving Hello)

```
1. Decrypt kind:1059 content with NIP-44 using my_private_key + event.pubkey
   → seal_json

2. Verify seal event signature

3. Decrypt seal content with NIP-44 using my_private_key + seal.pubkey
   → rumor_json (the actual message)

4. Parse rumor.content as KeychatMessage
   Check type == 101 (dmAddContactFromAlice)

5. Parse km.name as QRUserModel → get peer's Signal PreKey bundle

6. Verify globalSign:
   message = "Keychat-<qr.pubkey>-<qr.curve25519PkHex>-<qr.time>"
   verify_schnorr(qr.pubkey, qr.globalSign, sha256(message))
```

---

## 7. Message Format

### 7.1 KeychatMessage

All Keychat messages are JSON objects with a standard structure:

```json
{"c": "<crypto_mode>", "type": <int>, "msg": "<content>", "name": "<extra_data>"}
```

- `c`: Crypto mode — `"signal"` or `"nip04"` or `"group"`
- `type`: Message type code
- `msg`: Message content (text, or structured data)
- `name`: Extra data (varies by type — reply context, QRUserModel, etc.)

### 7.2 Message Types

| Type | Name | Description |
|------|------|-------------|
| 100 | `dm` | Normal direct message |
| 101 | `dmAddContactFromAlice` | Hello / add-friend request |
| 103 | `deleteHistory` | Delete chat history |
| 104 | `dmReject` | Reject friend request |
| 30 | `groupSendToAllMessage` | Group message to all members |
| 45 | `signalRelaySyncInvite` | Relay sync invitation |
| 48 | `signalSendProfile` | Profile update |
| 2001-2006 | `webrtc*` | WebRTC signaling |
| 3001-3009 | `group*` | KDF group operations |

**Note**: Type 102 (AddContactFromBob) exists in code but is NOT used by the app. Do not implement it.

### 7.3 Plain Text Fallback (REQUIRED)

The Keychat app may send plaintext directly without the KeychatMessage JSON wrapper in some scenarios (observed during interop testing). Receivers MUST handle this gracefully:

```
1. Try parsing as KeychatMessage JSON
2. If that fails, try parsing as AcceptContactReply JSON (PrekeyMessageModel)
3. If both fail, treat the entire string as a plain text DM:
   KeychatMessage { c: "signal", type: 100, msg: <raw_text>, name: null }
```

This fallback is implemented in `KeychatMessage::from_json_flexible()`. Never reject a successfully decrypted message just because it isn't valid JSON.

---

## 8. Address Management

### 8.1 Overview

Address management is the most complex and bug-prone part of the Keychat protocol. Two types of addresses rotate with the Signal ratchet:

- **`my_inbox`** — addresses I listen on (inbound). Peer sends to these.
- **`peer_inbox`** — the address I send to (outbound). Derived from peer's ratchet state.

These are **two completely different directions**. Mixing them is the #1 source of bugs.

### 8.2 Address Derivation Formula

All ratchet-derived addresses use this deterministic process:

```
generate_seed_from_ratchetkey_pair(ratchet_key_pair_string):
  // Input: "private_hex-public_hex" (from Signal session ratchet)
  private = curve25519_private_key(hex_decode(split[0]))
  public = curve25519_public_key(hex_decode(split[1]))
  dh = private.calculate_agreement(public)
  secrets = [0xFF; 32] || dh
  hash = SHA256(secrets)[0..64]   // 64 hex chars = 32 bytes
  secret_key = secp256k1_secret_key(hash)
  return x_only_public_key(secret_key).hex()
```

### 8.3 Sending: The 3-Level Fallback Chain

When sending a message to a peer, determine the destination address:

```
1. peer_inbox (DB cached)
   → Set after every decrypt from session.bobAddress
   → Most reliable — reflects latest ratchet state
   → If available, use this. Done.

2. peer_first_inbox (DB peer_mapping column)
   → Peer's onetimekey from their QRUserModel (set during hello)
   → Used only for the very first message after accepting hello
   → If sending here, wrap in PrekeyMessageModel (§9.4)
   → Clear to NULL after sending (one-time use)

3. peer_nostr_pubkey (ultimate fallback)
   → Peer's main Nostr pubkey
   → Used when no ratchet address and no onetimekey
   → Least private (links to identity), but always works
```

The resolved result is stored as `dest_pubkey`. The kind:4 event is then constructed with:
- `receiver_pubkeys = [dest_pubkey]` → becomes the event's p-tag(s)
- `ephemeral_sender = Keys::generate()` → becomes the event's `pubkey` field (random, per-message)

This mirrors the Keychat app's `_getSignalToAddress()`:

```dart
// Simplified — actual code also handles "05" prefix check
var to = bobSession.bobAddress ?? bobSession.address;
if (to.startsWith('05')) {
  to = room.toMainPubkey;           // → fallback 3: peer nostr pubkey
} else {
  to = generateSeedFromRatchetkeyPair(to);  // → level 1: peer_inbox
}
if (to == room.toMainPubkey && room.onetimekey != null) {
  to = room.onetimekey!;            // → level 2: peer_first_inbox
}
```

### 8.4 Sending: The "05" Prefix Check

Before deriving `peer_inbox` from `session.bobAddress`:

```
if bobAddress starts with "05":
    // "05" is the curve25519 public key type prefix byte.
    // Signal curve25519 pubkeys are 33 bytes (66 hex chars), starting with "05".
    // This means bobAddress is still the raw Signal identity key —
    // no ratchet step has occurred yet.
    // Cannot use as Nostr address (Nostr uses secp256k1 x-only, 32 bytes).
    → skip, fall through to level 2/3
else:
    // bobAddress is a ratchet key pair string ("privhex-pubhex")
    peer_inbox = generate_seed_from_ratchetkey_pair(bobAddress)
```

### 8.5 Sending: Updating peer_inbox After Decrypt

After **every** decrypt operation, update `peer_inbox` from the Signal session:

```
1. Read bobAddress from Signal session record
2. If bobAddress is None → log warning, skip
3. If bobAddress starts with "05" → skip (raw curve25519, not ratcheted yet)
4. Else → peer_inbox = generate_seed_from_ratchetkey_pair(bobAddress)
5. Save peer_inbox to DB (overwrites previous value)
```

**⚠️ CRITICAL**: This must happen unconditionally after every decrypt. The previous OpenClaw plugin implementation cached `my_sending_address` from `store_session(to_receiver_address)` callback, but that callback returned `None` in many code paths, leaving `peer_inbox` permanently stale. The fix: read `bobAddress` directly from the session record.

### 8.6 Receiving: my_inbox Management

`my_inbox` addresses are where peers send messages to me. They rotate with the ratchet:

**After encrypt** (sending a message):
- If `my_new_inbox` is returned (ratchet advanced):
  1. `derived = generate_seed_from_ratchetkey_pair(my_new_inbox)`
  2. Add `derived` to `my_inbox` list for this peer
  3. Subscribe to `derived` on relay
  4. Save to DB

**After decrypt** (receiving a message):
- The return value includes `alice_addrs` — these are our new `my_inbox` seeds
- For each address in `alice_addrs`:
  1. `derived = generate_seed_from_ratchetkey_pair(addr)`
  2. Add to `my_inbox` list + subscribe + save to DB

**⚠️ CRITICAL**: `alice_addrs` (from decrypt) and `my_new_inbox` (from encrypt) are both **my** receiving addresses. They must ONLY go into `my_inbox`. They must NEVER be used as `peer_inbox` (sending address). These are two different directions.

### 8.7 Receiving: Routing Inbound Messages

When a kind:4 event arrives:
1. Check `arrived_at` (the p-tag address the event was sent to)
2. Look up `arrived_at` in `my_inbox` → find which peer this message is from
3. Use the peer's `peer_signal_key` + `my_signal_key` to decrypt
4. After decrypt, update `peer_inbox` (§8.5) and add new `my_inbox` entries (§8.6)

### 8.8 Address Limits

- Maximum `my_inbox` addresses per peer: configurable (default 3–5)
- When adding a new address exceeds the limit, remove the oldest
- Only remove old addresses **lazily** — when a message arrives on a newer address, confirming the peer has moved on
- Use `alice_addrs` from decrypt result, NOT `getReceivingAddresses()` (which returns ALL peers' addresses — caused 510 address explosion in OpenClaw plugin)

---

## 9. PreKey Message Handling

The very first Signal message after accepting a hello is a **PreKey message**. It bootstraps the Signal ratchet.

### 9.1 Identifying a PreKey Message

```
ciphertext = base64_decode(event.content)
is_prekey = PreKeySignalMessage::try_from(ciphertext).is_ok()
```

**⚠️ CRITICAL**: Do NOT use `ciphertext[0] == 3` — Signal messages are protobuf-encoded and the first byte is a field tag, not a message type indicator.

### 9.2 Extracting Sender Identity

```
(peer_signal_key, signed_prekey_id) =
  parse_identity_from_prekey_signal_message(ciphertext)
```

Use `signed_prekey_id` to look up which of your `my_signal_key` identities this message is for.

### 9.3 Decrypting

```
(plaintext, msg_key_hash, alice_addrs) =
  decrypt_signal(my_signal_key_store, ciphertext, remote_address, is_prekey=true)
```

### 9.4 PrekeyMessageModel

When sending the first message to `peer_first_inbox` (onetimekey), wrap in PrekeyMessageModel:

```json
{
  "nostrId": "<my_nostr_pubkey_hex>",
  "signalId": "<my_signal_key_hex>",
  "time": <unix_ms>,
  "name": "<display_name>",
  "sig": "<schnorr_signature>",
  "message": "<actual message content or KeychatMessage JSON>",
  "lightning": "",
  "avatar": ""
}
```

Verify/create the signature:
```
content = "Keychat-<nostrId>-<signalId>-<time>"
sig = schnorr_sign(nostr_private_key, sha256(content))
```

The receiver extracts `message` field, which may contain a KeychatMessage JSON or plain text.

---

## 10. Media & File Transfer

### 10.1 Encryption

Files are encrypted client-side before upload using AES-256-CTR with PKCS7 padding:

```
1. Generate random 32-byte key + 16-byte IV
2. PKCS7 pad the plaintext (block size = 16)
3. AES-256-CTR encrypt the padded data
4. Base64-encode SHA-256 hash of the ciphertext
```

**PKCS7 padding is required** because the Keychat app's Dart `Encrypter(AES(key, mode: AESMode.ctr))` applies PKCS7 padding internally. Without it, the app cannot decrypt the file.

The key, IV, and hash are **base64-encoded** (not hex). This matches both the Keychat app and the OpenClaw agent bridge.

### 10.2 Upload

Two upload methods are supported. The client auto-detects the server type.

#### S3 Relay (primary, used by relay.keychat.io)

```
1. POST /api/v1/object  {"cashu":"", "length":<N>, "sha256":"<base64_hash>"}
   → Response: {"url":"<presigned_s3_url>", "headers":{...}, "access_url":"<final_url>"}
2. PUT <presigned_s3_url> with encrypted bytes + returned headers
3. Use access_url as the file URL
```

Detection: `GET /api/v1/info` — if response has `maxsize` field, it's an S3 relay.

#### Blossom (fallback)

```
PUT /upload HTTP/1.1
Content-Type: application/octet-stream
Authorization: Nostr <base64(kind:24242 event)>

<encrypted_file_bytes>
```

The NIP-98 authorization event (kind:24242) is signed by an ephemeral keypair and contains:
- `t` tag: `"upload"`
- `x` tag: SHA-256 hash of the encrypted file (**hex** for Blossom auth)
- `expiration` tag: Unix timestamp (typically +30 days)
- `content`: the file hash (hex)

Response: `{ "url": "<access_url>", "size": <bytes> }`

### 10.3 Message Format

The Signal-encrypted message content is a **URL with query parameters** (not a JSON object):

```
https://s3.keychat.io/path/to/file?kctype=image&suffix=jpg&key=<base64>&iv=<base64>&size=1234&hash=<base64>&sourceName=photo.jpg
```

Query parameters:

| Param | Type | Description |
|-------|------|-------------|
| `kctype` | String | Media type: `image`, `video`, `file`, `voiceNote` |
| `suffix` | String | File extension (e.g. `jpg`, `mp4`) |
| `key` | String | AES-256-CTR key (base64) |
| `iv` | String | AES-256-CTR IV (base64) |
| `size` | int | Encrypted file size in bytes |
| `hash` | String | SHA-256 of ciphertext (base64) |
| `sourceName` | String | Original filename |
| `isVoiceNote` | String? | `"1"` if voice message |
| `duration` | String? | Duration in seconds (voice/video) |
| `waveform` | String? | Base64 5-bit packed waveform (voice) |

The Keychat app parses this with `Uri.parse()` and extracts params. The base URL (without query params) is the download endpoint.

### 10.4 Receiving Flow

```
1. Parse media URL from decrypted Signal message (check for kctype param)
2. Download encrypted file from base URL
3. Base64-decode key and IV
4. AES-256-CTR decrypt
5. Strip PKCS7 padding
6. Save as <sourceName>.<suffix>
```

### 10.5 Security Properties

- **Server-blind**: Blossom server only sees encrypted bytes, cannot read content
- **Ephemeral auth**: Upload authorization uses a random keypair, unlinkable to sender identity
- **Integrity**: SHA-256 hash verifies file was not tampered with
- **Key distribution**: Encryption key travels only through the Signal-encrypted channel

---

## 11. Small Groups (Signal-based)

Signal-based small groups use fan-out encryption: each message is individually encrypted for each member using their respective Signal sessions. Suitable for groups up to ~20 members. For larger groups, use MLS (§13).

### 11.1 Group Identity

Each group has a random Nostr keypair. The public key serves as the group ID (`group_pubkey`). The secret key is held by the admin only (used for signing group management events in some implementations).

### 11.2 Group Type

Currently only `SendAll` type is supported:
- Admin creates group → generates random group keypair
- Members are invited via their existing 1:1 Signal sessions
- Each message is individually Signal-encrypted for every member (fan-out)

### 11.3 Invite Flow

1. Admin creates a `GroupProfile` containing (camelCase JSON fields):
   - `pubkey`: group's Nostr public key (hex)
   - `name`: group display name
   - `users`: list of members as `[{idPubkey, name, isAdmin}, ...]`
   - `groupType`: `"sendAll"`
   - `updatedAt`: millisecond timestamp
   - `oldToRoomPubKey`: same as `pubkey` (required by Keychat app)
2. Invite is wrapped in a `KeychatMessage`:
   - `c`: `"group"`
   - `type`: `11` (`GROUP_INVITE`)
   - `msg`: `JSON.stringify(groupProfile)`
   - `name`: `JSON.stringify([inviteMessage, senderIdPubkey])`
3. Sent to each invitee via their 1:1 Signal session (normal `send_message`)

### 11.4 Messaging

Messages are wrapped in a `KeychatMessage` with `c="group"`, `type=30` (`GROUP_SEND_TO_ALL`). The `msg` field contains a `GroupMessage` JSON object:

```json
{
  "message": "<plaintext message>",
  "pubkey": "<group_pubkey>"
}
```

Optional fields: `sig` (signature), `subtype` (event subtype), `ext` (extra data).

The sender encrypts this payload individually for each member using their Signal session and sends via kind:4 events (same as 1:1 DMs).

### 11.5 Group Management Events

For `sendAll` groups, **all** events (including management) are sent as `type=30` (`GROUP_SEND_TO_ALL`) with the specific operation indicated by the `subtype` field inside the `GroupMessage` JSON. Only `GROUP_INVITE` (type=11) uses a top-level type.

| subtype | Constant | Description | `ext` field |
|---------|----------|-------------|-------------|
| — | `GROUP_INVITE` (type=11) | Invite members to join | — |
| 15 | `GROUP_CHANGE_NICKNAME` | Member changes display name | new name |
| 17 | `GROUP_DISSOLVE` | Admin dissolves the group | — |
| 20 | `GROUP_CHANGE_ROOM_NAME` | Admin renames the group | new name |
| — | (no subtype) | Regular chat message | — |
| 31 | `GROUP_REMOVE_MEMBER` | Admin removes a member | member pubkey |

#### Management Message Format

All management events are wrapped as a regular group message (`type=30`) with `subtype` and `ext` inside:

```json
{
  "c": "group",
  "type": 30,
  "msg": "{\"message\":\"[System] ...\",\"pubkey\":\"<group_pubkey>\",\"subtype\":20,\"ext\":\"New Name\"}"
}
```

The Keychat app processes these through `processGroupMessage()` → reads `GroupMessage.subtype` → dispatches to the appropriate handler. The `ext` field carries the operation data (new name for rename, member pubkey for remove).

**Important**: Do NOT send management events as top-level `type=17/20/31`. The Keychat app's `sendAll` group code path only processes `type=30` messages and checks `subtype` internally. Top-level management types are only used for non-sendAll group types (e.g., `shareKey`).

### 11.6 Member Removal

Admin sends `type=30` with inner `subtype=31` and `ext=<member_pubkey>` to all remaining members. The removed member's Signal session is not destroyed — they simply stop receiving group messages.

### 11.7 Group Dissolution

Admin sends `type=30` with inner `subtype=17` to all members. All members should mark the group as dissolved locally.

### 11.8 Limitations

- **O(n) encryption**: Each message requires n separate Signal encryptions (one per member)
- **No forward secrecy at group level**: Compromise of any member's Signal session exposes messages sent to them
- **Admin-centric**: Only admin can add/remove members, rename, or dissolve
- **No built-in ordering**: Messages may arrive out of order across members

---

## 12. Ecash Stamps

libkeychat supports relay postage via ecash stamps, following [NIP-ESTAMP.md](./NIP-ESTAMP.md).

### 12.1 Discovery

Clients discover stamp requirements from relay NIP-11 (`application/nostr+json`) and read `fees.stamp` entries:

- `amount`: required fee amount
- `unit`: fee unit (`sat` or `msat`)
- `mints`: accepted Cashu mint URLs

If `fees.stamp` is missing or empty, the relay is treated as free for publishing.

### 12.2 Transport Format

For paid relays, the token is attached as the third element of the `EVENT` frame:

```json
["EVENT", <event>, "<cashu_token>"]
```

For free relays, the regular format is unchanged:

```json
["EVENT", <event>]
```

Stamps are transport-layer credentials and are not part of the signed Nostr event object.

### 12.3 Client Integration

`StampProvider` is an application-supplied trait for creating Cashu tokens. libkeychat does not ship a wallet dependency. Applications provide their own provider implementation (for example, backed by a Cashu wallet/SDK), then configure relay fees and publish with per-relay stamps.

## 13. Large Groups (MLS)

Large groups use the MLS (Messaging Layer Security) protocol via OpenMLS (Keychat's `kc4` branch fork). Unlike Signal-based small groups (§11) which encrypt per-member, MLS provides efficient group encryption that scales to hundreds of members.

### 13.1 Dependencies

- **OpenMLS**: Keychat fork (`kc4` branch) with `NostrGroupDataExtension` support
- **openmls-sqlite-storage**: SQLite-backed persistent storage for MLS state
- **Ciphersuite**: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (constant `CIPHERSUITE` from `kc` crate)

### 13.2 Identity

Each MLS participant is identified by their **Nostr pubkey hex** string, stored as a `BasicCredential`. This is the same long-term Nostr identity from §3.1 — MLS does not use disposable identities like Signal (§3.2).

### 13.3 Event Kinds

| Kind | Purpose | Encryption | Tags |
|------|---------|-----------|------|
| 10443 | KeyPackage publication | None (public) | `["p", publisher_nostr_pubkey]` |
| 444 | Welcome message | NIP-44 (sender → recipient) | `["p", recipient_nostr_pubkey]` |
| 1059 | MLS application message | NIP-59 Gift Wrap (NIP-44 + seal) | `["p", listen_key_pubkey]` |

### 13.4 KeyPackage Management

A KeyPackage advertises a member's MLS capabilities and allows others to add them to groups without interactive key exchange.

**Publishing:**
```
1. init_mls(db_path, nostr_id)           → initialize MLS identity + SQLite storage
2. create_key_package(nostr_id)          → KeyPackageResult { key_package (hex), mls_protocol_version, ciphersuite, extensions }
3. publish_key_package(relay, keypair, key_package_hex)  → kind:10443 event
```

**KeyPackage event (kind:10443):**
- `pubkey` = publisher's Nostr pubkey
- `content` = TLS-serialized KeyPackage, hex-encoded
- `tags` = `[["p", publisher_nostr_pubkey]]`
- Signed with publisher's Nostr private key

**Fetching:**
```
fetch_key_package(relay, member_pubkey_hex)  → subscribes to kind:10443 with p-tag filter, returns first matching content
```

**⚠️ Re-publish after join**: After joining a group via Welcome, a member SHOULD publish a fresh KeyPackage so they can be added to additional groups (each KeyPackage is single-use in MLS).

### 13.5 Group Creation

```
create_mls_group(nostr_id, group_name)  → group_id (random 32-byte hex)
```

**Group configuration:**
- `use_ratchet_tree_extension = true` (ratchet tree included in Welcome for stateless join)
- Custom extension `0xF233` (`NostrGroupDataExtension`): group name, description, member list, admin list, status
- `RequiredCapabilitiesExtension` enforces all members support the custom extension

**Group ID**: Random 32-byte hex string, used as the OpenMLS `GroupId`.

### 13.6 Adding Members

```
add_member(nostr_id, group_id, key_package_hex)  → AddMembersResult { commit_message, welcome }
```

**Steps:**
1. Parse and validate the member's KeyPackage (TLS deserialization + MLS 1.0 validation)
2. `mls_group.add_members(provider, signer, &[key_package])` → (commit, welcome, group_info)
3. `mls_group.merge_pending_commit(provider)` — apply locally
4. Distribute:
   - **Welcome** → send to new member via `send_welcome()` (kind:444, NIP-44 encrypted)
   - **Commit** → send to existing members via `send_group_message()` (kind:1059, Gift Wrap)

### 13.7 Joining via Welcome

```
join_group_from_welcome(nostr_id, welcome_bytes)  → group_id
```

**Steps:**
1. TLS-deserialize the Welcome message
2. `StagedWelcome::new_from_welcome(provider, join_config, welcome, None)`
3. `staged_welcome.into_group(provider)` → `MlsGroup`
4. Extract `group_id` from group context
5. Store in local groups map + group_list

**Welcome transport (kind:444):**
- Content = `nip44_encrypt(hex::encode(welcome_bytes), recipient_pubkey)`
- Tags = `[["p", recipient_nostr_pubkey]]`
- Signed with sender's Nostr keypair (not ephemeral — recipient needs to identify the group admin)

### 13.8 Group Messaging

**Encrypt + Send:**
```
encrypt_group_message(nostr_id, group_id, plaintext)  → ciphertext bytes
send_group_message(relay, sender_keypair, listen_key_hex, ciphertext)  → kind:1059 event
```

The send function wraps ciphertext in a NIP-59 Gift Wrap:
1. Create rumor (kind:14) with `content = hex::encode(ciphertext)`, `p-tag = listen_key_hex`
2. Seal rumor with NIP-44 encryption to `listen_key_hex`
3. Wrap seal in kind:1059 Gift Wrap with ephemeral sender keypair

**Receive + Decrypt:**
```
receive_group_message(relay, receiver_keypair, listen_key_hex)  → broadcast::Receiver<Vec<u8>>
decrypt_group_message(nostr_id, group_id, ciphertext)  → DecryptedGroupMessage { plaintext, sender_nostr_id, listen_key }
```

The receive function:
1. Subscribes to kind:1059 with `p-tag = listen_key_hex`
2. For each event: `unwrap_gift_wrap()` → verify rumor kind == 14 → `hex::decode(rumor.content)`
3. Forward raw ciphertext bytes via broadcast channel
4. Application calls `decrypt_group_message()` to get plaintext + sender identity

### 13.9 Listen Key Derivation

The **listen key** is a group-specific Nostr pubkey derived from the MLS group's export secret. All group members derive the same key, which serves as the relay subscription address.

```
export_secret = mls_group.export_secret(provider, "nostr", b"nostr", 32)
nostr_keys    = Keys::parse(hex::encode(export_secret))
listen_key    = hex::encode(nostr_keys.public_key().xonly())
```

**Properties:**
- Deterministic: same group state → same listen key
- Changes when group membership changes (after processing commits)
- Non-members cannot derive it (requires MLS group state)
- Used as the `p-tag` for kind:1059 group message events

### 13.10 Processing Commits

When a group admin adds or removes members, other members receive the commit:

```
process_commit(nostr_id, group_id, commit_bytes)  → CommitResult { sender, commit_type, operated_members }
```

**Commit types:**
| Type | Meaning |
|------|---------|
| `Add` | New member(s) added; `operated_members` lists their nostr_ids |
| `Remove` | Member(s) removed |
| `Update` | Member updated their leaf node (e.g., new KeyPackage) |
| `GroupContextExtensions` | Group metadata changed |

After processing, the local MLS group state is updated via `merge_staged_commit()`.

### 13.11 Removing Members

```
remove_member(nostr_id, group_id, member_nostr_id)  → RemoveMemberResult { commit_message }
```

**Steps:**
1. Find the target member's leaf index by matching `BasicCredential` identity against `member_nostr_id`
2. `mls_group.remove_members(provider, signer, &[leaf_index])`
3. `merge_pending_commit(provider)`
4. Distribute commit to remaining members

### 13.12 Leaving a Group

```
leave_group(nostr_id, group_id)  → commit_bytes
```

**Steps:**
1. Create a self-remove proposal + commit
2. Remove group from local `groups` map and `group_list`
3. Return commit bytes for other members to process

**⚠️ Note**: After leaving, the member can no longer decrypt group messages or derive the listen key. Other members MUST process the leave commit to update their group state.

### 13.13 Storage

MLS state is persisted via `openmls-sqlite-storage` (`SqliteStorageProvider<JsonCodec>`):
- MLS identity (signing key, credential)
- Group state (ratchet tree, epoch secrets, pending proposals)
- KeyPackages (unused packages for future group joins)

The `MlsUser` from the `kc` crate manages lifecycle: `load()` on init, `update()` after every mutation.

Global state is held in a `lazy_static` `Mutex<Option<MlsStore>>` with a dedicated tokio `Runtime` for async↔sync bridging (MLS operations are synchronous but storage may be async).

### 13.14 Complete Group Lifecycle Example

```
Alice (admin)                          Bob                              Charlie
─────────────────────────────────────────────────────────────────────────────────
init_mls(db, "alice")                  init_mls(db, "bob")             init_mls(db, "charlie")
                                       create_key_package("bob")       create_key_package("charlie")
                                       publish_key_package(relay, kp)  publish_key_package(relay, kp)

fetch_key_package(relay, bob_pubkey)
create_mls_group("alice", "Team")
add_member("alice", gid, bob_kp)
  → commit + welcome
send_welcome(relay, alice, bob, welcome)
send_group_message(relay, alice, lk, commit)
                                       join_group_from_welcome("bob", welcome)

fetch_key_package(relay, charlie_pubkey)
add_member("alice", gid, charlie_kp)
  → commit + welcome
send_welcome(relay, alice, charlie, welcome)
send_group_message(relay, alice, lk, commit)
                                       process_commit("bob", gid, commit)
                                                                        join_group_from_welcome("charlie", welcome)

encrypt_group_message("alice", gid, "Hello team!")
send_group_message(relay, alice, lk, ct)
                                       decrypt_group_message("bob", gid, ct)
                                         → "Hello team!" from alice
                                                                        decrypt_group_message("charlie", gid, ct)
                                                                          → "Hello team!" from alice

remove_member("alice", gid, "charlie")
  → commit
send_group_message(relay, alice, lk, commit)
                                       process_commit("bob", gid, commit)
                                                                        (can no longer decrypt)
```

---

## 14. Cryptographic Primitives Reference

### 14.1 Key Types

| Key | Curve | Size | Usage |
|-----|-------|------|-------|
| Nostr identity | secp256k1 | 32 bytes private, 32 bytes x-only public | Identity, signing, NIP-04/44 |
| Signal identity (`my_signal_key` / `peer_signal_key`) | curve25519 | 32 bytes private, 33 bytes public | Signal session identity |
| Signed prekey | curve25519 | 33 bytes public | Signal X3DH |
| One-time prekey | curve25519 | 33 bytes public | Signal X3DH (one-use) |
| `my_first_inbox` / `peer_first_inbox` | secp256k1 | 32 bytes x-only public | Temporary Nostr receive address (one-time) |

### 14.2 Encryption Algorithms

- **NIP-04**: AES-256-CBC + HMAC (legacy, for kind:4 non-Signal)
- **NIP-44**: XChaCha20 + HMAC-SHA256 (used in Gift Wrap)
- **Signal Protocol**: Double Ratchet (AES-256-CBC + HMAC-SHA256 per message)
- **MLS**: TreeKEM + AEAD (AES-128-GCM or AES-256-GCM)

### 14.3 Signatures

- **Schnorr (BIP-340)**: Used for Nostr event signatures AND `globalSign` in QRUserModel / PrekeyMessageModel
- Nostr events are signed with secp256k1 Schnorr signatures (NOT Ed25519)

---

## 15. Storage

### 15.1 Peer Mapping Table

```sql
CREATE TABLE peer_mapping (
  nostr_pubkey      TEXT PRIMARY KEY,  -- peer's Nostr pubkey (hex)
  peer_signal_key   TEXT,              -- peer's Signal curve25519 pubkey
  device_id         INTEGER DEFAULT 1,
  name              TEXT,              -- peer's display name
  my_signal_key     TEXT,              -- our per-peer Signal pubkey
  my_signal_privkey TEXT,              -- our per-peer Signal private key (cleared after session established)
  peer_first_inbox  TEXT,              -- peer's onetimekey (cleared after first send)
  peer_inbox        TEXT               -- current sending address (updated after each decrypt)
);
```

### 15.2 My Inboxes Table

```sql
CREATE TABLE my_inboxes (
  address           TEXT PRIMARY KEY,  -- derived Nostr address
  peer_nostr_pubkey TEXT NOT NULL,     -- which peer this address is for
  created_at        INTEGER            -- timestamp
);
```

### 15.3 Storage Trait

```rust
pub trait DataStore: Send + Sync {
    // Signal stores
    async fn save_session(&self, addr: &str, record: &[u8]) -> Result<()>;
    async fn load_session(&self, addr: &str) -> Result<Option<Vec<u8>>>;

    // Peer management
    async fn save_peer_mapping(&self, peer: &PeerMapping) -> Result<()>;
    async fn get_peer_mapping(&self, nostr_pubkey: &str) -> Result<Option<PeerMapping>>;
    async fn lookup_by_signed_prekey_id(&self, id: u32) -> Result<Option<PeerMapping>>;

    // Address management
    async fn save_my_inbox(&self, address: &str, peer_nostr_pubkey: &str) -> Result<()>;
    async fn get_my_inboxes(&self, peer_nostr_pubkey: &str) -> Result<Vec<String>>;
    async fn get_all_my_inboxes(&self) -> Result<Vec<(String, String)>>; // (address, peer)
    async fn delete_my_inbox(&self, address: &str) -> Result<()>;
    async fn save_peer_inbox(&self, nostr_pubkey: &str, address: &str) -> Result<()>;
    async fn get_peer_inbox(&self, nostr_pubkey: &str) -> Result<Option<String>>;

    // Event deduplication
    async fn is_event_processed(&self, event_id: &str) -> Result<bool>;
    async fn mark_event_processed(&self, event_id: &str) -> Result<()>;

    // Pending hello messages (queued while waiting for accept-first)
    async fn save_pending_hello_msg(&self, peer: &str, text: &str) -> Result<i64>;
    async fn get_pending_hello_msgs(&self, peer: &str) -> Result<Vec<(i64, String)>>;
    async fn delete_pending_hello_msg(&self, id: i64) -> Result<()>;
}
```

### 15.4 Implementations

- `storage/memory.rs` — `InMemoryDataStore` for testing
- `storage/sqlite.rs` — `SqliteDataStore` for production
- `signal/session_store.rs` — `CapturingSessionStore` wrapping in-memory Signal stores with `bobAddress` tracking
- `SignalParticipantSnapshot` — serializable snapshot of Signal state (identity, prekeys, sessions) for persistence across restarts

The `interop_test` example uses a hybrid approach: Signal state is serialized via `SignalParticipantSnapshot` into a SQLite DB (`interop_test.db`), while address management state (`AddressManager`) is stored as JSON in the same DB. This survives process restarts without re-pairing.

---

## Appendix: Known Pitfalls

These are real bugs encountered during development. Every implementation MUST avoid them.

### P1: BIP-39 Derivation Path
**Wrong**: SHA-256 hash of seed
**Wrong**: BIP-32 with coin type 1238 (legacy Signal key path)
**Right**: BIP-32 with `m/44'/1237'/{account}'/0/0` (NIP-06)

### P2: PreKey Message Detection
**Wrong**: `ciphertext[0] == 3` (byte inspection)
**Right**: `PreKeySignalMessage::try_from(ciphertext).is_ok()` (protobuf parsing)

### P3: my_inbox Source
**Wrong**: `getReceivingAddresses()` — returns ALL peers' addresses (caused 510 address explosion)
**Right**: Use `alice_addrs` (from decrypt) or `my_new_inbox` (from encrypt) — per-peer only

### P4: peer_inbox Stale Cache
**Wrong**: Cache `peer_inbox` from `store_session(to_receiver_address)` callback (was never written correctly)
**Right**: Read `bobAddress` directly from Signal session record after each decrypt → derive → save as `peer_inbox`

### P5: Hello Reply Subscription
**Wrong**: Only subscribe to main Nostr pubkey after sending Hello
**Right**: Subscribe to `my_first_inbox` — peer's reply will arrive there

### P6: Kind:4 Content Format
**Wrong**: Attempt NIP-04 decryption on all kind:4 events
**Right**: Check `content.contains("?iv=")` — if yes, NIP-04; otherwise, raw base64 Signal ciphertext

### P7: Signal Identity Derivation
**Wrong**: Derive Signal curve25519 key from mnemonic (legacy approach)
**Right**: Generate randomly with `OsRng` — `my_signal_key` is disposable per-peer

### P8: Message Sender Identity
**Wrong**: Use main Nostr pubkey as event sender
**Right**: Generate a random one-time Nostr keypair for EACH message sent

### P9: peer_inbox "05" Prefix
**Wrong**: Treat raw Signal curve25519 pubkey (starts with "05") as a valid Nostr address
**Right**: If `bobAddress` starts with "05", skip derivation — fall through to `peer_first_inbox` or `peer_nostr_pubkey`

### P10: Hello Timestamp Tweaking
**Wrong**: Apply NIP-59 random timestamp offset to Hello messages
**Right**: Use real timestamp (`timestamp_tweaked = false`) — tweaked timestamps can make the event invisible to receivers

### P11: my_first_inbox Used as Sending Address
**Wrong**: Set `peer_inbox = my_first_inbox` after sending Hello (sending to your OWN onetimekey)
**Right**: `my_first_inbox` is a **receiving** address (where the peer sends their reply TO you). It must never be used as a sending target. Before ratchet is established, sending falls through to `peer_first_inbox` or `peer_nostr_pubkey`.

### P12: alice_addrs Used as peer_inbox
**Wrong**: After decrypt, set `peer_inbox = alice_addrs[last]` (alice_addrs are YOUR addresses)
**Right**: `alice_addrs` → `my_inbox` only. `peer_inbox` comes from `session.bobAddress`. Different directions — never cross them.

### P13: bobAddress Update After Decrypt (Resolved)
The `store_session(to_receiver_address)` callback IS reliable for all decrypt paths — both PreKey decrypt and normal decrypt pass `Some(to_receiver_address)`. Only `message_encrypt` passes `None`, but encrypt does not need to update `peer_inbox`. The `CapturingSessionStore` callback approach (or signal-storage's DB write) is sufficient. No fallback to direct session record read is needed.

### P14: peer_first_inbox Not Cleared After Use
**Wrong**: Keep `peer_first_inbox` after sending the first message — subsequent messages still go there
**Right**: Clear `peer_first_inbox = NULL` immediately after the first send. It's a one-time address. After that, `peer_inbox` (from ratchet) takes over.

---

## Changelog

- **0.5.0-draft (2026-03-05)**: Updated §10 Media with PKCS7 padding requirement, base64 encoding (not hex), S3 relay + Blossom dual upload, media URL query-param format (not JSON). Updated §11 Small Groups: management events must use type=30 wrapper with GroupMessage.subtype (not top-level type=17/20/31); added GroupProfile camelCase requirement and oldToRoomPubKey field; fixed GroupMessage format to {message, pubkey}. All M1–M7 features complete. Verified interop: 1:1 DM, small group create/invite/messaging/rename/dissolve, MLS bidirectional, media send with S3 relay upload.
- **0.4.0-draft (2026-03-04)**: Updated §5.4 with implemented relay transport details (concurrent publish, 10s ack timeout, auto-reconnect). Fixed §4.5 Signal Stores to document `CapturingSessionStore` and flag semantics (0-4 matching signal-storage crate). Updated §7.3 from optional shortcut to required plain text fallback (observed in Keychat app interop). Updated §14.4 with actual implementation details (`SignalParticipantSnapshot`, hybrid persistence in interop_test). Full bidirectional interop with Keychat app verified: hello accept → auto-reply → multi-message echo → address rotation all working.
- **0.3.0-draft (2026-03-04)**: Added sending runtime variables (`dest_pubkey`, `receiver_pubkeys`, `ephemeral_sender`) to naming conventions. Unified all address naming to `peer_inbox` / `my_inbox` / `my_first_inbox` / `peer_first_inbox` / `my_new_inbox` / `arrived_at` convention. Added naming conventions table. Rewrote §6 as two clear scenarios (A: outbound hello, B: inbound hello) with step-by-step including address management at each stage. Rewrote §8 around the 3-level fallback chain (`peer_inbox → peer_first_inbox → peer_nostr_pubkey`). Added §8.4 ("05" prefix), §8.5 (peer_inbox update after decrypt), §8.6 (my_inbox management), §8.7 (inbound routing). Updated §14 storage with concrete SQL schema matching the naming. Added P14 (peer_first_inbox not cleared). All pitfalls updated with new naming.
- **0.2.0-draft (2026-03-04)**: Merged from keychat-protocol-spec.md and MEMORY.md. Added Gift Wrap structure, globalSign, timestamp tweak warning, PreKey handling, media transfer, crypto reference, kind:4 distinction.
- **0.1.0-draft (2026-03-03)**: Initial draft. M1 scope (Identity + Signal crypto) implemented and verified.
