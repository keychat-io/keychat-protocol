# NIP-XX -- Signal Protocol over Nostr

`optional` `author:keychat`

## Abstract

This NIP defines how to run the Signal Protocol (PQXDH + Double Ratchet) over the Nostr network, enabling 1-to-1 end-to-end encrypted messaging with forward secrecy, post-compromise security, and post-quantum resistance. It specifies the key exchange, message encryption, address rotation, and event structure required for interoperable implementations.

This NIP depends on [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md), [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md), and [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md).

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Motivation

This proposal introduces Signal Protocol into the Nostr network, allowing Nostr clients to have end-to-end encrypted private communications with:

- **Forward Secrecy (FS):** Compromise of current keys does not reveal past messages.
- **Post-Compromise Security (PCS):** Security is restored after a key compromise through the DH ratchet.
- **Post-Quantum Resistance:** The initial key agreement uses PQXDH, combining classical ECDH with ML-KEM 1024 (Kyber) key encapsulation.
- **Sender Anonymity:** Every message is sent from a random ephemeral Nostr keypair; the sender's real npub never appears as a Nostr event author.
- **Receiver Unlinkability:** Receiving addresses rotate with each DH ratchet step, derived deterministically from the ratchet state and decoupled from identity.

## Overview

### Signal Protocol

The Signal Protocol is a set of cryptographic specifications providing end-to-end encryption for private communications.

**Algorithms:**

- **PQXDH** (Post-Quantum Extended Diffie-Hellman) — Initial key agreement with hybrid classical + post-quantum security
- **Double Ratchet** — Ongoing key derivation providing forward secrecy and post-compromise security per message

### Architecture

Private conversation is between a Sender (Alice) and a Recipient (Bob). All communications are routed through Nostr relays — there is no direct connection between participants. Every outgoing message uses a fresh ephemeral Nostr keypair as the event author, so relays and observers cannot correlate messages to the sender's identity.

### Cryptographic Primitives

All cryptographic operations are performed by the [libsignal](https://github.com/signalapp/libsignal) Rust library. Implementations MUST use libsignal (or a compatible, audited implementation) and MUST NOT implement cryptographic primitives independently.

| Algorithm | Usage |
|-----------|-------|
| **PQXDH** (Curve25519 + ML-KEM 1024) | Initial key agreement |
| **Double Ratchet** (Curve25519 ECDH + HKDF) | Ongoing key derivation |
| **AES-256-CBC + HMAC-SHA256** | Message encryption (internal to libsignal) |
| **XEdDSA** | Signal prekey signatures |
| **Schnorr (BIP-340)** | Nostr event signatures, `globalSign` identity binding |
| **NIP-44** (XChaCha20 + HMAC-SHA256) | Gift Wrap encryption (for friend requests) |

#### PQXDH Parameters

| Parameter | Value |
|-----------|-------|
| curve | Curve25519 |
| hash | SHA-512 |
| pqkem | ML-KEM 1024 (CRYSTALS-Kyber-1024) |
| info | "Keychat" |

PQXDH extends X3DH by adding a post-quantum KEM (Key Encapsulation Mechanism) to the initial handshake. The prekey bundle includes a **Kyber KEM public key** in addition to the standard Curve25519 keys. During session establishment:

1. Alice performs the standard ECDH calculations (DH1, DH2, DH3, optionally DH4)
2. Alice encapsulates a shared secret using Bob's Kyber public key: `(CT, SS) = PQKEM-ENC(KyberPrekey)`
3. The final session key combines both: `SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)`
4. Alice sends the KEM ciphertext `CT` along with her initial message

This provides **hybrid security**: the session is protected if either the classical (ECDH) or post-quantum (Kyber) assumption holds.

Once the session is established, the Double Ratchet operates identically to standard Signal Protocol — ongoing ratchet steps use Curve25519 ECDH.

## Transport

### Unified Event Kind

All messages — friend requests, encrypted chat messages, and prekey messages — use **kind 1059** as the Nostr transport event, regardless of the encryption mode.

### Two Transport Modes

#### Mode 1: Direct Transport (Signal-encrypted messages)

Signal messages are already end-to-end encrypted. They are transported directly as `kind: 1059` events without additional Nostr-layer encryption:

```json
{
  "kind": 1059,
  "pubkey": "<ephemeral one-time pubkey>",
  "content": "<base64(signal_ciphertext)>",
  "tags": [["p", "<receiver_address>"]],
  "created_at": "<unix_timestamp>",
  "id": "<event_id>",
  "sig": "<sig>"
}
```

- `pubkey` MUST be a freshly generated ephemeral secp256k1 key. The sender's real npub MUST NOT appear.
- `content` is `base64(signal_ciphertext)` — raw Signal ciphertext, no NIP-44 wrapping.
- `created_at` MUST be the real current timestamp (not tweaked).
- `receiver_address` is either a ratchet-derived address, `firstInbox`, or the peer's npub, depending on session state (see [Address Rotation](#address-rotation)).

Used for: all messages after a Signal session is established.

#### Mode 2: NIP-17 Gift Wrap (no Signal session yet)

When no Signal session exists (e.g., friend requests), NIP-17 three-layer wrapping provides encryption and metadata protection:

```
Layer 3 (outer): Gift Wrap (kind 1059)
  pubkey:      ephemeral key (NOT sender's real pubkey)
  created_at:  real timestamp
  content:     NIP-44 encrypt(ephemeral_privkey, receiver_pubkey) →
    Layer 2: Seal (kind 13)
      pubkey:    sender's real pubkey
      content:   NIP-44 encrypt(sender_privkey, receiver_pubkey) →
        Layer 1: Rumor (unsigned event)
          kind:    14
          tags:    [["p", "<receiver_pubkey>"]]
          content: KCMessage JSON plaintext
```

Used for: `friendRequest` messages (before Signal session establishment).

## Message Format (KCMessage v2)

All structured messages use the KCMessage v2 envelope. This is the content that goes inside the Signal-encrypted payload (Mode 1) or the NIP-17 Rumor (Mode 2).

### Envelope Structure

```json
{
  "v": 2,
  "id": "<uuid-v4>",
  "kind": "<message_kind>",
  "<payload_field>": { ... },
  "signalPrekeyAuth": { ... },
  "fallback": "<human-readable degraded text>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | `int` | Yes | Protocol version. MUST be `2`. |
| `kind` | `string` | Yes | Message type identifier. |
| `id` | `string` | No | Message UUID v4. Required for `friendRequest`. |
| `signalPrekeyAuth` | `object` | No | Identity binding for PrekeyMessages (see below). |
| `fallback` | `string` | No | Human-readable text for clients that don't recognize the `kind`. |

### Message Kinds

| Kind | Payload Field | Description |
|------|---------------|-------------|
| `text` | `text` | Text message |
| `friendRequest` | `friendRequest` | Friend request with PQXDH prekey bundle (via NIP-17) |
| `friendApprove` | `friendApprove` | Accept friend request |
| `friendReject` | `friendReject` | Reject friend request |

### friendRequest Payload

The prekey bundle for establishing a Signal session with PQXDH. Sent via NIP-17 Gift Wrap (Mode 2).

```json
{
  "v": 2,
  "id": "fr-uuid-001",
  "kind": "friendRequest",
  "friendRequest": {
    "message": "Hi, I'm Alice.",
    "name": "Alice",
    "nostrIdentityKey": "<alice_nostr_pubkey_hex>",
    "signalIdentityKey": "<signal_curve25519_pubkey_hex>",
    "firstInbox": "<ephemeral_nostr_pubkey_hex>",
    "deviceId": "<device_uuid>",
    "signalSignedPrekeyId": 1,
    "signalSignedPrekey": "<hex>",
    "signalSignedPrekeySignature": "<hex>",
    "signalOneTimePrekeyId": 1,
    "signalOneTimePrekey": "<hex>",
    "signalKyberPrekeyId": 1,
    "signalKyberPrekey": "<hex>",
    "signalKyberPrekeySignature": "<hex>",
    "globalSign": "<schnorr_sig_hex>",
    "time": 1700000000,
    "version": 2
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | `string` | No | Optional greeting |
| `name` | `string` | Yes | Display name |
| `nostrIdentityKey` | `string` | Yes | Sender's Nostr secp256k1 pubkey (hex, 64 chars) |
| `signalIdentityKey` | `string` | Yes | Sender's Signal Curve25519 identity pubkey (hex, 66 chars) |
| `firstInbox` | `string` | Yes | Ephemeral Nostr pubkey for first-message delivery |
| `deviceId` | `string` | Yes | Device ID for multi-device disambiguation |
| `signalSignedPrekeyId` | `int` | Yes | Signed prekey ID |
| `signalSignedPrekey` | `string` | Yes | Signed prekey (Curve25519, hex) |
| `signalSignedPrekeySignature` | `string` | Yes | XEdDSA signature over the signed prekey |
| `signalOneTimePrekeyId` | `int` | Yes | One-time prekey ID |
| `signalOneTimePrekey` | `string` | Yes | One-time prekey (Curve25519, hex) |
| `signalKyberPrekeyId` | `int` | Yes | Kyber KEM prekey ID |
| `signalKyberPrekey` | `string` | Yes | Kyber KEM public key (ML-KEM 1024, hex) |
| `signalKyberPrekeySignature` | `string` | Yes | XEdDSA signature over the Kyber prekey |
| `globalSign` | `string` | Yes | Schnorr signature: `sign(sha256("Keychat-{nostrIdentityKey}-{signalIdentityKey}-{time}"))` |
| `time` | `int` | No | Unix timestamp for anti-replay |
| `version` | `int` | Yes | Protocol version, MUST be `2` |

### friendApprove / friendReject Payload

```json
{
  "v": 2,
  "kind": "friendApprove",
  "friendApprove": {
    "requestId": "fr-uuid-001",
    "message": "Nice to meet you!"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `requestId` | `string` | Yes | The `id` of the original `friendRequest` KCMessage |
| `message` | `string` | No | Optional text |

### signalPrekeyAuth (Identity Binding)

Carried on the first Signal PrekeyMessage after session establishment. Binds the sender's Nostr identity to their Signal identity.

```json
{
  "nostrId": "<nostr_pubkey_hex>",
  "signalId": "<signal_curve25519_pubkey_hex>",
  "name": "Bob",
  "time": 1700000000,
  "sig": "<schnorr_signature_hex>"
}
```

The receiver MUST verify: `schnorr_verify(nostrId, sig, sha256("Keychat-{nostrId}-{signalId}-{time}"))`. If verification fails, the session MUST be rejected.

### text Payload

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
| `format` | `string` | No | `"plain"` (default) or `"markdown"` |

### Forward Compatibility

| Scenario | Behavior |
|----------|----------|
| Known `kind` | Parse normally |
| Unknown `kind` + `fallback` present | Display `fallback` as plain text |
| Unknown `kind` + no `fallback` | Display: "This message requires a newer version of Keychat" |

## Protocol Flow

### 1. Create Identity

Both Alice and Bob MUST create a Nostr identity — a secp256k1 keypair (nsec/npub) — before starting a conversation. The Nostr identity is the user's permanent, sovereign identity.

Signal Protocol key material (Curve25519 identity keys, signed prekeys, one-time prekeys, Kyber KEM keys) is **ephemeral and per-peer**: a new Signal identity MUST be generated for every contact and discarded on session reset. Signal keys are internal encryption state, not part of the user's identity.

### 2. Add Contact (Friend Request)

Alice MUST add Bob as a contact before messaging. It is RECOMMENDED that Alice and Bob share only one live session at a time.

#### Step 1: Generate Signal identity for this peer

Alice generates a fresh Curve25519 keypair as the Signal identity for communicating with Bob.

#### Step 2: Generate PQXDH prekey bundle

Alice generates the full prekey bundle:
- Signed prekey (Curve25519) + XEdDSA signature
- One-time prekey (Curve25519)
- Kyber KEM prekey (ML-KEM 1024) + XEdDSA signature

#### Step 3: Generate firstInbox

Alice generates a fresh ephemeral Nostr secp256k1 keypair. The public key (`firstInbox`) is included in the friend request so Bob can deliver his first reply.

Alice MUST subscribe to `firstInbox` on her relays for `kind: 1059` events. If she fails to do so, she will miss Bob's response.

#### Step 4: Send friend request (Mode 2)

Alice constructs a `friendRequest` KCMessage containing the full PQXDH prekey bundle, wraps it in NIP-17 Gift Wrap, and sends it to Bob's npub:

```json
{
  "kind": 1059,
  "pubkey": "<random ephemeral pubkey>",
  "content": "<NIP-44 encrypted seal>",
  "tags": [["p", "<bob_npub>"]],
  "created_at": "<unix_timestamp>"
}
```

Alice now listens on both her npub and `firstInbox`.

#### Step 5: Prekey messages (optional)

Before Bob confirms the request, Alice MAY send additional messages to Bob. These are encrypted using Signal Protocol (as PrekeyMessages) and delivered to Bob's npub or `firstInbox`.

#### Step 6: Accept friend request

When Bob receives the friend request, he:

1. Unwraps the NIP-17 Gift Wrap (kind 1059 → seal → rumor)
2. Parses the `friendRequest` payload
3. Verifies the `globalSign` Schnorr signature
4. Processes the PQXDH prekey bundle (EC + Kyber keys) to establish a Signal session
5. Sends a `friendApprove` message encrypted with Signal Protocol to Alice's `firstInbox`

Bob's approval is a PrekeyMessage (first Signal message in the session) and MUST include `signalPrekeyAuth` for identity binding:

```json
{
  "v": 2,
  "kind": "friendApprove",
  "friendApprove": { "requestId": "<original_friendRequest.id>" },
  "signalPrekeyAuth": {
    "nostrId": "<bob_nostr_pubkey>",
    "signalId": "<bob_signal_pubkey>",
    "name": "Bob",
    "time": 1700000000,
    "sig": "<schnorr_signature>"
  }
}
```

The session between Alice and Bob is now established.

### 3. Private Messaging

Alice can send private messages to Bob once they share a live session.

#### Key Derivation Function (KDF)

The Double Ratchet provides the key evolution mechanism:

- When a message is sent or received, a **symmetric-key ratchet** step derives the message key from the sending or receiving chain.
- When a new ratchet public key is received (direction change), a **DH ratchet** step replaces the chain keys before the symmetric ratchet.

The DH ratchet only advances on **direction change** — sending multiple messages in a row does not rotate keys.

#### Encrypt Message

```
1. Construct KCMessage:
   { "v": 2, "kind": "text", "text": { "content": "Hello Bob!" } }

2. Determine delivery address (see Address Rotation):
   to_address = resolve_sending_address(session, room)

3. Encrypt with Signal Protocol:
   (ciphertext, new_receiving_addr) = signal_encrypt(kcmessage_json, remote_address)

4. If new_receiving_addr returned:
   Subscribe to derive_nostr_address(new_receiving_addr) on relays

5. Build kind 1059 event:
   {
     "kind": 1059,
     "pubkey": "<fresh ephemeral keypair>",
     "content": "<base64(ciphertext)>",
     "tags": [["p", "<to_address>"]],
     "created_at": "<real unix timestamp>"
   }

6. Publish to relay(s)
```

#### Decrypt Message

```
1. Receive kind 1059 event on a listening address
2. Decode: ciphertext = base64_decode(event.content)
3. Detect PrekeyMessage: PreKeySignalMessage::try_from(ciphertext)
   (Do NOT use ciphertext[0] byte for detection — Signal is protobuf-encoded)
4. If PrekeyMessage: parse signalPrekeyAuth from decrypted content, verify Schnorr sig
5. Decrypt with Signal Protocol → KCMessage JSON
6. Update peer's sending address from session state (see Address Rotation)
7. Parse KCMessage: check v == 2, route by kind
```

## Address Rotation

This is the core privacy mechanism for communication over a public relay network.

### Problem

The original Signal Protocol operates over a private network. On Nostr, a public network, if the sender's or receiver's address remains unchanged, an observer can analyze identity and communication patterns from frequency, timing, and volume — even without decrypting content.

### Solution: Ratchet-Derived Addresses

Each DH ratchet step generates a new Nostr receiving address, providing **message unlinkability**. The address is derived by a cross-curve one-way mapping from Curve25519 ratchet state to secp256k1 Nostr address:

```
derive_receiving_address(private_key: [u8; 32], public_key: [u8; 33]) -> String:
  // Step 1: Curve25519 ECDH
  shared_secret = private_key.calculate_agreement(public_key)

  // Step 2: Pad
  seed = [0xFF; 32] || shared_secret

  // Step 3: Hash
  hash = SHA256(seed)[0..32]

  // Step 4: Derive secp256k1 key
  secret_key = secp256k1_secret_key(hash)

  // Step 5: Return Nostr address
  return x_only_public_key(secret_key).hex()
```

### When Addresses Rotate

- **After encrypt:** `new_receiving_addr` is YOUR new receiving address. Subscribe to it on the relay.
- **After decrypt:** `session.bobAddress` updates to the PEER's new receiving address. Use it as the destination next time you send.
- **Rotation is directional:** The DH ratchet only advances on direction change (receive then send, or vice versa). Sending 5 messages in a row does NOT rotate the address.

### firstInbox Lifecycle

`firstInbox` is a temporary receiving address used before the ratchet activates:

1. Alice generates `firstInbox` and includes it in her `friendRequest`
2. Bob sends his `friendApprove` (and possibly follow-up messages) to `firstInbox`
3. Once Alice receives a message on a ratchet-derived address, she clears `firstInbox` — the ratchet is now active

### Sliding Window

Implementations SHOULD maintain a sliding window of 2–3 receiving addresses per peer:

```
addresses = [addr_n-1, addr_n]  // listen on both
// When addr_n+1 is derived → drop addr_n-1, add addr_n+1
```

Old addresses are removed from relay subscriptions.

### Sender Address Resolution

When sending, resolve the target address in this priority order:

```
1. session.bobAddress exists and is NOT a raw Signal identity key (0x05 prefix)?
   → to_address = derive_nostr_address(bobAddress)

2. bobAddress is raw Signal identity key or missing?
   → room.peerFirstInbox exists? Use peerFirstInbox
   → else: peer's npub (Nostr identity pubkey)
```

### Lifecycle Example

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

### Subscription Filter

A client subscribes to all active receiving addresses:

```json
{
  "kinds": [1059],
  "#p": [
    "<npub>",
    "<firstInbox_1>",
    "<ratchet_addr_peer1_a>", "<ratchet_addr_peer1_b>",
    "<ratchet_addr_peer2_a>", "<ratchet_addr_peer2_b>"
  ],
  "since": "<unix_timestamp>"
}
```

## Concerns in Public Networks

Private communication over Nostr operates in a more complex environment than the private infrastructure Signal Protocol was designed for.

### Relay Reliability

Although Nostr relay nodes carry risks such as censorship and message discarding, as long as at least one relay is honest, confidential communication between Alice and Bob can be achieved. Implementations SHOULD connect to multiple relays for redundancy.

### Network Analysis

The random ephemeral sender keys and ratchet-derived address rotation make traffic analysis between sending and receiving addresses as difficult as possible. However, analysis based on behavioral patterns or IP addresses remains a concern. Users MAY additionally use Tor or VPN for IP-level protection.

### Eavesdropping

The Double Ratchet algorithm ensures the confidentiality of each message and provides forward secrecy and post-compromise security even if a key is leaked. The PQXDH initial handshake additionally protects against future quantum computing threats.

### Sustainable Incentive Compatibility

Relays can collect fees for forwarding messages, ensuring the network's sustainability and preventing spam. Participants MAY pay fees using Cashu ecash stamps — see the ecash stamp specification for details.

## Security Considerations

### Security Assumptions

1. **Computational hardness:** The security relies on AES-256, Curve25519 ECDH, ML-KEM 1024 (Kyber), and SHA-256/SHA-512. An adversary cannot break these in any time frame relevant to real-world applications.
2. **Honest relay:** At least one relay honestly delivers all messages between communicating parties. Relays MAY analyze or attempt to break encrypted content, but cannot succeed given assumption 1.
3. **PRNG quality:** The RNG provides sufficient randomness. Implementations MUST use cryptographically secure PRNGs; self-implementations MUST NOT be used.

### Security Goals

1. **Confidentiality:** An adversary cannot obtain plaintext from ciphertext. AES-256 provides the symmetric encryption; the Double Ratchet minimizes consequences of key leakage through continuous key evolution.
2. **Integrity:** Messages cannot be modified without detection. HMAC-SHA256 (internal to libsignal) verifies data integrity.
3. **Authentication:** Signal Protocol authenticates parties through the PQXDH handshake and the ongoing ratchet. The `globalSign` Schnorr signature binds Nostr identity to Signal identity at session establishment.
4. **Non-repudiation:** Not a primary goal. Non-repudiation requires retaining all messages from session start.

### Threat Model

1. **Phishing Client:** Attackers can forge apps or inject malicious code. App providers SHOULD strengthen verification of installation package fingerprints.
2. **Message Forgery:** Relays can truncate or attempt to modify ciphertext. HMAC verification (built into libsignal's AES-256-CBC mode) detects all tampering.
3. **Denial of Service:** Relays can refuse to forward messages. Address rotation ensures communicators frequently change addresses, reducing targeted denial-of-service effectiveness. Using multiple relays provides additional resilience.
4. **Traffic Identification:** Despite address rotation, relays can track communication habits based on IP addresses and message patterns. Users MAY use Tor/VPN, switch relays, or fetch unrelated encrypted messages to increase traffic obfuscation.

## Implementation Reference

### Reference Implementation

The reference implementation is [libkeychat](https://github.com/nicobao/keychat-protocol), built on top of:

- [libsignal](https://github.com/signalapp/libsignal) — Signal Protocol (PQXDH + Double Ratchet)
- [nostr-rs](https://github.com/rust-nostr/nostr) — Nostr protocol primitives (NIP-44, NIP-59)

### Database Design (Informative)

> **Note:** The following database schema is from the reference implementation and is NOT normative. Implementations MAY use any storage mechanism that preserves the required protocol state.

The basic persistent state includes: identity keys, ratchet state, session state, opponent signed keys, and prekeys.

```sql
identity (
  id integer primary key AUTOINCREMENT,
  nextPrekeyId integer,
  registrationId integer,
  address text,
  privateKey text,
  publicKey text
);

session_status (
  id integer primary key AUTOINCREMENT,
  aliceSenderRatchetKey text,
  address text,
  record text,
  bobSenderRatchetKey text,
  bobAddress text,
  aliceAddresses text
);
```

## References

[1] The PQXDH Key Agreement Protocol, https://signal.org/docs/specifications/pqxdh/

[2] The X3DH Key Agreement Protocol, https://signal.org/docs/specifications/x3dh/

[3] The Double Ratchet Algorithm, https://signal.org/docs/specifications/doubleratchet/

[4] NIP-17: Private Direct Messages, https://github.com/nostr-protocol/nips/blob/master/17.md

[5] NIP-44: Encrypted Payloads (Versioned), https://github.com/nostr-protocol/nips/blob/master/44.md

[6] NIP-59: Gift Wrap, https://github.com/nostr-protocol/nips/blob/master/59.md

[7] libsignal in Rust, https://github.com/signalapp/libsignal

[8] Not in The Prophecies: Practical Attacks on Nostr, https://crypto-sec-n.github.io/
