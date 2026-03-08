# Keychat Protocol

Keychat protocol is a sovereign messaging stack that integrates five layers: **identity** (BIP-39 mnemonic → Nostr secp256k1 keypair, self-custodial with no server dependency), **transport** (Nostr relay network, decentralized and replaceable), **encryption** (Signal Protocol for 1-to-1 chats, MLS for group messaging), **routing** (independent receiving and sending addresses that continuously rotate), and **stamps** (Cashu ecash tokens attached to messages as anonymous micropayments to relays).

## Contents

- **[libkeychat](libkeychat/)** — Rust implementation of the Keychat protocol: sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption
- **[SPEC.md](libkeychat/SPEC.md)** — Authoritative protocol specification (v0.4.0-draft)
- **[Client Guide](libkeychat/docs/client-guide.md)** — KeychatClient API guide and usage examples

### [NIPs](nips/)

Nostr Implementation Possibilities proposed by Keychat:

| NIP | Title | Status |
|-----|-------|--------|
| [NIP-XX: Ecash Token as Nostr Note Stamp](nips/nip-estamp.md) | Anonymous per-event micropayments to relays using Cashu ecash | Draft |
