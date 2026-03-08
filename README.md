# Keychat Protocol

Keychat protocol is a sovereign messaging stack that integrates five layers:

- **Identity** — Nostr keypair, self-custodial with no server dependency
- **Transport** — Nostr relay network, open and self-hostable
- **Encryption** — Signal Protocol for 1-to-1 and small group chats, MLS for large group messaging
- **Addressing** — Receiving and sending addresses are decoupled from identity and continuously rotate
- **Stamps** — Cashu ecash tokens attached to messages as anonymous micropayments to relays

## Contents

- **[libkeychat](libkeychat/)** — Rust implementation of the Keychat protocol: sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption
- **[Keychat Spec](docs/SPEC.md)** — Authoritative protocol specification (v0.4.0-draft)
- **[Client Guide](libkeychat/docs/client-guide.md)** — KeychatClient API guide and usage examples

### [NIPs](nips/)

Nostr Implementation Possibilities proposed by Keychat:

| NIP | Title | Status |
|-----|-------|--------|
| [NIP-XX: Ecash Token as Nostr Note Stamp](nips/nip-estamp.md) | Anonymous per-event micropayments to relays using Cashu ecash | Draft |
