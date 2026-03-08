# Keychat Protocol

Keychat is a sovereign messaging stack that integrates five layers into one cohesive protocol: **identity** (BIP-39 mnemonic → Nostr secp256k1 keypair, self-custodial with no server dependency), **transport** (Nostr relay network, decentralized and replaceable), **encryption** (Signal Protocol Double Ratchet and X3DH, with peer-to-peer key exchange via NIP-17 Gift Wrap instead of a central key server), **routing** (ratchet-derived Nostr addresses that rotate with every message, making traffic analysis impractical), and **stamps** (Cashu ecash tokens attached to messages as anonymous micropayments to relays). Where Signal Protocol is a cryptographic primitive for end-to-end encryption, Keychat is the full communication layer that makes sovereign, private, and economically sustainable messaging possible without any central authority.

## Contents

- **[libkeychat](libkeychat/)** — Rust implementation of the Keychat protocol: sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption
- **[SPEC.md](libkeychat/SPEC.md)** — Authoritative protocol specification (v0.4.0-draft)
- **[Client Guide](libkeychat/docs/client-guide.md)** — KeychatClient API guide and usage examples

### [NIPs](nips/)

Nostr Implementation Possibilities proposed by Keychat:

| NIP | Title | Status |
|-----|-------|--------|
| [NIP-XX: Ecash Token as Nostr Note Stamp](nips/nip-estamp.md) | Anonymous per-event micropayments to relays using Cashu ecash | Draft |
