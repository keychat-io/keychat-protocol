# Keychat Protocol

Protocol specifications, reference implementation, and NIPs for the [Keychat](https://keychat.io) ecosystem.

## Contents

- **[libkeychat](libkeychat/)** — Rust implementation of the Keychat protocol: sovereign, end-to-end encrypted messaging over Nostr relays using Signal Protocol encryption
- **[SPEC.md](libkeychat/SPEC.md)** — Authoritative protocol specification (v0.4.0-draft)
- **[Client Guide](libkeychat/docs/client-guide.md)** — KeychatClient API guide and usage examples

### [NIPs](nips/)

Nostr Implementation Possibilities proposed by Keychat:

| NIP | Title | Status |
|-----|-------|--------|
| [NIP-XX: Ecash Token as Nostr Note Stamp](nips/nip-estamp.md) | Anonymous per-event micropayments to relays using Cashu ecash | Draft |
