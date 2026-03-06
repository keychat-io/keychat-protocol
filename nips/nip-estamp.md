NIP-XX
======

Ecash Token as Nostr Note Stamp
--------------------------------

`draft` `optional` `relay` `client`

This NIP defines a mechanism for clients to attach ecash tokens (Cashu) to Nostr events as **stamps** — anonymous per-event micropayments to relays. Stamps solve two fundamental problems for the Nostr relay ecosystem: spam prevention and relay sustainability.

## Motivation

Nostr relays face a dilemma: they must accept events from anyone (openness), but this makes them vulnerable to spam. Existing approaches have significant trade-offs:

- **Proof of Work** ([NIP-13](13.md)) penalizes mobile and low-power devices disproportionately.
- **NIP-42 authentication** binds a pubkey to the relay's access-control relationship, creating a trackable persistent identity between user and relay.
- **Subscription models** require accounts and payment identity, contradicting Nostr's ethos.

Ecash stamps offer a different approach: **anonymous, per-event micropayments**. A user attaches a small ecash token (e.g., 1 sat) to each event. The relay redeems the token before accepting the event. No account, no identity, no subscription — just a stamp on each message, like postage on a letter.

This is not a new idea. [Keychat](https://keychat.io) has used Cashu ecash tokens as message stamps in production since 2024. This NIP standardizes the mechanism so any Nostr relay and client can adopt it.

### Why Ecash

Ecash (specifically [Cashu](https://cashu.space)) has properties that make it uniquely suited for this:

- **Anonymous**: the relay cannot link stamps to a user identity. Each token is a bearer instrument — whoever holds it can spend it, and the mint cannot trace redemption back to issuance.
- **Instant**: no on-chain confirmation needed. Token redemption is a single HTTP call to the mint.
- **Micro-scale**: designed for sub-cent payments. 1 sat ≈ $0.001 is viable.
- **No account required**: the user holds tokens locally. No registration, no login, no KYC.
With stamps, a relay becomes a **post office**: it delivers your message for a small fee, without knowing who you are.

## Overview

```
  Client                       Relay
    |                            |
    |-- HTTP GET (NIP-11) ------>|
    |<-- fee schedule -----------|  (amount, unit, mints)
    |                            |
    |-- ["EVENT", <event>,  ---->|
    |     "cashuA..."]           |
    |                            |  relay redeems token with mint
    |<-- ["OK", <id>, true] ----|  (accepted)
    |                            |
    |-- ["EVENT", <event>] ----->|  (no stamp)
    |<-- ["OK", <id>, false, -->|  (rejected: "stamp required")
    |     "blocked: stamp        |
    |      required"]            |
```

## Specification

### 1. Fee Discovery (Relay → Client)

Relays advertise stamp requirements in their [NIP-11](11.md) relay information document by adding a `stamp` field inside `fees`:

```json
{
  "limitation": {
    "payment_required": true
  },
  "fees": {
    "stamp": [
      {
        "amount": 1,
        "unit": "sat",
        "mints": ["https://mint.example.com"]
      }
    ]
  }
}
```

Fields:

- `amount` (integer, REQUIRED): the cost per event in the specified unit.
- `unit` (string, REQUIRED): currency unit. MUST be `"sat"` or `"msat"`.
- `mints` (array of strings, REQUIRED): list of Cashu mint URLs the relay accepts. Clients MUST use one of these mints.
- `kinds` (array of integers, OPTIONAL): if present, only these event kinds require stamps. All other kinds are free. If absent, ALL kinds require stamps.

A relay MAY define multiple entries in the `stamp` array with different `kinds` to set different prices for different event kinds:

```json
{
  "fees": {
    "stamp": [
      {
        "kinds": [1, 6, 7],
        "amount": 1,
        "unit": "sat",
        "mints": ["https://mint.example.com"]
      },
      {
        "kinds": [1063],
        "amount": 5,
        "unit": "sat",
        "mints": ["https://mint.example.com"]
      }
    ]
  }
}
```

If a kind matches multiple entries, the client SHOULD use the first matching entry.

Clients SHOULD fetch and cache the NIP-11 document on connection and periodically refresh it.

### 2. Attaching a Stamp (Client → Relay)

When publishing an event to a relay that requires stamps, the client appends a Cashu token as the **third element** of the `EVENT` message array:

```json
["EVENT", <event JSON>, "<cashu_token>"]
```

Where:

- The first element is the string `"EVENT"`.
- The second element is the standard Nostr event object (as defined in [NIP-01](01.md)).
- The third element is a [Cashu token](https://github.com/cashubtc/nuts) string (e.g., `"cashuA..."` for V3 tokens or `"cashuB..."` for V4 tokens).

Example:

```json
["EVENT", {"id":"ab..","pubkey":"cd..","kind":1,"content":"hello","tags":[],"created_at":1700000000,"sig":"ef.."}, "cashuAeyJwcm9vZnMi..."]
```

#### Why Outside the Event

The stamp is deliberately placed **outside** the signed event object for three critical reasons:

1. **Multi-relay independence**: Users typically publish to multiple relays simultaneously. Each relay requires its own stamp. If the stamp were inside the event (e.g., as a tag), the event signature would include it, meaning different stamps would produce different event IDs. By keeping stamps out-of-band, the same signed event can be sent to many relays, each with a different stamp attached at the transport layer.

2. **Mixed relay sets**: Users may connect to both free and paid relays. The same event goes to free relays without a stamp and to paid relays with one. No special handling needed — the event is identical either way.

3. **Separation of concerns**: The stamp is a transport-layer credential between client and relay, like postage on a letter. It is not part of the message content. Other clients fetching the event from the relay do not see or need the stamp — it has already been redeemed.

### 3. Stamp Verification (Relay)

When a relay receives an `EVENT` message:

1. Parse the message array. If a third element exists and is a string, treat it as a stamp token.
2. If the event kind requires a stamp (per the relay's configuration) and no stamp is present, reject with `["OK", <event_id>, false, "blocked: stamp required"]`.
3. If a stamp is present:
   a. Decode the Cashu token.
   b. Verify the token's mint URL is in the relay's accepted mints list.
   c. Verify the total token amount meets the required fee.
   d. **Redeem the token** with the mint (call the mint's `/v1/swap` or `/v1/melt` endpoint). This is the atomic validation step — if redemption succeeds, the token is valid and has been collected. If it fails, the token is invalid, already spent, or the mint is unreachable.
4. If redemption succeeds, accept and store the event normally. The stamp token is NOT stored — it is discarded after redemption.
5. If redemption fails, reject with `["OK", <event_id>, false, "blocked: invalid stamp"]`.

Relays SHOULD implement rate limiting on stamp failures to prevent probing attacks (e.g., max 5 failures per IP per 60 seconds).

Relays MUST NOT store the Cashu token alongside the event. The token is a transport-layer artifact and has no meaning after redemption. Clients fetching events via `REQ` never see stamps.

### 4. Client Behavior

Clients SHOULD:

- On connection, fetch the relay's NIP-11 document to discover stamp requirements.
- Maintain a local Cashu wallet with tokens from mints accepted by their relays.
- Before publishing, check each connected relay's fee schedule. For paid relays, create a fresh Cashu token of the required amount and attach it. For free relays, send the event without a stamp.
- Track stamp spending locally for user transparency (optional).
- If the wallet has insufficient balance, either skip the paid relay or prompt the user.

Clients SHOULD pre-split tokens into small denominations (e.g., 1-sat proofs) to avoid needing to interact with the mint for every event. This enables offline stamp creation.

### 5. Relay Configuration

This section is informational (not normative) and provides guidance for relay operators.

A relay implementing this NIP needs:

1. **A Cashu wallet** to receive and redeem tokens. This can be embedded (e.g., using the [CDK](https://github.com/cashubtc/cdk) library in Rust) or delegated to an external service.

2. **Configuration** specifying:
   - Accepted mint URLs
   - Price per event (may vary by kind)
   - Free kinds (e.g., kind 0 for profiles, kind 3 for contact lists, kind 10002 for relay lists)

3. **NIP-11 advertisement** of the stamp fee schedule.

Example relay configuration:

```toml
[stamp]
enabled = true
unit = "sat"
mints = ["https://mint.example.com"]

# Default price for all kinds
default_price = 1

# Free kinds (no stamp required)
free_kinds = [0, 3, 10002]

# Custom prices for specific kinds
[stamp.prices]
1063 = 5  # file metadata: 5 sats
```

### 6. Privacy Considerations

Ecash stamps preserve user privacy:

- **Relay cannot identify payer**: Cashu tokens are bearer instruments. The relay redeems the token with the mint but learns nothing about who created it. The mint sees a redemption request but cannot link it to the original issuance (blind signatures).
- **No account linkage**: Unlike subscription or authentication models, stamps create no persistent relationship between user and relay.
- **No payment graph**: Each stamp is independent. There is no transaction history linking multiple events to the same payer.
- **Token is discarded**: The stamp is not stored with the event. Other users fetching the event cannot see that a stamp was paid or by whom.

This is fundamentally different from:

| Model | Identity leaked | Persistent relationship | Privacy |
|-------|----------------|------------------------|---------|
| Subscription (Lightning invoice) | Yes (payment hash) | Yes (account) | Low |
| NIP-42 Auth | Yes (pubkey bound to access control) | Yes (session) | Low |
| Proof of Work | No | No | High but penalizes low-power devices |
| **Ecash Stamp** | **No** | **No** | **High** |

### 7. Economic Considerations

At 1 sat (~$0.001) per event:

- A normal user posting 50 notes/day pays ~$0.05/day, ~$1.50/month.
- A spammer sending 100,000 events pays ~$100 — a meaningful deterrent.
- A relay processing 1 million events/day earns ~$1,000/day — enough to sustain infrastructure.

The asymmetry is the point: negligible cost for legitimate users, prohibitive cost for spammers. Relay operators can adjust pricing to find their market equilibrium.

### 8. Backwards Compatibility

This NIP is fully backwards compatible:

- **Old clients, new relay**: If a client sends `["EVENT", <event>]` without a stamp to a stamp-required relay, the relay rejects it with a descriptive `OK` message. The client can detect `payment_required: true` from NIP-11 and inform the user.
- **New clients, old relay**: If a client sends `["EVENT", <event>, "cashuA..."]` to a relay that doesn't understand stamps, the relay SHOULD ignore the extra array element per standard JSON array handling. The event is processed normally.
- **Mixed relay sets**: Clients naturally handle mixed free/paid relays by checking each relay's NIP-11 independently.

## Reference Implementation

### Client: Creating and Attaching a Stamp

```typescript
import { CashuMint, CashuWallet, getEncodedToken } from '@cashu/cashu-ts';

// Initialize wallet with relay's accepted mint
const mint = new CashuMint('https://mint.example.com');
const wallet = new CashuWallet(mint);

// Create a 1-sat stamp
const { send } = await wallet.send(1, proofs);
const token = getEncodedToken({ mint: 'https://mint.example.com', proofs: send });

// Attach to EVENT message
const message = JSON.stringify(["EVENT", signedEvent, token]);
ws.send(message);
```

### Relay: Verifying and Redeeming a Stamp

```rust
use cdk::wallet::Wallet;
use cdk::nuts::Token;

async fn handle_event(msg: Vec<serde_json::Value>, wallet: &Wallet, config: &StampConfig) -> Result<()> {
    let event: Event = serde_json::from_value(msg[1].clone())?;
    let stamp: Option<String> = msg.get(2).and_then(|v| v.as_str()).map(String::from);

    // Check if this kind requires a stamp
    if config.requires_stamp(event.kind) {
        let token_str = stamp.ok_or("stamp required")?;

        // Decode and verify
        let token = Token::from_str(&token_str)?;
        let amount = token.total_amount();
        let mint_url = token.mint_url();

        if amount < config.price_for_kind(event.kind) {
            return Err("insufficient stamp amount");
        }
        if !config.accepted_mints.contains(&mint_url) {
            return Err("mint not accepted");
        }

        // Atomic redeem — this is the validation
        wallet.receive(&token_str).await?;
    }

    // Store event (without stamp)
    db.store_event(&event).await?;
    Ok(())
}
```

## FAQ

**Q: What if a relay goes down after redeeming the stamp but before storing the event?**

A: The stamp is lost. This is acceptable — it's 1 sat. The client can retry with a new stamp. This is no different from a postage stamp on a letter lost in transit.

**Q: Can a malicious relay collect stamps without storing events?**

A: Yes, just as a dishonest post office could take postage without delivering mail. Users mitigate this by choosing reputable relays. The Nostr model already requires users to trust their relays to store and serve events. Stamps don't change this trust model.

**Q: Why Cashu specifically? Why not Lightning invoices?**

A: Lightning invoices require interactive payment flows (generate invoice → pay → confirm). This adds latency to every event publication and requires the user to be online with a Lightning wallet. Cashu tokens are pre-created, non-interactive, and can be attached instantly. They also preserve privacy — Lightning payments can be correlated; Cashu tokens cannot.

## Prior Art

- [Keychat](https://keychat.io): Production use of Cashu stamps for relay anti-spam since 2024.
- [NIP-13](13.md): Proof of Work as spam deterrence (computational cost instead of monetary cost).
- [Hashcash](http://www.hashcash.org/): The original proof-of-work anti-spam system for email (1997).
- [Chaumian ecash](https://en.wikipedia.org/wiki/Ecash): Blind signature-based digital cash (1982).
