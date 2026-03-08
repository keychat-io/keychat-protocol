# Understanding Keychat Through Mail

Imagine sending a letter. You write your message on a sheet of paper, put it in an envelope, write the recipient's name and address, your own name and return address, stick on a stamp, and drop it in the mailbox. The post office reads the envelope and delivers it.

This process has worked for centuries. Keychat does fundamentally the same thing — delivering a message from one person to another — but it redesigns every element of the process. This article uses the mail analogy to explain how the Keychat protocol works, across five layers.

## I. Identity: Self-Generated, Self-Owned

In traditional mail, your name and address are bound together, written on the envelope, visible to both the post office and the recipient.

In Keychat, your identity is a Nostr keypair — think of it as a name you give yourself. You generate it on your own, no registration with any authority required. No service provider can revoke it, and no one can impersonate it (because only you hold the private key).

Unlike traditional mail, your name doesn't need to appear on the envelope. Neither the sender's name nor the recipient's name is written there. Your identity exists only inside the sealed letter — only the recipient learns who sent it after opening.

## II. Encryption: Every Letter Gets a Different Lock

A traditional envelope is made of paper — the postal worker shouldn't open it, but technically could.

Every Keychat message is encrypted with Signal Protocol. Think of each letter being placed in a combination lockbox that only the recipient can open. But Keychat goes further: every letter uses a different lock and key.

This is thanks to the Double Ratchet algorithm. After each communication, the ratchet advances one step, deriving entirely new encryption keys. Old keys are immediately destroyed. This produces two important properties:

- **Forward secrecy**: Even if someone steals your current key, they cannot open previous letters — each letter used a different lock, and the old keys no longer exist
- **Backward secrecy** (post-compromise recovery): Even if a key is stolen, the next communication will derive new keys, locking the attacker out again

For users, all of this happens automatically in the background — you just write and read messages.

## III. Addressing: The Envelope Is Nearly Blank

This is where Keychat diverges most from traditional mail.

A traditional envelope carries two sets of information: the recipient's name and address, and the sender's name and address. A Keychat envelope needs only one thing: **the recipient's current receiving address**. The sender's address is randomly generated each time — random means effectively none. The relay cannot determine who sent it.

And the receiving address itself keeps changing. Keychat repurposes the Double Ratchet algorithm — originally designed only to derive encryption keys — to also derive receiving addresses. Each time the DH ratchet advances, it updates both the encryption keys and the receiving addresses. After one round-trip of communication, both parties' receiving addresses are updated and old addresses become invalid. It's like moving to a new house after every letter exchange, with only the other party knowing your new address.

Random sender addresses, rotating receiver addresses — every letter looks to the relay like one stranger writing to another, completely unlinkable. No one can collect your mail by watching a single address, and even the relay cannot construct a social graph of who communicates with whom.

**Adding a friend: the one exception.** You know someone's identity (Nostr public key), but there are no rotating addresses between you yet. You prepare a special introduction letter (Hello) containing your identity, encryption keys, and a temporary receiving address, wrap it in a sealed package (NIP-17 Gift Wrap), and send it directly to the other party's **identity** — this is the only time identity serves as a receiving address. The recipient opens the package, establishes an encrypted channel (Signal session), and sends their first reply to your temporary address. From the moment you reply to their first letter, ratchet-derived receiving addresses take over and both parties enter the continuously rotating address flow.

## IV. Transport: An Open Relay Network

Traditional mail depends on a national postal system. Keychat's relays (Nostr relays) form an open network — anyone can run their own relay.

Each letter can be posted to multiple relays simultaneously, and the recipient collects from multiple relays simultaneously. It's like dropping the same letter into mailboxes at several different post offices while the recipient checks their box at each one. As long as any single post office delivers successfully, the letter arrives. No single point of failure, no censorship bottleneck, no monopoly.

## V. Stamps: Turning Relays into Post Offices

Some relays charge postage. Keychat handles this with ecash stamps — anonymous micropayments using Cashu tokens.

The analogy is literal: you buy a stamp (a small ecash token, typically a few satoshis) and attach it to the envelope. The relay validates the stamp before delivering the letter. Stamps are bearer instruments — the relay knows the stamp is valid, but not who bought it. The stamp is attached outside the Event as a transport-layer credential, not part of the letter content, and is not forwarded to the recipient.

```
Free relay:   ["EVENT"]
Paid relay:   ["EVENT", "<stamp>"]
```

Relays get paid for delivery, users get spam filtering, and neither party sacrifices privacy. With stamps, relays truly become post offices — not just passive message pipes, but operators providing paid delivery services. When every relay can set its own pricing, an open postal market naturally emerges.

---

Setting the mail analogy aside, Keychat is a communication protocol where users self-generate their identity with no dependency on any service provider; message content is end-to-end encrypted and readable only by the recipient, with keys continuously updated via the ratchet for both forward and backward secrecy; receiving addresses are decoupled from identity and continuously rotate while sender addresses are randomly generated each time, making metadata nearly invisible to relays; relays form an open network that anyone can operate and users freely choose among; and ecash stamps turn relays into paid post offices, forming a freely competitive delivery market. These five layers — identity, encryption, addressing, transport, and stamps — combined together, make sovereign communication.
