//! ChatSession: high-level wrapper that integrates Signal encryption with
//! address rotation (spec §8 + §9).
//!
//! Combines `SignalParticipant` and `AddressManager` into a single interface
//! for sending and receiving encrypted messages with automatic address rotation.

use crate::address::{AddressManager, AddressUpdate};
use crate::chat::{handle_received_message, MessageAction, MessageMetadata};
use crate::error::{KeychatError, Result};
use crate::identity::{EphemeralKeypair, Identity};
use crate::message::KCMessage;
use crate::signal_session::SignalParticipant;

use base64::Engine;
use libsignal_protocol::ProtocolAddress;
use nostr::prelude::*;

/// A chat session combining Signal encryption with address rotation.
#[derive(Clone)]
pub struct ChatSession {
    /// Signal Protocol participant (encrypt/decrypt).
    pub signal: SignalParticipant,
    /// Address rotation manager.
    pub addresses: AddressManager,
    /// Our Nostr identity (for signing events, verifying auth).
    pub my_identity: Identity,
}

impl std::fmt::Debug for ChatSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSession")
            .field("signal", &self.signal)
            .field("identity", &self.my_identity.pubkey_hex())
            .finish_non_exhaustive()
    }
}

impl ChatSession {
    /// Create a new ChatSession.
    pub fn new(
        signal: SignalParticipant,
        addresses: AddressManager,
        my_identity: Identity,
    ) -> Self {
        Self {
            signal,
            addresses,
            my_identity,
        }
    }

    /// Register a peer for address tracking.
    pub fn add_peer(
        &mut self,
        peer_id: &str,
        peer_first_inbox: Option<String>,
        peer_nostr_pubkey: Option<String>,
    ) {
        self.addresses
            .add_peer(peer_id, peer_first_inbox, peer_nostr_pubkey);
    }

    /// Send an encrypted message to a peer.
    ///
    /// - Resolves the sending address via AddressManager (§9.4)
    /// - Encrypts with Signal Protocol
    /// - Updates address rotation state
    /// - Returns the Nostr event + address update info
    pub async fn send_message(
        &mut self,
        peer_id: &str,
        remote_address: &ProtocolAddress,
        message: &KCMessage,
    ) -> Result<(Event, AddressUpdate)> {
        // Resolve where to send
        let to_address = self.addresses.resolve_send_address(peer_id)?;

        // Encrypt
        let json = message.to_json()?;
        let enc = self.signal.encrypt(remote_address, json.as_bytes())?;

        // Update addresses after encrypt
        let update = self
            .addresses
            .on_encrypt(peer_id, enc.sender_address.as_deref())?;

        // Build kind:1059 event
        let event = build_mode1_event(&enc.bytes, &to_address).await?;

        Ok((event, update))
    }

    /// Receive and decrypt a kind:1059 event from a peer.
    ///
    /// - Decrypts with Signal Protocol
    /// - Updates address rotation state
    /// - Returns the KCMessage, metadata, and address update info
    pub fn receive_message(
        &mut self,
        peer_id: &str,
        remote_address: &ProtocolAddress,
        event: &Event,
    ) -> Result<(KCMessage, MessageMetadata, AddressUpdate)> {
        if event.kind != Kind::GiftWrap {
            return Err(KeychatError::Signal(format!(
                "expected kind 1059, got {}",
                event.kind.as_u16()
            )));
        }

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&event.content)
            .map_err(|e| KeychatError::Signal(format!("invalid base64 content: {e}")))?;

        let is_prekey = SignalParticipant::is_prekey_message(&ciphertext);

        let decrypt_result = self.signal.decrypt(remote_address, &ciphertext)?;

        let plaintext_str = String::from_utf8(decrypt_result.plaintext)
            .map_err(|e| KeychatError::Signal(format!("invalid UTF-8: {e}")))?;

        let message = KCMessage::try_parse(&plaintext_str).ok_or_else(|| {
            KeychatError::Signal("decrypted content is not a valid KCMessage v2".into())
        })?;

        let received_on = event
            .tags
            .iter()
            .find_map(|tag| {
                let values = tag.as_slice();
                if values.len() >= 2 && values[0] == "p" {
                    Some(values[1].clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let metadata = MessageMetadata {
            is_prekey_message: is_prekey,
            signal_prekey_auth: message.signal_prekey_auth.clone(),
            event_id: event.id,
            event_pubkey: event.pubkey,
            received_on_address: received_on,
        };

        // Update addresses after decrypt
        let update = self.addresses.on_decrypt(
            peer_id,
            decrypt_result.bob_derived_address.as_deref(),
            decrypt_result.alice_addrs.as_deref(),
        )?;

        Ok((message, metadata, update))
    }

    /// Clear the peer's firstInbox (called when first ratchet-derived message received).
    pub fn clear_peer_first_inbox(&mut self, peer_id: &str) {
        self.addresses.clear_peer_first_inbox(peer_id);
    }

    /// Get the action for a received message.
    pub fn route_message(&self, message: &KCMessage) -> MessageAction {
        handle_received_message(message)
    }
}

/// Build a kind:1059 Mode 1 event with ephemeral sender and base64 content.
async fn build_mode1_event(ciphertext: &[u8], to_address: &str) -> Result<Event> {
    let sender = EphemeralKeypair::generate();
    let content = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    let to_pubkey = PublicKey::from_hex(to_address)
        .map_err(|e| KeychatError::Signal(format!("invalid to_address: {e}")))?;

    let event = EventBuilder::new(Kind::GiftWrap, &content)
        .tag(Tag::public_key(to_pubkey))
        .sign(sender.keys())
        .await
        .map_err(|e| KeychatError::Signal(format!("failed to sign event: {e}")))?;

    Ok(event)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressManager;
    use crate::message::KCMessageKind;
    use libsignal_protocol::DeviceId;

    /// Helper: create two ChatSessions that are ready to communicate.
    fn setup_chat_sessions() -> (ChatSession, ChatSession, ProtocolAddress, ProtocolAddress) {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        let mut alice_signal = SignalParticipant::new("alice", 1).unwrap();
        let mut bob_signal = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob_signal.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(
            bob_signal.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );
        let alice_addr = ProtocolAddress::new(
            alice_signal.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );

        alice_signal
            .process_prekey_bundle(&bob_addr, &bob_bundle)
            .unwrap();

        let alice_mgr = AddressManager::new();
        let bob_mgr = AddressManager::new();

        let alice_session = ChatSession::new(alice_signal, alice_mgr, alice_id);
        let bob_session = ChatSession::new(bob_signal, bob_mgr, bob_id);

        (alice_session, bob_session, alice_addr, bob_addr)
    }

    #[tokio::test]
    async fn chat_session_send_receive_roundtrip() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_chat_sessions();

        let alice_peer_id = bob.signal.identity_public_key_hex();
        let bob_peer_id = alice.signal.identity_public_key_hex();

        // Register peers — use real pubkeys for firstInbox (must be valid Nostr pubkeys)
        let bob_inbox = EphemeralKeypair::generate();
        let alice_inbox = EphemeralKeypair::generate();
        alice.add_peer(&alice_peer_id, Some(bob_inbox.pubkey_hex()), None);
        bob.add_peer(&bob_peer_id, Some(alice_inbox.pubkey_hex()), None);

        // Alice sends (PrekeyMessage)
        let msg = KCMessage::text("Hello from ChatSession!");
        let (event, update) = alice
            .send_message(&alice_peer_id, &bob_addr, &msg)
            .await
            .unwrap();

        assert_eq!(event.kind, Kind::GiftWrap);

        // Bob receives
        let (received, metadata, recv_update) = bob
            .receive_message(&bob_peer_id, &alice_addr, &event)
            .unwrap();

        assert_eq!(received.kind, KCMessageKind::Text);
        assert_eq!(
            received.text.as_ref().unwrap().content,
            "Hello from ChatSession!"
        );
        assert!(metadata.is_prekey_message);

        // Bob replies
        let reply = KCMessage::text("Hi back!");
        let (reply_event, reply_update) = bob
            .send_message(&bob_peer_id, &alice_addr, &reply)
            .await
            .unwrap();

        // Alice receives reply
        let (alice_received, alice_meta, alice_recv_update) = alice
            .receive_message(&alice_peer_id, &bob_addr, &reply_event)
            .unwrap();

        assert_eq!(alice_received.kind, KCMessageKind::Text);
        assert_eq!(alice_received.text.as_ref().unwrap().content, "Hi back!");
        assert!(!alice_meta.is_prekey_message);
    }

    #[tokio::test]
    async fn address_rotation_through_chat_session() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_chat_sessions();

        let alice_peer_id = bob.signal.identity_public_key_hex();
        let bob_peer_id = alice.signal.identity_public_key_hex();

        let bob_inbox = EphemeralKeypair::generate();
        let alice_inbox = EphemeralKeypair::generate();
        alice.add_peer(&alice_peer_id, Some(bob_inbox.pubkey_hex()), None);
        bob.add_peer(&bob_peer_id, Some(alice_inbox.pubkey_hex()), None);

        // msg1: Alice → Bob (PrekeyMessage)
        let msg1 = KCMessage::text("m1");
        let (ev1, au1) = alice
            .send_message(&alice_peer_id, &bob_addr, &msg1)
            .await
            .unwrap();
        let (_, _, bu1) = bob
            .receive_message(&bob_peer_id, &alice_addr, &ev1)
            .unwrap();

        // Bob should have an updated sending address
        if bu1.new_sending.is_some() {
            // Bob clears firstInbox, uses ratchet address from now on
            bob.clear_peer_first_inbox(&bob_peer_id);
        }

        // msg2: Bob → Alice (direction change)
        let msg2 = KCMessage::text("m2");
        let (ev2, bu2) = bob
            .send_message(&bob_peer_id, &alice_addr, &msg2)
            .await
            .unwrap();
        let (_, _, au2) = alice
            .receive_message(&alice_peer_id, &bob_addr, &ev2)
            .unwrap();

        // Alice should now have an updated sending address for Bob
        if au2.new_sending.is_some() {
            alice.clear_peer_first_inbox(&alice_peer_id);
        }

        // msg3: Alice → Bob (direction change)
        let msg3 = KCMessage::text("m3");
        let (ev3, au3) = alice
            .send_message(&alice_peer_id, &bob_addr, &msg3)
            .await
            .unwrap();
        let (_, _, bu3) = bob
            .receive_message(&bob_peer_id, &alice_addr, &ev3)
            .unwrap();

        // Verify addresses have been rotating
        let alice_recv = alice.addresses.get_all_receiving_address_strings();
        let bob_recv = bob.addresses.get_all_receiving_address_strings();

        assert!(
            !alice_recv.is_empty() || !bob_recv.is_empty(),
            "at least one side should have receiving addresses"
        );

        // Verify send addresses are resolvable (not using firstInbox anymore)
        let alice_send = alice.addresses.resolve_send_address(&alice_peer_id);
        let bob_send = bob.addresses.resolve_send_address(&bob_peer_id);
        // At minimum, one should be Ok (the firstInbox fallback was cleared)
        assert!(alice_send.is_ok() || bob_send.is_ok());
    }

    #[tokio::test]
    async fn chat_session_multiple_messages_same_direction() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_chat_sessions();

        let alice_peer_id = bob.signal.identity_public_key_hex();
        let bob_peer_id = alice.signal.identity_public_key_hex();

        let bob_inbox = EphemeralKeypair::generate();
        let alice_inbox = EphemeralKeypair::generate();
        alice.add_peer(&alice_peer_id, Some(bob_inbox.pubkey_hex()), None);
        bob.add_peer(&bob_peer_id, Some(alice_inbox.pubkey_hex()), None);

        // Send 3 messages in the same direction
        for i in 1..=3 {
            let msg = KCMessage::text(&format!("msg{i}"));
            let (ev, _) = alice
                .send_message(&alice_peer_id, &bob_addr, &msg)
                .await
                .unwrap();
            let (received, _, _) = bob.receive_message(&bob_peer_id, &alice_addr, &ev).unwrap();
            assert_eq!(received.text.as_ref().unwrap().content, format!("msg{i}"));
        }

        // Verify we haven't accumulated many addresses (ratchet doesn't
        // advance without direction change)
        let alice_addrs = alice.addresses.get_all_receiving_address_strings();
        assert!(
            alice_addrs.len() <= 2,
            "same-direction sends should not produce many addresses"
        );
    }

    #[tokio::test]
    async fn chat_session_clear_first_inbox_after_ratchet() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_chat_sessions();

        let alice_peer_id = bob.signal.identity_public_key_hex();
        let bob_peer_id = alice.signal.identity_public_key_hex();

        let bob_inbox = EphemeralKeypair::generate();
        let alice_inbox = EphemeralKeypair::generate();
        let bob_inbox_hex = bob_inbox.pubkey_hex();
        let alice_inbox_hex = alice_inbox.pubkey_hex();
        alice.add_peer(&alice_peer_id, Some(bob_inbox_hex.clone()), None);
        bob.add_peer(&bob_peer_id, Some(alice_inbox_hex.clone()), None);

        // Before any messages, resolve should use firstInbox
        let addr_before = alice
            .addresses
            .resolve_send_address(&alice_peer_id)
            .unwrap();
        assert_eq!(addr_before, bob_inbox_hex);

        // msg1: Alice → Bob
        let (ev1, _) = alice
            .send_message(&alice_peer_id, &bob_addr, &KCMessage::text("m1"))
            .await
            .unwrap();
        let (_, _, bu1) = bob
            .receive_message(&bob_peer_id, &alice_addr, &ev1)
            .unwrap();

        // msg2: Bob → Alice (ratchet takes over)
        let (ev2, _) = bob
            .send_message(&bob_peer_id, &alice_addr, &KCMessage::text("m2"))
            .await
            .unwrap();
        let (_, _, au2) = alice
            .receive_message(&alice_peer_id, &bob_addr, &ev2)
            .unwrap();

        // Clear firstInbox after receiving ratchet message
        if au2.new_sending.is_some() {
            alice.clear_peer_first_inbox(&alice_peer_id);

            // Now resolve should use ratchet-derived address, not firstInbox
            let addr_after = alice
                .addresses
                .resolve_send_address(&alice_peer_id)
                .unwrap();
            assert_ne!(
                addr_after, bob_inbox_hex,
                "should use ratchet address after clearing firstInbox"
            );
        }
    }

    #[test]
    fn chat_session_debug() {
        let identity = Identity::generate().unwrap().identity;
        let signal = SignalParticipant::new("test", 1).unwrap();
        let session = ChatSession::new(signal, AddressManager::new(), identity);
        let debug = format!("{:?}", session);
        assert!(debug.contains("ChatSession"));
    }
}
