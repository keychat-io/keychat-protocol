//! Signal Chat Transport (kind:1059 Mode 1) and SignalPrekeyAuth handling.
//!
//! Phase 4 implementation: wraps Signal sessions into the Nostr transport layer,
//! providing send/receive for encrypted messages as kind:1059 events with
//! ephemeral senders and base64 content.
//!
//! Also implements:
//! - SignalPrekeyAuth creation and verification (§4.6)
//! - KCMessage v2 routing by kind

use crate::error::{KeychatError, Result};
use crate::identity::EphemeralKeypair;
use crate::message::{KCMessage, KCMessageKind, SignalPrekeyAuth};
use crate::signal_keys::{compute_global_sign, verify_global_sign};
use crate::signal_session::SignalParticipant;

use base64::Engine;
use libsignal_protocol::ProtocolAddress;
#[cfg(test)]
use libsignal_protocol::DeviceId;
use nostr::prelude::*;

// ─── MessageMetadata ─────────────────────────────────────────────────────────

/// Metadata about a received encrypted message.
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    /// Whether the message was a Signal PrekeyMessage (first message after session establishment).
    pub is_prekey_message: bool,
    /// SignalPrekeyAuth from the KCMessage envelope (if present).
    pub signal_prekey_auth: Option<SignalPrekeyAuth>,
    /// The Nostr event ID of the received event.
    pub event_id: EventId,
    /// The ephemeral sender pubkey from the Nostr event (NOT the real sender).
    pub event_pubkey: PublicKey,
    /// Which p-tag address this event was delivered to.
    pub received_on_address: String,
}

// ─── MessageAction (KCMessage routing) ──────────────────────────────────────

/// Action to take after parsing a received KCMessage.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageAction {
    /// Display a text message to the user.
    DisplayText {
        content: String,
        format: Option<String>,
    },
    /// A friend request was approved.
    FriendApprove {
        request_id: String,
        prekey_auth: Option<SignalPrekeyAuth>,
    },
    /// A friend request was rejected.
    FriendReject {
        request_id: String,
    },
    /// Display files to the user.
    DisplayFiles {
        files: crate::message::KCFilesPayload,
    },
    /// An unknown kind with optional fallback text.
    UnknownKind {
        kind: String,
        fallback: Option<String>,
    },
    /// Non-KCMessage plaintext (not valid JSON or v != 2).
    PlainText {
        content: String,
    },
}

// ─── SignalPrekeyAuth creation & verification ────────────────────────────────

/// Create a SignalPrekeyAuth for outbound PrekeyMessages (§4.6).
///
/// This binds the sender's Nostr identity to their Signal identity via a
/// Schnorr signature over `"Keychat-{nostrId}-{signalId}-{time}"`.
pub fn create_signal_prekey_auth(
    nostr_secret_key: &nostr::SecretKey,
    nostr_pubkey_hex: &str,
    signal_pubkey_hex: &str,
    display_name: &str,
) -> Result<SignalPrekeyAuth> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let sig = compute_global_sign(nostr_secret_key, nostr_pubkey_hex, signal_pubkey_hex, time)?;

    Ok(SignalPrekeyAuth {
        nostr_id: nostr_pubkey_hex.to_string(),
        signal_id: signal_pubkey_hex.to_string(),
        time,
        name: display_name.to_string(),
        sig,
        avatar: None,
        lightning: None,
    })
}

/// Verify a SignalPrekeyAuth from an inbound PrekeyMessage (§4.6).
///
/// Checks:
/// - Schnorr signature is valid
/// - nostrId and signalId are valid public keys
pub fn verify_signal_prekey_auth(auth: &SignalPrekeyAuth) -> Result<()> {
    // Verify nostrId is a valid secp256k1 x-only public key (32 bytes = 64 hex chars)
    let nostr_bytes = hex::decode(&auth.nostr_id)
        .map_err(|e| KeychatError::Signal(format!("invalid nostrId hex: {e}")))?;
    if nostr_bytes.len() != 32 {
        return Err(KeychatError::Signal(format!(
            "nostrId must be 32 bytes, got {}",
            nostr_bytes.len()
        )));
    }
    // Verify it's a valid x-only public key
    nostr::secp256k1::XOnlyPublicKey::from_slice(&nostr_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid nostrId public key: {e}")))?;

    // Verify signalId is a valid hex string (Signal identity keys are 33 bytes with 0x05 prefix)
    let signal_bytes = hex::decode(&auth.signal_id)
        .map_err(|e| KeychatError::Signal(format!("invalid signalId hex: {e}")))?;
    if signal_bytes.is_empty() {
        return Err(KeychatError::Signal("signalId is empty".into()));
    }

    // Verify Schnorr signature
    let valid = verify_global_sign(&auth.nostr_id, &auth.signal_id, auth.time, &auth.sig)?;
    if !valid {
        return Err(KeychatError::Signal(
            "SignalPrekeyAuth signature verification failed".into(),
        ));
    }

    Ok(())
}

// ─── Send encrypted message ─────────────────────────────────────────────────

/// Send an encrypted message as a kind:1059 event (Mode 1 Direct Transport, §8.1).
///
/// - Serializes the KCMessage to JSON
/// - Encrypts with Signal Protocol
/// - Generates an ephemeral sender keypair
/// - Builds a kind:1059 event with base64-encoded ciphertext
/// - Signs with ephemeral sender's private key
pub async fn send_encrypted_message(
    signal: &mut SignalParticipant,
    remote_address: &ProtocolAddress,
    message: &KCMessage,
    to_address: &str,
) -> Result<Event> {
    let json = message.to_json()?;
    let ct = signal.encrypt(remote_address, json.as_bytes())?;
    let ciphertext = ct.bytes;
    build_mode1_event(&ciphertext, to_address).await
}

// ─── Receive encrypted message ──────────────────────────────────────────────

/// Receive and decrypt a kind:1059 event (Mode 1 Direct Transport, §8.2).
///
/// - Verifies event is kind 1059
/// - base64_decodes the content to get Signal ciphertext
/// - Detects PrekeyMessage via `PreKeySignalMessage::try_from()`
/// - Decrypts with Signal Protocol
/// - Parses as KCMessage v2, routes by kind
/// - Returns parsed message + metadata
pub fn receive_encrypted_message(
    signal: &mut SignalParticipant,
    remote_address: &ProtocolAddress,
    event: &Event,
) -> Result<(KCMessage, MessageMetadata)> {
    // Verify kind 1059
    if event.kind != Kind::GiftWrap {
        return Err(KeychatError::Signal(format!(
            "expected kind 1059, got {}",
            event.kind.as_u16()
        )));
    }

    // base64 decode content
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|e| KeychatError::Signal(format!("invalid base64 content: {e}")))?;

    // Detect PrekeyMessage
    let is_prekey = SignalParticipant::is_prekey_message(&ciphertext);

    // Decrypt
    let decrypt_result = signal.decrypt(remote_address, &ciphertext)?;

    // Parse plaintext
    let plaintext_str = String::from_utf8(decrypt_result.plaintext.clone())
        .map_err(|e| KeychatError::Signal(format!("decrypted text is not valid UTF-8: {e}")))?;

    let message = KCMessage::try_parse(&plaintext_str).ok_or_else(|| {
        KeychatError::Signal("decrypted content is not a valid KCMessage v2".into())
    })?;

    // Extract the p-tag receiving address
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

    Ok((message, metadata))
}

/// Receive a kind:1059 event and return the decrypted plaintext as a string,
/// handling both valid KCMessage v2 and plain text content.
///
/// Returns `(Option<KCMessage>, String, MessageMetadata)` where:
/// - First: parsed KCMessage if valid v2 JSON
/// - Second: the raw plaintext string (always present)
/// - Third: message metadata
pub fn receive_encrypted_message_flexible(
    signal: &mut SignalParticipant,
    remote_address: &ProtocolAddress,
    event: &Event,
) -> Result<(Option<KCMessage>, String, MessageMetadata)> {
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

    let decrypt_result = signal.decrypt(remote_address, &ciphertext)?;

    let plaintext_str = String::from_utf8(decrypt_result.plaintext.clone())
        .map_err(|e| KeychatError::Signal(format!("decrypted text is not valid UTF-8: {e}")))?;

    let message = KCMessage::try_parse(&plaintext_str);

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
        signal_prekey_auth: message.as_ref().and_then(|m| m.signal_prekey_auth.clone()),
        event_id: event.id,
        event_pubkey: event.pubkey,
        received_on_address: received_on,
    };

    Ok((message, plaintext_str, metadata))
}

// ─── KCMessage routing ──────────────────────────────────────────────────────

/// Route a received KCMessage to the appropriate action (§4.4, §4.7).
///
/// Handles known kinds (text, friendApprove, friendReject, files) and
/// provides forward-compatible fallback for unknown kinds.
pub fn handle_received_message(message: &KCMessage) -> MessageAction {
    match &message.kind {
        KCMessageKind::Text => {
            if let Some(ref text) = message.text {
                MessageAction::DisplayText {
                    content: text.content.clone(),
                    format: text.format.clone(),
                }
            } else {
                // Text kind but missing payload — use fallback
                MessageAction::DisplayText {
                    content: message
                        .fallback
                        .clone()
                        .unwrap_or_else(|| "[missing text payload]".to_string()),
                    format: None,
                }
            }
        }
        KCMessageKind::FriendApprove => {
            let request_id = message
                .friend_approve
                .as_ref()
                .map(|p| p.request_id.clone())
                .unwrap_or_default();
            MessageAction::FriendApprove {
                request_id,
                prekey_auth: message.signal_prekey_auth.clone(),
            }
        }
        KCMessageKind::FriendReject => {
            let request_id = message
                .friend_reject
                .as_ref()
                .map(|p| p.request_id.clone())
                .unwrap_or_default();
            MessageAction::FriendReject { request_id }
        }
        KCMessageKind::Files => {
            if let Some(ref files) = message.files {
                MessageAction::DisplayFiles {
                    files: files.clone(),
                }
            } else {
                MessageAction::UnknownKind {
                    kind: "files".to_string(),
                    fallback: message.fallback.clone(),
                }
            }
        }
        KCMessageKind::Unknown(kind_str) => MessageAction::UnknownKind {
            kind: kind_str.clone(),
            fallback: message.fallback.clone(),
        },
        // All other known kinds that we don't specifically handle yet
        other => MessageAction::UnknownKind {
            kind: other.as_str().to_string(),
            fallback: message.fallback.clone(),
        },
    }
}

/// Try to parse a plaintext string as a KCMessage and route it.
///
/// If the string is valid KCMessage v2 JSON, routes by kind.
/// If not valid JSON or v != 2, returns PlainText.
pub fn parse_and_route(plaintext: &str) -> MessageAction {
    match KCMessage::try_parse(plaintext) {
        Some(msg) => handle_received_message(&msg),
        None => MessageAction::PlainText {
            content: plaintext.to_string(),
        },
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

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
    use crate::identity::Identity;
    use crate::message::{
        KCCashuPayload, KCFilePayload, KCFilesPayload, KCTextPayload, FileCategory,
    };

    /// Helper: establish a Signal session between Alice and Bob, returning both participants
    /// and their protocol addresses.
    fn setup_session() -> (
        SignalParticipant,
        SignalParticipant,
        ProtocolAddress,
        ProtocolAddress,
    ) {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr =
            ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        let alice_addr =
            ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        // Exchange messages to complete session on both sides
        let ct = alice.encrypt_bytes(&bob_addr, b"init").unwrap();
        bob.decrypt_bytes(&alice_addr, &ct).unwrap();
        // Bob replies to fully establish the session (graduates from PrekeyMessage)
        let ct2 = bob.encrypt_bytes(&alice_addr, b"ack").unwrap();
        alice.decrypt_bytes(&bob_addr, &ct2).unwrap();

        (alice, bob, alice_addr, bob_addr)
    }

    // ─── Test: Send/receive kind:1059 roundtrip ──────────────────────────────

    #[tokio::test]
    async fn send_receive_text_roundtrip() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        // Alice generates an address for Bob to send to (use a real pubkey for p-tag)
        let receiving_keys = EphemeralKeypair::generate();
        let receiving_addr = receiving_keys.pubkey_hex();

        // Alice sends text message
        let msg = KCMessage::text("Hello Bob from Phase 4!");
        let event = send_encrypted_message(&mut alice, &bob_addr, &msg, &receiving_addr)
            .await
            .unwrap();

        // Verify event properties
        assert_eq!(event.kind, Kind::GiftWrap);
        // Ephemeral pubkey - not Alice's real pubkey
        // (We can't easily get Alice's nostr pubkey here, but we verify it's a valid key)
        assert_eq!(event.pubkey.to_hex().len(), 64);
        // Content is base64
        assert!(base64::engine::general_purpose::STANDARD
            .decode(&event.content)
            .is_ok());
        // p-tag contains receiving address
        let p_tag = event
            .tags
            .iter()
            .find(|t| t.as_slice()[0] == "p")
            .unwrap();
        assert_eq!(p_tag.as_slice()[1], receiving_addr);
        // Real timestamp (not tweaked) — just verify it's recent
        let now = nostr::Timestamp::now().as_u64();
        assert!(event.created_at.as_u64() <= now + 10);
        assert!(event.created_at.as_u64() >= now - 60);

        // Bob receives and decrypts
        let (received_msg, metadata) =
            receive_encrypted_message(&mut bob, &alice_addr, &event).unwrap();

        assert_eq!(received_msg.kind, KCMessageKind::Text);
        assert_eq!(
            received_msg.text.as_ref().unwrap().content,
            "Hello Bob from Phase 4!"
        );
        assert!(!metadata.is_prekey_message); // Session fully established (bidirectional)
        assert_eq!(metadata.received_on_address, receiving_addr);
        assert_eq!(metadata.event_pubkey, event.pubkey);
    }

    #[tokio::test]
    async fn prekey_message_with_signal_prekey_auth() {
        // Fresh participants — no session exchange yet
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr =
            ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        let alice_addr =
            ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));

        // Alice processes Bob's bundle (but Bob hasn't seen Alice yet)
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        // Create SignalPrekeyAuth
        let alice_identity = Identity::generate().unwrap().identity;
        let auth = create_signal_prekey_auth(
            alice_identity.secret_key(),
            &alice_identity.pubkey_hex(),
            &alice.identity_public_key_hex(),
            "Alice",
        )
        .unwrap();

        // Build message with signalPrekeyAuth
        let mut msg = KCMessage::friend_approve("fr-test-001".into(), Some("Hello!".into()));
        msg.signal_prekey_auth = Some(auth.clone());

        let receiving_keys = EphemeralKeypair::generate();
        let event = send_encrypted_message(
            &mut alice,
            &bob_addr,
            &msg,
            &receiving_keys.pubkey_hex(),
        )
        .await
        .unwrap();

        // Verify this is a PrekeyMessage at the binary level
        let raw_ct = base64::engine::general_purpose::STANDARD
            .decode(&event.content)
            .unwrap();
        assert!(SignalParticipant::is_prekey_message(&raw_ct));

        // Bob receives
        let (received_msg, metadata) =
            receive_encrypted_message(&mut bob, &alice_addr, &event).unwrap();

        assert!(metadata.is_prekey_message);
        assert!(metadata.signal_prekey_auth.is_some());

        let received_auth = metadata.signal_prekey_auth.unwrap();
        assert_eq!(received_auth.nostr_id, alice_identity.pubkey_hex());
        assert_eq!(received_auth.name, "Alice");

        // Verify Schnorr signature
        verify_signal_prekey_auth(&received_auth).unwrap();

        // Verify message routing
        assert_eq!(received_msg.kind, KCMessageKind::FriendApprove);
    }

    // ─── Test: SignalPrekeyAuth ──────────────────────────────────────────────

    #[test]
    fn create_and_verify_signal_prekey_auth() {
        let identity = Identity::generate().unwrap().identity;
        let signal = SignalParticipant::new("test", 1).unwrap();

        let auth = create_signal_prekey_auth(
            identity.secret_key(),
            &identity.pubkey_hex(),
            &signal.identity_public_key_hex(),
            "TestUser",
        )
        .unwrap();

        assert_eq!(auth.nostr_id, identity.pubkey_hex());
        assert_eq!(auth.signal_id, signal.identity_public_key_hex());
        assert_eq!(auth.name, "TestUser");
        assert!(!auth.sig.is_empty());

        // Verify
        verify_signal_prekey_auth(&auth).unwrap();
    }

    #[test]
    fn signal_prekey_auth_tampered_sig_fails() {
        let identity = Identity::generate().unwrap().identity;
        let signal = SignalParticipant::new("test", 1).unwrap();

        let mut auth = create_signal_prekey_auth(
            identity.secret_key(),
            &identity.pubkey_hex(),
            &signal.identity_public_key_hex(),
            "TestUser",
        )
        .unwrap();

        // Tamper with signature
        auth.sig = "00".repeat(64);
        assert!(verify_signal_prekey_auth(&auth).is_err());
    }

    #[test]
    fn signal_prekey_auth_wrong_nostr_id_fails() {
        let identity = Identity::generate().unwrap().identity;
        let signal = SignalParticipant::new("test", 1).unwrap();

        let mut auth = create_signal_prekey_auth(
            identity.secret_key(),
            &identity.pubkey_hex(),
            &signal.identity_public_key_hex(),
            "TestUser",
        )
        .unwrap();

        // Use a different nostrId
        let other = Identity::generate().unwrap().identity;
        auth.nostr_id = other.pubkey_hex();
        assert!(verify_signal_prekey_auth(&auth).is_err());
    }

    // ─── Test: KCMessage routing ─────────────────────────────────────────────

    #[test]
    fn route_text_message() {
        let msg = KCMessage::text("Hello!");
        let action = handle_received_message(&msg);
        assert_eq!(
            action,
            MessageAction::DisplayText {
                content: "Hello!".into(),
                format: None,
            }
        );
    }

    #[test]
    fn route_text_with_format() {
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::Text,
            text: Some(KCTextPayload {
                content: "**bold**".into(),
                format: Some("markdown".into()),
            }),
            ..KCMessage::text("unused")
        };
        let action = handle_received_message(&msg);
        assert_eq!(
            action,
            MessageAction::DisplayText {
                content: "**bold**".into(),
                format: Some("markdown".into()),
            }
        );
    }

    #[test]
    fn route_friend_approve() {
        let msg = KCMessage::friend_approve("fr-001".into(), None);
        let action = handle_received_message(&msg);
        match action {
            MessageAction::FriendApprove {
                request_id,
                prekey_auth,
            } => {
                assert_eq!(request_id, "fr-001");
                assert!(prekey_auth.is_none());
            }
            _ => panic!("expected FriendApprove"),
        }
    }

    #[test]
    fn route_friend_approve_with_auth() {
        let mut msg = KCMessage::friend_approve("fr-002".into(), None);
        msg.signal_prekey_auth = Some(SignalPrekeyAuth {
            nostr_id: "abc".into(),
            signal_id: "def".into(),
            time: 123,
            name: "Bob".into(),
            sig: "sig".into(),
            avatar: None,
            lightning: None,
        });
        let action = handle_received_message(&msg);
        match action {
            MessageAction::FriendApprove {
                request_id,
                prekey_auth,
            } => {
                assert_eq!(request_id, "fr-002");
                assert!(prekey_auth.is_some());
                assert_eq!(prekey_auth.unwrap().name, "Bob");
            }
            _ => panic!("expected FriendApprove"),
        }
    }

    #[test]
    fn route_friend_reject() {
        let msg = KCMessage::friend_reject("fr-003".into(), None);
        let action = handle_received_message(&msg);
        assert_eq!(
            action,
            MessageAction::FriendReject {
                request_id: "fr-003".into(),
            }
        );
    }

    #[test]
    fn route_files_message() {
        let files_payload = KCFilesPayload {
            message: Some("Photos".into()),
            items: vec![KCFilePayload {
                category: FileCategory::Image,
                url: "https://example.com/img.jpg".into(),
                type_: Some("image/jpeg".into()),
                suffix: Some("jpg".into()),
                size: Some(1024),
                key: None,
                iv: None,
                hash: None,
                source_name: None,
                audio_duration: None,
                amplitude_samples: None,
                ecash_token: None,
            }],
        };
        let msg = KCMessage {
            v: 2,
            id: Some("file-1".into()),
            kind: KCMessageKind::Files,
            files: Some(files_payload.clone()),
            ..empty_msg()
        };
        let action = handle_received_message(&msg);
        match action {
            MessageAction::DisplayFiles { files } => {
                assert_eq!(files.items.len(), 1);
                assert_eq!(files.items[0].category, FileCategory::Image);
            }
            _ => panic!("expected DisplayFiles"),
        }
    }

    #[test]
    fn route_unknown_kind_with_fallback() {
        let json = r#"{"v":2,"kind":"futureKind","fallback":"Upgrade your client"}"#;
        let action = parse_and_route(json);
        assert_eq!(
            action,
            MessageAction::UnknownKind {
                kind: "futureKind".into(),
                fallback: Some("Upgrade your client".into()),
            }
        );
    }

    #[test]
    fn route_unknown_kind_without_fallback() {
        let json = r#"{"v":2,"kind":"futureKind"}"#;
        let action = parse_and_route(json);
        assert_eq!(
            action,
            MessageAction::UnknownKind {
                kind: "futureKind".into(),
                fallback: None,
            }
        );
    }

    #[test]
    fn route_invalid_json_as_plaintext() {
        let action = parse_and_route("not json at all");
        assert_eq!(
            action,
            MessageAction::PlainText {
                content: "not json at all".into(),
            }
        );
    }

    #[test]
    fn route_v1_message_as_plaintext() {
        let json = r#"{"v":1,"kind":"text","text":{"content":"old"}}"#;
        let action = parse_and_route(json);
        assert_eq!(
            action,
            MessageAction::PlainText {
                content: json.into(),
            }
        );
    }

    #[test]
    fn route_known_but_unhandled_kind() {
        // Cashu is a known kind but not specifically handled by handle_received_message
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::Cashu,
            cashu: Some(KCCashuPayload {
                mint: "https://mint.example.com".into(),
                token: "cashuAtoken".into(),
                amount: 100,
                unit: None,
                memo: None,
                message: None,
            }),
            fallback: Some("Sent 100 sats".into()),
            ..empty_msg()
        };
        let action = handle_received_message(&msg);
        assert_eq!(
            action,
            MessageAction::UnknownKind {
                kind: "cashu".into(),
                fallback: Some("Sent 100 sats".into()),
            }
        );
    }

    // ─── Test: Multiple message types through pipeline ───────────────────────

    #[tokio::test]
    async fn multiple_message_types_pipeline() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let recv = EphemeralKeypair::generate();

        // 1. Text message
        let text_msg = KCMessage::text("Hello!");
        let text_event =
            send_encrypted_message(&mut alice, &bob_addr, &text_msg, &recv.pubkey_hex())
                .await
                .unwrap();
        let (dec_text, _) =
            receive_encrypted_message(&mut bob, &alice_addr, &text_event).unwrap();
        assert_eq!(dec_text.kind, KCMessageKind::Text);
        assert_eq!(dec_text.text.unwrap().content, "Hello!");

        // 2. Files message
        let files_msg = KCMessage {
            v: 2,
            id: Some("f-1".into()),
            kind: KCMessageKind::Files,
            files: Some(KCFilesPayload {
                message: Some("Photo".into()),
                items: vec![KCFilePayload {
                    category: FileCategory::Image,
                    url: "https://example.com/a.jpg".into(),
                    type_: None,
                    suffix: None,
                    size: None,
                    key: None,
                    iv: None,
                    hash: None,
                    source_name: None,
                    audio_duration: None,
                    amplitude_samples: None,
                    ecash_token: None,
                }],
            }),
            ..empty_msg()
        };
        let recv2 = EphemeralKeypair::generate();
        let files_event =
            send_encrypted_message(&mut bob, &alice_addr, &files_msg, &recv2.pubkey_hex())
                .await
                .unwrap();
        let (dec_files, _) =
            receive_encrypted_message(&mut alice, &bob_addr, &files_event).unwrap();
        assert_eq!(dec_files.kind, KCMessageKind::Files);
        assert_eq!(dec_files.files.unwrap().items.len(), 1);

        // 3. Cashu message
        let cashu_msg = KCMessage {
            v: 2,
            id: Some("c-1".into()),
            kind: KCMessageKind::Cashu,
            cashu: Some(KCCashuPayload {
                mint: "https://mint.example.com".into(),
                token: "cashuAtoken".into(),
                amount: 21,
                unit: Some("sat".into()),
                memo: None,
                message: Some("Tips".into()),
            }),
            fallback: Some("21 sats sent".into()),
            ..empty_msg()
        };
        let recv3 = EphemeralKeypair::generate();
        let cashu_event =
            send_encrypted_message(&mut alice, &bob_addr, &cashu_msg, &recv3.pubkey_hex())
                .await
                .unwrap();
        let (dec_cashu, _) =
            receive_encrypted_message(&mut bob, &alice_addr, &cashu_event).unwrap();
        assert_eq!(dec_cashu.kind, KCMessageKind::Cashu);
        assert_eq!(dec_cashu.cashu.unwrap().amount, 21);
    }

    // ─── Test: Full end-to-end (friend request → chat) ──────────────────────

    #[tokio::test]
    async fn full_end_to_end_friend_request_to_chat() {
        use crate::friend_request::{
            accept_friend_request, receive_friend_request, send_friend_request,
        };

        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        // 1. Alice sends friend request (NIP-17 Gift Wrap)
        let (gift_wrap, alice_state) =
            send_friend_request(&alice_id, &bob_id.pubkey_hex(), "Alice", "dev-alice")
                .await
                .unwrap();
        assert_eq!(gift_wrap.kind, Kind::GiftWrap);

        // 2. Bob receives friend request
        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        assert_eq!(received.payload.name, "Alice");

        // 3. Bob accepts (Signal PrekeyMessage with signalPrekeyAuth)
        let accepted = accept_friend_request(&bob_id, &received, "Bob")
            .await
            .unwrap();
        assert!(accepted.message.signal_prekey_auth.is_some());

        // 4. Alice decrypts Bob's approval and verifies signalPrekeyAuth
        let ct_bytes = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        assert!(SignalParticipant::is_prekey_message(&ct_bytes));

        let bob_signal_id = accepted.signal_participant.identity_public_key_hex();
        let bob_signal_addr =
            ProtocolAddress::new(bob_signal_id.clone(), DeviceId::from(1u32));

        let mut alice_signal = alice_state.signal_participant;
        let decrypt_result = alice_signal
            .decrypt_bytes(&bob_signal_addr, &ct_bytes)
            .unwrap();

        let approve_str = String::from_utf8(decrypt_result).unwrap();
        let approve_msg = KCMessage::try_parse(&approve_str).unwrap();

        let auth = approve_msg.signal_prekey_auth.as_ref().unwrap();
        verify_signal_prekey_auth(auth).unwrap();
        assert_eq!(auth.nostr_id, bob_id.pubkey_hex());

        // Verify routing
        let action = handle_received_message(&approve_msg);
        match action {
            MessageAction::FriendApprove { prekey_auth, .. } => {
                assert!(prekey_auth.is_some());
            }
            _ => panic!("expected FriendApprove action"),
        }

        // 5. Alice sends text message (kind:1059 Mode 1)
        let alice_text = KCMessage::text("Hello Bob, nice to meet you!");
        let recv_addr = EphemeralKeypair::generate();
        let text_event = send_encrypted_message(
            &mut alice_signal,
            &bob_signal_addr,
            &alice_text,
            &recv_addr.pubkey_hex(),
        )
        .await
        .unwrap();

        // 6. Bob receives, decrypts, parses as KCMessage text
        let alice_signal_addr = ProtocolAddress::new(
            alice_signal.identity_public_key_hex(),
            DeviceId::from(1u32),
        );
        let mut bob_signal = accepted.signal_participant;
        let (bob_received, bob_meta) =
            receive_encrypted_message(&mut bob_signal, &alice_signal_addr, &text_event).unwrap();

        assert_eq!(bob_received.kind, KCMessageKind::Text);
        assert_eq!(
            bob_received.text.as_ref().unwrap().content,
            "Hello Bob, nice to meet you!"
        );
        assert!(!bob_meta.is_prekey_message);

        let bob_action = handle_received_message(&bob_received);
        assert_eq!(
            bob_action,
            MessageAction::DisplayText {
                content: "Hello Bob, nice to meet you!".into(),
                format: None,
            }
        );

        // 7. Bob replies
        let bob_text = KCMessage::text("Hi Alice! Great to connect.");
        let recv_addr2 = EphemeralKeypair::generate();
        let reply_event = send_encrypted_message(
            &mut bob_signal,
            &alice_signal_addr,
            &bob_text,
            &recv_addr2.pubkey_hex(),
        )
        .await
        .unwrap();

        // 8. Alice receives, decrypts
        let (alice_received, alice_meta) =
            receive_encrypted_message(&mut alice_signal, &bob_signal_addr, &reply_event).unwrap();

        assert_eq!(alice_received.kind, KCMessageKind::Text);
        assert_eq!(
            alice_received.text.as_ref().unwrap().content,
            "Hi Alice! Great to connect."
        );
        assert!(!alice_meta.is_prekey_message);
    }

    // ─── Test: receive_encrypted_message_flexible ────────────────────────────

    #[tokio::test]
    async fn flexible_receive_handles_valid_kcmessage() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let recv = EphemeralKeypair::generate();

        let msg = KCMessage::text("flex test");
        let event = send_encrypted_message(&mut alice, &bob_addr, &msg, &recv.pubkey_hex())
            .await
            .unwrap();

        let (maybe_msg, plaintext, _meta) =
            receive_encrypted_message_flexible(&mut bob, &alice_addr, &event).unwrap();

        assert!(maybe_msg.is_some());
        assert!(plaintext.contains("flex test"));
    }

    // ─── Test: Ephemeral sender verification ─────────────────────────────────

    #[tokio::test]
    async fn event_uses_ephemeral_sender() {
        let (mut alice, _bob, _alice_addr, bob_addr) = setup_session();
        let recv = EphemeralKeypair::generate();

        let msg = KCMessage::text("test sender");
        let event1 = send_encrypted_message(&mut alice, &bob_addr, &msg, &recv.pubkey_hex())
            .await
            .unwrap();
        let recv2 = EphemeralKeypair::generate();
        let event2 = send_encrypted_message(&mut alice, &bob_addr, &msg, &recv2.pubkey_hex())
            .await
            .unwrap();

        // Each event should have a different ephemeral pubkey
        assert_ne!(event1.pubkey, event2.pubkey);
        // Both should be valid 64-char hex pubkeys
        assert_eq!(event1.pubkey.to_hex().len(), 64);
        assert_eq!(event2.pubkey.to_hex().len(), 64);
    }

    /// Helper to create an empty KCMessage shell.
    fn empty_msg() -> KCMessage {
        KCMessage {
            v: 2,
            id: None,
            kind: KCMessageKind::Text,
            text: None,
            files: None,
            cashu: None,
            lightning: None,
            friend_request: None,
            friend_approve: None,
            friend_reject: None,
            group_id: None,
            reply_to: None,
            signal_prekey_auth: None,
            fallback: None,
            thread_id: None,
            forward_from: None,
            burn_after_reading: None,
            extra: std::collections::HashMap::new(),
        }
    }
}
