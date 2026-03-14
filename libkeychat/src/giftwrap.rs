//! NIP-17 Gift Wrap (three-layer wrapping).
//!
//! Implements the three-layer NIP-17 wrapping used for messages when no encrypted
//! session exists (e.g., friend requests). See spec §3.3 Mode 2.
//!
//! Layers:
//!   Layer 1 (innermost): Rumor (kind 14, unsigned event)
//!   Layer 2: Seal (kind 13, signed by sender, encrypted with NIP-44)
//!   Layer 3 (outermost): Gift Wrap (kind 1059, signed by ephemeral key, encrypted with NIP-44)
//!
//! Keychat divergence from NIP-17: uses REAL timestamps, NOT tweaked.

use crate::error::{KeychatError, Result};
use crate::identity::EphemeralKeypair;
use nostr::prelude::*;

/// The result of unwrapping a Gift Wrap event.
#[derive(Debug, Clone)]
pub struct UnwrappedMessage {
    /// The real sender's public key (from the Seal layer)
    pub sender_pubkey: PublicKey,
    /// The decrypted plaintext content (from the Rumor layer)
    pub content: String,
    /// The rumor kind (should be 14 for direct messages)
    pub rumor_kind: Kind,
    /// The rumor tags
    pub rumor_tags: Vec<Tag>,
    /// The rumor created_at timestamp
    pub created_at: Timestamp,
}

/// Create a NIP-17 Gift Wrap event.
///
/// Three-layer wrapping:
///   1. Build a Rumor (kind 14, unsigned) with the plaintext content
///   2. Wrap in a Seal (kind 13): NIP-44 encrypt rumor with sender's real key → receiver
///   3. Wrap in a Gift Wrap (kind 1059): NIP-44 encrypt seal with ephemeral key → receiver
///
/// Per Keychat spec: uses REAL timestamps (no random offset).
pub async fn create_gift_wrap(
    sender_keys: &Keys,
    receiver_pubkey: &PublicKey,
    content: &str,
) -> Result<Event> {
    // Generate ephemeral wrapper keypair for outer layer
    let wrapper = EphemeralKeypair::generate();

    create_gift_wrap_with_wrapper(wrapper.keys(), sender_keys, receiver_pubkey, content).await
}

/// Create a Gift Wrap with a specific wrapper keypair (useful for testing).
pub async fn create_gift_wrap_with_wrapper(
    wrapper_keys: &Keys,
    sender_keys: &Keys,
    receiver_pubkey: &PublicKey,
    content: &str,
) -> Result<Event> {
    let now = Timestamp::now();

    // Layer 1: Rumor (kind 14, unsigned)
    // The rumor contains the actual plaintext content
    let rumor: UnsignedEvent = EventBuilder::new(Kind::from(14), content)
        .tag(Tag::public_key(*receiver_pubkey))
        .custom_created_at(now)
        .build(sender_keys.public_key());

    let rumor_json = rumor.as_json();

    // Layer 2: Seal (kind 13)
    // Encrypt the rumor JSON with sender's real private key → receiver's public key
    let seal_content = crate::nip44::encrypt(
        sender_keys.secret_key(),
        receiver_pubkey,
        &rumor_json,
    )?;

    let seal = EventBuilder::new(Kind::from(13), &seal_content)
        .custom_created_at(now)
        .sign(sender_keys)
        .await
        .map_err(|e| KeychatError::GiftWrap(format!("failed to sign seal: {e}")))?;

    let seal_json = seal.as_json();

    // Layer 3: Gift Wrap (kind 1059)
    // Encrypt the seal JSON with ephemeral wrapper key → receiver's public key
    let wrap_content = crate::nip44::encrypt(
        wrapper_keys.secret_key(),
        receiver_pubkey,
        &seal_json,
    )?;

    let gift_wrap = EventBuilder::new(Kind::GiftWrap, &wrap_content)
        .tag(Tag::public_key(*receiver_pubkey))
        .custom_created_at(now)
        .sign(wrapper_keys)
        .await
        .map_err(|e| KeychatError::GiftWrap(format!("failed to sign gift wrap: {e}")))?;

    Ok(gift_wrap)
}

/// Unwrap a NIP-17 Gift Wrap event.
///
/// Three-layer unwrapping:
///   1. Decrypt Gift Wrap content (NIP-44 with receiver's key + wrapper's pubkey) → Seal
///   2. Verify Seal signature, decrypt Seal content (NIP-44 with receiver's key + sender's pubkey) → Rumor
///   3. Parse Rumor to get sender pubkey and plaintext content
pub fn unwrap_gift_wrap(
    receiver_keys: &Keys,
    event: &Event,
) -> Result<UnwrappedMessage> {
    // Verify this is a kind 1059 event
    if event.kind != Kind::GiftWrap {
        return Err(KeychatError::GiftWrap(format!(
            "expected kind 1059, got kind {}",
            event.kind.as_u16()
        )));
    }

    // Layer 3 → 2: Decrypt Gift Wrap to get Seal
    let seal_json = crate::nip44::decrypt(
        receiver_keys.secret_key(),
        &event.pubkey,
        &event.content,
    )
    .map_err(|e| KeychatError::GiftWrap(format!("failed to decrypt gift wrap: {e}")))?;

    let seal: Event = Event::from_json(&seal_json)
        .map_err(|e| KeychatError::GiftWrap(format!("invalid seal event: {e}")))?;

    // Verify seal is kind 13
    if seal.kind != Kind::from(13) {
        return Err(KeychatError::GiftWrap(format!(
            "expected seal kind 13, got kind {}",
            seal.kind.as_u16()
        )));
    }

    // Verify seal signature
    seal.verify()
        .map_err(|e| KeychatError::GiftWrap(format!("seal signature invalid: {e}")))?;

    let sender_pubkey = seal.pubkey;

    // Layer 2 → 1: Decrypt Seal to get Rumor
    let rumor_json = crate::nip44::decrypt(
        receiver_keys.secret_key(),
        &sender_pubkey,
        &seal.content,
    )
    .map_err(|e| KeychatError::GiftWrap(format!("failed to decrypt seal: {e}")))?;

    // Parse rumor (unsigned event)
    let rumor: UnsignedEvent = UnsignedEvent::from_json(&rumor_json)
        .map_err(|e| KeychatError::GiftWrap(format!("invalid rumor event: {e}")))?;

    // Verify rumor is kind 14
    if rumor.kind != Kind::from(14) {
        return Err(KeychatError::GiftWrap(format!(
            "expected rumor kind 14, got kind {}",
            rumor.kind.as_u16()
        )));
    }

    Ok(UnwrappedMessage {
        sender_pubkey,
        content: rumor.content.clone(),
        rumor_kind: rumor.kind,
        rumor_tags: rumor.tags.to_vec(),
        created_at: rumor.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wrap_unwrap_roundtrip() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let content = r#"{"v":2,"kind":"friendRequest","id":"test-uuid"}"#;

        let gift_wrap =
            create_gift_wrap(&sender, &receiver.public_key(), content).await.unwrap();

        // Verify outer event properties
        assert_eq!(gift_wrap.kind, Kind::GiftWrap);
        // The pubkey should NOT be the sender's real pubkey (it's ephemeral)
        assert_ne!(gift_wrap.pubkey, sender.public_key());
        // Should have a p-tag with receiver's pubkey
        let p_tags: Vec<_> = gift_wrap
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)))
            .collect();
        assert!(!p_tags.is_empty());

        // Unwrap
        let unwrapped = unwrap_gift_wrap(&receiver, &gift_wrap).unwrap();
        assert_eq!(unwrapped.sender_pubkey, sender.public_key());
        assert_eq!(unwrapped.content, content);
        assert_eq!(unwrapped.rumor_kind, Kind::from(14));
    }

    #[tokio::test]
    async fn wrong_receiver_cannot_unwrap() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let wrong_receiver = Keys::generate();

        let gift_wrap = create_gift_wrap(
            &sender,
            &receiver.public_key(),
            "secret message",
        )
        .await
        .unwrap();

        let result = unwrap_gift_wrap(&wrong_receiver, &gift_wrap);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn real_timestamps_used() {
        let sender = Keys::generate();
        let receiver = Keys::generate();

        let before = Timestamp::now();
        let gift_wrap =
            create_gift_wrap(&sender, &receiver.public_key(), "test").await.unwrap();
        let after = Timestamp::now();

        let event_time = gift_wrap.created_at;
        assert!(event_time >= before);
        assert!(event_time <= after);
    }

    #[tokio::test]
    async fn three_layers_present() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let content = "hello";

        let gift_wrap =
            create_gift_wrap(&sender, &receiver.public_key(), content).await.unwrap();

        // Layer 3: Gift Wrap (kind 1059)
        assert_eq!(gift_wrap.kind, Kind::GiftWrap);

        // Decrypt to Layer 2: Seal (kind 13)
        let seal_json = crate::nip44::decrypt(
            receiver.secret_key(),
            &gift_wrap.pubkey,
            &gift_wrap.content,
        )
        .unwrap();
        let seal: Event = Event::from_json(&seal_json).unwrap();
        assert_eq!(seal.kind, Kind::from(13));
        assert_eq!(seal.pubkey, sender.public_key());

        // Decrypt to Layer 1: Rumor (kind 14)
        let rumor_json = crate::nip44::decrypt(
            receiver.secret_key(),
            &seal.pubkey,
            &seal.content,
        )
        .unwrap();
        let rumor: UnsignedEvent = UnsignedEvent::from_json(&rumor_json).unwrap();
        assert_eq!(rumor.kind, Kind::from(14));
        assert_eq!(rumor.content, content);
    }
}
