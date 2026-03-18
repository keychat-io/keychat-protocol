//! Friend request flow implementation (§6, §7, §8).
//!
//! - **Send**: Generate Signal keys, build KCFriendRequestPayload, NIP-17 Gift Wrap
//! - **Receive**: Unwrap Gift Wrap, verify globalSign, parse friend request
//! - **Accept**: Process prekey bundle (X3DH), send friendApprove with signalPrekeyAuth
//! - **Messaging**: Send/receive Signal-encrypted KCMessages via kind:1059 Mode 1

use std::sync::{Arc, Mutex};

use crate::error::{KeychatError, Result};
use crate::giftwrap::{create_gift_wrap, unwrap_gift_wrap};
use crate::identity::{EphemeralKeypair, Identity};
use crate::message::{KCFriendRequestPayload, KCMessage, KCMessageKind, SignalPrekeyAuth};
use crate::signal_keys::{compute_global_sign, verify_global_sign};
use crate::signal_session::{generate_prekey_material, SignalParticipant};
use crate::storage::SecureStorage;

use base64::Engine;
use libsignal_protocol::{kem, DeviceId, KyberPreKeyId, PreKeyBundle, ProtocolAddress};
use nostr::prelude::*;

/// State returned after sending a friend request.
#[derive(Debug)]
pub struct FriendRequestState {
    pub signal_participant: SignalParticipant,
    pub first_inbox_keys: EphemeralKeypair,
    pub request_id: String,
    pub peer_nostr_pubkey: String,
}

/// Parsed friend request received from a peer.
#[derive(Debug)]
pub struct FriendRequestReceived {
    pub sender_pubkey: PublicKey,
    pub sender_pubkey_hex: String,
    pub message: KCMessage,
    pub payload: KCFriendRequestPayload,
}

/// Result of accepting a friend request.
pub struct FriendRequestAccepted {
    pub signal_participant: SignalParticipant,
    pub event: Event,
    pub message: KCMessage,
    /// Ratchet address metadata from the acceptance encrypt (sender_address).
    /// Use this to initialize AddressManager after accepting.
    pub sender_address: Option<String>,
}

/// Send a friend request to a peer (§6.2).
pub async fn send_friend_request(
    my_identity: &Identity,
    peer_nostr_pubkey: &str,
    display_name: &str,
    device_id: &str,
) -> Result<(Event, FriendRequestState)> {
    let peer_nostr_pubkey_hex = crate::identity::normalize_pubkey(peer_nostr_pubkey)?;
    let signal_participant = SignalParticipant::new(my_identity.pubkey_hex(), 1)?;
    let first_inbox_keys = EphemeralKeypair::generate();
    let first_inbox_hex = first_inbox_keys.pubkey_hex();

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signal_identity_key_hex = signal_participant.identity_public_key_hex();
    let global_sign = compute_global_sign(
        my_identity.secret_key(),
        &my_identity.pubkey_hex(),
        &signal_identity_key_hex,
        time,
    )?;

    let payload = KCFriendRequestPayload {
        message: None,
        name: display_name.to_string(),
        nostr_identity_key: my_identity.pubkey_hex(),
        signal_identity_key: signal_identity_key_hex,
        first_inbox: first_inbox_hex,
        device_id: device_id.to_string(),
        signal_signed_prekey_id: signal_participant.signed_prekey_id(),
        signal_signed_prekey: signal_participant.signed_prekey_public_hex()?,
        signal_signed_prekey_signature: signal_participant.signed_prekey_signature_hex()?,
        signal_one_time_prekey_id: signal_participant.prekey_id(),
        signal_one_time_prekey: signal_participant.prekey_public_hex()?,
        signal_kyber_prekey_id: signal_participant.kyber_prekey_id(),
        signal_kyber_prekey: signal_participant.kyber_prekey_public_hex()?,
        signal_kyber_prekey_signature: signal_participant.kyber_prekey_signature_hex()?,
        global_sign,
        time: Some(time),
        version: 2,
        relay: None,
        avatar: None,
        lightning: None,
    };

    let request_id = format!("fr-{}", uuid_v4());
    let kc_message = KCMessage::friend_request(request_id.clone(), payload);
    let kc_json = kc_message.to_json()?;

    let peer_pubkey = PublicKey::from_hex(&peer_nostr_pubkey_hex)
        .map_err(|e| KeychatError::Signal(format!("invalid peer pubkey: {e}")))?;

    let gift_wrap_event = create_gift_wrap(my_identity.keys(), &peer_pubkey, &kc_json).await?;

    let state = FriendRequestState {
        signal_participant,
        first_inbox_keys,
        request_id,
        peer_nostr_pubkey: peer_nostr_pubkey_hex,
    };

    Ok((gift_wrap_event, state))
}

/// Receive and parse a friend request from a Gift Wrap event (§7.1, §7.2).
pub fn receive_friend_request(
    my_identity: &Identity,
    gift_wrap_event: &Event,
) -> Result<FriendRequestReceived> {
    let unwrapped = unwrap_gift_wrap(my_identity.keys(), gift_wrap_event)?;

    let message = KCMessage::try_parse(&unwrapped.content).ok_or_else(|| {
        KeychatError::Signal("failed to parse KCMessage from Gift Wrap".into())
    })?;

    if message.kind != KCMessageKind::FriendRequest {
        return Err(KeychatError::Signal(format!(
            "expected friendRequest, got {:?}",
            message.kind
        )));
    }

    let payload = message.friend_request.clone().ok_or_else(|| {
        KeychatError::Signal("friendRequest message missing payload".into())
    })?;

    let time = payload
        .time
        .ok_or_else(|| KeychatError::Signal("friendRequest missing time".into()))?;

    let valid = verify_global_sign(
        &payload.nostr_identity_key,
        &payload.signal_identity_key,
        time,
        &payload.global_sign,
    )?;

    if !valid {
        return Err(KeychatError::Signal(
            "globalSign verification failed".into(),
        ));
    }

    let sender_hex = unwrapped.sender_pubkey.to_hex();
    if sender_hex != payload.nostr_identity_key {
        return Err(KeychatError::Signal(format!(
            "sender pubkey mismatch: seal={} payload={}",
            sender_hex, payload.nostr_identity_key
        )));
    }

    Ok(FriendRequestReceived {
        sender_pubkey: unwrapped.sender_pubkey,
        sender_pubkey_hex: sender_hex,
        message,
        payload,
    })
}

/// Accept a friend request (§7.3, §7.4).
pub async fn accept_friend_request(
    my_identity: &Identity,
    friend_request: &FriendRequestReceived,
    display_name: &str,
) -> Result<FriendRequestAccepted> {
    let payload = &friend_request.payload;

    let mut my_signal = SignalParticipant::new(my_identity.pubkey_hex(), 1)?;

    // Build PreKeyBundle from friend request payload
    let remote_identity_key_bytes = hex::decode(&payload.signal_identity_key)
        .map_err(|e| KeychatError::Signal(format!("hex decode signal identity: {e}")))?;
    let remote_identity_key =
        libsignal_protocol::IdentityKey::decode(&remote_identity_key_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid signal identity key: {e}")))?;

    let remote_signed_prekey_bytes = hex::decode(&payload.signal_signed_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode signed prekey: {e}")))?;
    let remote_signed_prekey =
        libsignal_protocol::PublicKey::deserialize(&remote_signed_prekey_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid signed prekey: {e}")))?;

    let remote_signed_prekey_sig = hex::decode(&payload.signal_signed_prekey_signature)
        .map_err(|e| KeychatError::Signal(format!("hex decode sig: {e}")))?;

    let remote_one_time_prekey_bytes = hex::decode(&payload.signal_one_time_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode one-time prekey: {e}")))?;
    let remote_one_time_prekey =
        libsignal_protocol::PublicKey::deserialize(&remote_one_time_prekey_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid one-time prekey: {e}")))?;

    // Kyber prekey is mandatory for PQXDH in libsignal v0.88.3
    if payload.signal_kyber_prekey.is_empty() {
        return Err(KeychatError::Signal(
            "Kyber prekey is required for PQXDH session establishment".into(),
        ));
    }

    let kyber_prekey_bytes = hex::decode(&payload.signal_kyber_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode kyber prekey: {e}")))?;
    let kyber_public_key = kem::PublicKey::deserialize(&kyber_prekey_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid kyber prekey: {e}")))?;
    let kyber_sig = hex::decode(&payload.signal_kyber_prekey_signature)
        .map_err(|e| KeychatError::Signal(format!("hex decode kyber sig: {e}")))?;

    let prekey_bundle = PreKeyBundle::new(
        1,
        DeviceId::new(1).unwrap(),
        Some((
            libsignal_protocol::PreKeyId::from(payload.signal_one_time_prekey_id),
            remote_one_time_prekey,
        )),
        libsignal_protocol::SignedPreKeyId::from(payload.signal_signed_prekey_id),
        remote_signed_prekey,
        remote_signed_prekey_sig,
        KyberPreKeyId::from(payload.signal_kyber_prekey_id),
        kyber_public_key,
        kyber_sig,
        remote_identity_key,
    )
    .map_err(|e| KeychatError::Signal(format!("failed to build prekey bundle: {e}")))?;

    // Process prekey bundle (PQXDH handshake)
    let remote_address = ProtocolAddress::new(
        payload.signal_identity_key.clone(),
        DeviceId::new(1).unwrap(),
    );
    my_signal.process_prekey_bundle(&remote_address, &prekey_bundle)?;

    // Build friendApprove with signalPrekeyAuth
    let request_id = friend_request.message.id.clone().unwrap_or_default();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let my_signal_id_hex = my_signal.identity_public_key_hex();
    let sig = compute_global_sign(
        my_identity.secret_key(),
        &my_identity.pubkey_hex(),
        &my_signal_id_hex,
        time,
    )?;

    let mut approve_msg = KCMessage::friend_approve(request_id, None);
    approve_msg.signal_prekey_auth = Some(SignalPrekeyAuth {
        nostr_id: my_identity.pubkey_hex(),
        signal_id: my_signal_id_hex,
        time,
        name: display_name.to_string(),
        sig,
        avatar: None,
        lightning: None,
    });

    let approve_json = approve_msg.to_json()?;

    // Encrypt with Signal (PrekeyMessage) — use encrypt to capture ratchet info
    let ct = my_signal.encrypt(&remote_address, approve_json.as_bytes())?;

    // Build kind:1059 Mode 1 event → peer's firstInbox
    let event = build_mode1_event(&ct.bytes, &payload.first_inbox).await?;

    Ok(FriendRequestAccepted {
        signal_participant: my_signal,
        event,
        message: approve_msg,
        sender_address: ct.sender_address,
    })
}

/// Send a friend request with persistent Signal participant (§6.2).
///
/// Same as `send_friend_request` but uses pre-generated keys and creates a
/// `SignalParticipant::persistent()` backed by SQLCipher.
/// The caller should save `keys` to the DB before calling this.
pub async fn send_friend_request_persistent(
    my_identity: &Identity,
    peer_nostr_pubkey: &str,
    display_name: &str,
    device_id: &str,
    keys: crate::signal_session::SignalPreKeyMaterial,
    storage: Arc<Mutex<SecureStorage>>,
    signal_device_id: u32,
) -> Result<(Event, FriendRequestState)> {
    let peer_nostr_pubkey_hex = crate::identity::normalize_pubkey(peer_nostr_pubkey)?;
    let signal_participant =
        SignalParticipant::persistent(my_identity.pubkey_hex(), signal_device_id, keys, storage)?;
    let first_inbox_keys = EphemeralKeypair::generate();
    let first_inbox_hex = first_inbox_keys.pubkey_hex();

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signal_identity_key_hex = signal_participant.identity_public_key_hex();
    let global_sign = compute_global_sign(
        my_identity.secret_key(),
        &my_identity.pubkey_hex(),
        &signal_identity_key_hex,
        time,
    )?;

    let payload = KCFriendRequestPayload {
        message: None,
        name: display_name.to_string(),
        nostr_identity_key: my_identity.pubkey_hex(),
        signal_identity_key: signal_identity_key_hex,
        first_inbox: first_inbox_hex,
        device_id: device_id.to_string(),
        signal_signed_prekey_id: signal_participant.signed_prekey_id(),
        signal_signed_prekey: signal_participant.signed_prekey_public_hex()?,
        signal_signed_prekey_signature: signal_participant.signed_prekey_signature_hex()?,
        signal_one_time_prekey_id: signal_participant.prekey_id(),
        signal_one_time_prekey: signal_participant.prekey_public_hex()?,
        signal_kyber_prekey_id: signal_participant.kyber_prekey_id(),
        signal_kyber_prekey: signal_participant.kyber_prekey_public_hex()?,
        signal_kyber_prekey_signature: signal_participant.kyber_prekey_signature_hex()?,
        global_sign,
        time: Some(time),
        version: 2,
        relay: None,
        avatar: None,
        lightning: None,
    };

    let request_id = format!("fr-{}", uuid_v4());
    let kc_message = KCMessage::friend_request(request_id.clone(), payload);
    let kc_json = kc_message.to_json()?;

    let peer_pubkey = PublicKey::from_hex(&peer_nostr_pubkey_hex)
        .map_err(|e| KeychatError::Signal(format!("invalid peer pubkey: {e}")))?;

    let gift_wrap_event = create_gift_wrap(my_identity.keys(), &peer_pubkey, &kc_json).await?;

    let state = FriendRequestState {
        signal_participant,
        first_inbox_keys,
        request_id,
        peer_nostr_pubkey: peer_nostr_pubkey_hex,
    };

    Ok((gift_wrap_event, state))
}

/// Accept a friend request with persistent Signal participant (§7.3, §7.4).
///
/// Same as `accept_friend_request` but uses pre-generated keys and creates a
/// `SignalParticipant::persistent()` backed by SQLCipher.
/// The caller should save `keys` to the DB before calling this.
pub async fn accept_friend_request_persistent(
    my_identity: &Identity,
    friend_request: &FriendRequestReceived,
    display_name: &str,
    keys: crate::signal_session::SignalPreKeyMaterial,
    storage: Arc<Mutex<SecureStorage>>,
    signal_device_id: u32,
) -> Result<FriendRequestAccepted> {
    let payload = &friend_request.payload;

    let mut my_signal = SignalParticipant::persistent(
        my_identity.pubkey_hex(),
        signal_device_id,
        keys,
        storage,
    )?;

    // Build PreKeyBundle from friend request payload
    let remote_identity_key_bytes = hex::decode(&payload.signal_identity_key)
        .map_err(|e| KeychatError::Signal(format!("hex decode signal identity: {e}")))?;
    let remote_identity_key =
        libsignal_protocol::IdentityKey::decode(&remote_identity_key_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid signal identity key: {e}")))?;

    let remote_signed_prekey_bytes = hex::decode(&payload.signal_signed_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode signed prekey: {e}")))?;
    let remote_signed_prekey =
        libsignal_protocol::PublicKey::deserialize(&remote_signed_prekey_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid signed prekey: {e}")))?;

    let remote_signed_prekey_sig = hex::decode(&payload.signal_signed_prekey_signature)
        .map_err(|e| KeychatError::Signal(format!("hex decode sig: {e}")))?;

    let remote_one_time_prekey_bytes = hex::decode(&payload.signal_one_time_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode one-time prekey: {e}")))?;
    let remote_one_time_prekey =
        libsignal_protocol::PublicKey::deserialize(&remote_one_time_prekey_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid one-time prekey: {e}")))?;

    if payload.signal_kyber_prekey.is_empty() {
        return Err(KeychatError::Signal(
            "Kyber prekey is required for PQXDH session establishment".into(),
        ));
    }

    let kyber_prekey_bytes = hex::decode(&payload.signal_kyber_prekey)
        .map_err(|e| KeychatError::Signal(format!("hex decode kyber prekey: {e}")))?;
    let kyber_public_key = kem::PublicKey::deserialize(&kyber_prekey_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid kyber prekey: {e}")))?;
    let kyber_sig = hex::decode(&payload.signal_kyber_prekey_signature)
        .map_err(|e| KeychatError::Signal(format!("hex decode kyber sig: {e}")))?;

    // Parse remote device_id from payload, default to 1
    let remote_device_id: u32 = payload.device_id.parse().unwrap_or(1);

    let prekey_bundle = PreKeyBundle::new(
        1,
        DeviceId::new(remote_device_id as u8).unwrap_or(DeviceId::new(1).unwrap()),
        Some((
            libsignal_protocol::PreKeyId::from(payload.signal_one_time_prekey_id),
            remote_one_time_prekey,
        )),
        libsignal_protocol::SignedPreKeyId::from(payload.signal_signed_prekey_id),
        remote_signed_prekey,
        remote_signed_prekey_sig,
        KyberPreKeyId::from(payload.signal_kyber_prekey_id),
        kyber_public_key,
        kyber_sig,
        remote_identity_key,
    )
    .map_err(|e| KeychatError::Signal(format!("failed to build prekey bundle: {e}")))?;

    let remote_address = ProtocolAddress::new(
        payload.signal_identity_key.clone(),
        DeviceId::new(remote_device_id as u8).unwrap_or(DeviceId::new(1).unwrap()),
    );
    my_signal.process_prekey_bundle(&remote_address, &prekey_bundle)?;

    let request_id = friend_request.message.id.clone().unwrap_or_default();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let my_signal_id_hex = my_signal.identity_public_key_hex();
    let sig = compute_global_sign(
        my_identity.secret_key(),
        &my_identity.pubkey_hex(),
        &my_signal_id_hex,
        time,
    )?;

    let mut approve_msg = KCMessage::friend_approve(request_id, None);
    approve_msg.signal_prekey_auth = Some(SignalPrekeyAuth {
        nostr_id: my_identity.pubkey_hex(),
        signal_id: my_signal_id_hex,
        time,
        name: display_name.to_string(),
        sig,
        avatar: None,
        lightning: None,
    });

    let approve_json = approve_msg.to_json()?;

    // Encrypt with Signal — session changes automatically persisted to SQLCipher
    let ct = my_signal.encrypt(&remote_address, approve_json.as_bytes())?;

    let event = build_mode1_event(&ct.bytes, &payload.first_inbox).await?;

    Ok(FriendRequestAccepted {
        signal_participant: my_signal,
        event,
        message: approve_msg,
        sender_address: ct.sender_address,
    })
}

/// Send a Signal-encrypted KCMessage as kind:1059 Mode 1 (§8.1).
pub async fn send_signal_message(
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

/// Receive and decrypt a Signal-encrypted kind:1059 event (§8.2).
pub fn receive_signal_message(
    signal: &mut SignalParticipant,
    remote_address: &ProtocolAddress,
    event: &Event,
) -> Result<(KCMessage, crate::signal_session::SignalDecryptResult)> {
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|e| KeychatError::Signal(format!("invalid base64: {e}")))?;

    let decrypt_result = signal.decrypt(remote_address, &ciphertext)?;

    let plaintext_str = String::from_utf8(decrypt_result.plaintext.clone())
        .map_err(|e| KeychatError::Signal(format!("not valid UTF-8: {e}")))?;

    let message = KCMessage::try_parse(&plaintext_str)
        .ok_or_else(|| KeychatError::Signal("not a valid KCMessage v2".into()))?;

    Ok((message, decrypt_result))
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

fn uuid_v4() -> String {
    use ::rand::Rng;
    let mut rng = ::rand::rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_friend_request_roundtrip() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        // Step 1: Alice sends friend request
        let (gift_wrap, alice_state) = send_friend_request(
            &alice_id,
            &bob_id.pubkey_hex(),
            "Alice",
            "device-alice",
        )
        .await
        .unwrap();

        assert_eq!(gift_wrap.kind, Kind::GiftWrap);
        assert_ne!(gift_wrap.pubkey, alice_id.public_key());

        // Step 2: Bob receives friend request
        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        assert_eq!(received.sender_pubkey, alice_id.public_key());
        assert_eq!(received.payload.name, "Alice");
        assert_eq!(received.message.kind, KCMessageKind::FriendRequest);

        // Step 3: Bob accepts
        let accepted = accept_friend_request(&bob_id, &received, "Bob").await.unwrap();
        assert_eq!(accepted.event.kind, Kind::GiftWrap);
        assert_eq!(accepted.message.kind, KCMessageKind::FriendApprove);
        assert!(accepted.message.signal_prekey_auth.is_some());

        // Step 4: Alice decrypts Bob's approval
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        let bob_signal_id = accepted.signal_participant.identity_public_key_hex();
        let bob_signal_addr = ProtocolAddress::new(bob_signal_id.clone(), DeviceId::new(1).unwrap());

        let mut alice_signal = alice_state.signal_participant;
        let decrypt_result = alice_signal
            .decrypt_bytes(&bob_signal_addr, &ciphertext)
            .unwrap();

        let approve_json = String::from_utf8(decrypt_result).unwrap();
        let approve_msg = KCMessage::try_parse(&approve_json).unwrap();
        assert_eq!(approve_msg.kind, KCMessageKind::FriendApprove);

        let auth = approve_msg.signal_prekey_auth.as_ref().unwrap();
        assert_eq!(auth.nostr_id, bob_id.pubkey_hex());
        assert_eq!(auth.name, "Bob");
        let sig_valid =
            verify_global_sign(&auth.nostr_id, &auth.signal_id, auth.time, &auth.sig).unwrap();
        assert!(sig_valid);

        // Step 5: Alice sends "Hello Bob!"
        let hello_msg = KCMessage::text("Hello Bob!");
        let hello_event = send_signal_message(
            &mut alice_signal,
            &bob_signal_addr,
            &hello_msg,
            &received.payload.first_inbox,
        )
        .await
        .unwrap();

        let alice_signal_addr = ProtocolAddress::new(
            alice_signal.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );
        let mut bob_signal = accepted.signal_participant;
        let (hello_dec, _) =
            receive_signal_message(&mut bob_signal, &alice_signal_addr, &hello_event).unwrap();
        assert_eq!(hello_dec.text.as_ref().unwrap().content, "Hello Bob!");

        // Step 6: Bob sends "Hi Alice!"
        let hi_msg = KCMessage::text("Hi Alice!");
        let hi_event = send_signal_message(
            &mut bob_signal,
            &alice_signal_addr,
            &hi_msg,
            &alice_state.first_inbox_keys.pubkey_hex(),
        )
        .await
        .unwrap();

        let (hi_dec, _) =
            receive_signal_message(&mut alice_signal, &bob_signal_addr, &hi_event).unwrap();
        assert_eq!(hi_dec.text.as_ref().unwrap().content, "Hi Alice!");
    }

    #[tokio::test]
    async fn global_sign_verification_tampered() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        let (gift_wrap, _) = send_friend_request(
            &alice_id,
            &bob_id.pubkey_hex(),
            "Alice",
            "dev-1",
        )
        .await
        .unwrap();

        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        let p = &received.payload;

        // Tampered time
        let result =
            verify_global_sign(&p.nostr_identity_key, &p.signal_identity_key, p.time.unwrap() + 1, &p.global_sign)
                .unwrap();
        assert!(!result);

        // Tampered signal key
        let result = verify_global_sign(
            &p.nostr_identity_key,
            "05deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00",
            p.time.unwrap(),
            &p.global_sign,
        )
        .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn wrong_receiver_cannot_open() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;
        let charlie_id = Identity::generate().unwrap().identity;

        let (gift_wrap, _) = send_friend_request(
            &alice_id,
            &bob_id.pubkey_hex(),
            "Alice",
            "dev-1",
        )
        .await
        .unwrap();

        let result = receive_friend_request(&charlie_id, &gift_wrap);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn prekey_message_on_first_approve() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        let (gift_wrap, _) = send_friend_request(
            &alice_id,
            &bob_id.pubkey_hex(),
            "Alice",
            "dev-1",
        )
        .await
        .unwrap();

        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        let accepted = accept_friend_request(&bob_id, &received, "Bob").await.unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        assert!(
            SignalParticipant::is_prekey_message(&ciphertext),
            "first message after accept should be a PrekeyMessage"
        );
    }
}
