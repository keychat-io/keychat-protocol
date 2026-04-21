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
    /// The rumor created_at timestamp (real sender timestamp from NIP-17 inner layer)
    pub created_at: u64,
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

// ─── Shared helpers (C-DUP3) ────────────────────────────────────────────────

/// Build a friend request event from an already-created SignalParticipant.
async fn build_friend_request_event(
    my_identity: &Identity,
    peer_nostr_pubkey_hex: &str,
    display_name: &str,
    device_id: &str,
    signal_participant: &SignalParticipant,
    first_inbox_hex: &str,
) -> Result<(Event, String)> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

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
        first_inbox: first_inbox_hex.to_string(),
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

    let peer_pubkey = PublicKey::from_hex(peer_nostr_pubkey_hex)
        .map_err(|e| KeychatError::Signal(format!("invalid peer pubkey: {e}")))?;

    // Initial FR is sent in v2 schema. Cross-version FR (1.5 ↔ Flutter v1) is a
    // known gap: the payload carries Kyber prekey fields that v1 lacks, and the
    // Flutter app's JSON parser doesn't understand the v2 `{v:2,kind,...}` shape.
    // The outer Gift Wrap still tags `clientv=2` for peer-version discovery.
    let gift_wrap_event = create_gift_wrap(my_identity.keys(), &peer_pubkey, &kc_json).await?;
    tracing::info!("friend request event built: request_id={request_id}");
    Ok((gift_wrap_event, request_id))
}

/// Parse a KCFriendRequestPayload into a PreKeyBundle + remote ProtocolAddress.
fn build_prekey_bundle_from_payload(
    payload: &KCFriendRequestPayload,
) -> Result<(PreKeyBundle, ProtocolAddress)> {
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

    let remote_device_id: u32 = payload.device_id.parse().unwrap_or_else(|_| {
        tracing::warn!(
            "device_id parse failed for '{}', defaulting to 1",
            payload.device_id
        );
        1
    });
    let device_id = DeviceId::new(remote_device_id as u8).unwrap_or_else(|_| {
        tracing::warn!(
            "device_id {} out of range, defaulting to 1",
            remote_device_id
        );
        DeviceId::new(1).unwrap()
    });

    let prekey_bundle = if payload.signal_kyber_prekey.is_empty() {
        // v1 (X3DH-only) peer — no Kyber prekey. Build a legacy bundle.
        tracing::info!("building X3DH-only PreKeyBundle (no Kyber) for v1 peer");
        PreKeyBundle::new_without_kyber(
            1,
            device_id,
            Some((
                libsignal_protocol::PreKeyId::from(payload.signal_one_time_prekey_id),
                remote_one_time_prekey,
            )),
            libsignal_protocol::SignedPreKeyId::from(payload.signal_signed_prekey_id),
            remote_signed_prekey,
            remote_signed_prekey_sig,
            remote_identity_key,
        )
        .map_err(|e| KeychatError::Signal(format!("failed to build X3DH prekey bundle: {e}")))?
    } else {
        // v2 (PQXDH) peer — include Kyber prekey.
        tracing::info!(
            "building PQXDH PreKeyBundle (with Kyber1024) for v2 peer; kyber_prekey_id={} kyber_prekey_bytes={}",
            payload.signal_kyber_prekey_id,
            payload.signal_kyber_prekey.len() / 2,
        );
        let kyber_prekey_bytes = hex::decode(&payload.signal_kyber_prekey)
            .map_err(|e| KeychatError::Signal(format!("hex decode kyber prekey: {e}")))?;
        let kyber_public_key = kem::PublicKey::deserialize(&kyber_prekey_bytes)
            .map_err(|e| KeychatError::Signal(format!("invalid kyber prekey: {e}")))?;
        let kyber_sig = hex::decode(&payload.signal_kyber_prekey_signature)
            .map_err(|e| KeychatError::Signal(format!("hex decode kyber sig: {e}")))?;

        PreKeyBundle::new(
            1,
            device_id,
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
        .map_err(|e| KeychatError::Signal(format!("failed to build prekey bundle: {e}")))?
    };

    let remote_address = ProtocolAddress::new(payload.signal_identity_key.clone(), device_id);

    Ok((prekey_bundle, remote_address))
}

/// Build the accept event: process bundle, encrypt approval, wrap as kind:1059.
async fn build_accept_event(
    my_identity: &Identity,
    my_signal: &mut SignalParticipant,
    friend_request: &FriendRequestReceived,
    display_name: &str,
) -> Result<FriendRequestAccepted> {
    if friend_request.payload.version == 1 {
        return build_v1_accept_event(my_identity, my_signal, friend_request, display_name).await;
    }

    let payload = &friend_request.payload;
    let (prekey_bundle, remote_address) = build_prekey_bundle_from_payload(payload)?;

    my_signal.process_prekey_bundle(&remote_address, &prekey_bundle)?;
    tracing::info!("session established for friend request acceptance");

    let request_id = friend_request.message.id.clone().unwrap_or_default();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

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
    let ct = my_signal.encrypt(&remote_address, approve_json.as_bytes())?;
    let event = build_mode1_event(&ct.bytes, &payload.first_inbox).await?;

    Ok(FriendRequestAccepted {
        signal_participant: my_signal.clone(),
        event,
        message: approve_msg,
        sender_address: ct.sender_address,
    })
}

/// Build a v1 Flutter-compatible accept event.
///
/// In v1, accepting a friend request is NOT a dedicated protocol message. The
/// approver just sends a plain chat "hello" (see `chat_page.dart` approve
/// button, which calls `sendMessage(room, RoomUtil.getHelloMessage(name))`).
/// But the first Signal message after `addRoomKPA` goes through v1's
/// `decryptPreKeyMessage` path, which expects the decrypted plaintext to be a
/// `PrekeyMessageModel` JSON carrying identity proof (schnorr sig over
/// `Keychat-{nostrId}-{signalId}-{time}`) plus the actual message string.
///
/// Wire shape:
///   - Plaintext = PrekeyMessageModel JSON (`nostrId`/`signalId`/`time`/`sig`
///     /`name`/`message`)
///   - Signal-encrypted against alice's freshly-built session
///   - Wrapped as nostr `kind=4`, ephemeral sender, p-tagged to alice's
///     `onetimekey` from the FR (the address she's subscribed to)
async fn build_v1_accept_event(
    my_identity: &Identity,
    my_signal: &mut SignalParticipant,
    friend_request: &FriendRequestReceived,
    display_name: &str,
) -> Result<FriendRequestAccepted> {
    let payload = &friend_request.payload;
    let (prekey_bundle, remote_address) = build_prekey_bundle_from_payload(payload)?;

    my_signal.process_prekey_bundle(&remote_address, &prekey_bundle)?;
    tracing::info!("session established (v1 path) for friend request acceptance");

    if payload.first_inbox.is_empty() {
        return Err(KeychatError::Signal(
            "v1 FR missing onetimekey (payload.first_inbox) — cannot route accept".into(),
        ));
    }

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let my_signal_id_hex = my_signal.identity_public_key_hex();
    let sig = compute_global_sign(
        my_identity.secret_key(),
        &my_identity.pubkey_hex(),
        &my_signal_id_hex,
        time,
    )?;

    // Plaintext human-readable body shown in alice's chat log. Must match
    // `RoomUtil.getHelloMessage` so the UX looks identical to a native v1
    // approve.
    let hello = format!(
        "\u{1F604} Hi, I'm {display_name}.\nLet's start an encrypted chat."
    );

    // v1 `PrekeyMessageModel` — field names are lowerCamelCase to match the
    // Dart `@JsonSerializable` output. `lightning`/`avatar` are optional;
    // serde_json's `Value` skips them naturally.
    let pmm = serde_json::json!({
        "nostrId": my_identity.pubkey_hex(),
        "signalId": my_signal_id_hex,
        "time": time,
        "sig": sig.clone(),
        "name": display_name,
        "message": hello.clone(),
    });
    let pmm_bytes = serde_json::to_vec(&pmm)
        .map_err(|e| KeychatError::Signal(format!("pmm serialize: {e}")))?;

    let ct = my_signal.encrypt(&remote_address, &pmm_bytes)?;

    // kind=4 with ephemeral signer and p-tag to alice's onetimekey.
    let event =
        crate::chat::build_mode1_event_with_kind(&ct.bytes, &payload.first_inbox, Kind::from(4))
            .await?;

    // Caller bookkeeping — expose a friendApprove KCMessage with the same
    // SignalPrekeyAuth the v2 path produces, so upstream logging is uniform.
    let request_id = friend_request.message.id.clone().unwrap_or_default();
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

    Ok(FriendRequestAccepted {
        signal_participant: my_signal.clone(),
        event,
        message: approve_msg,
        sender_address: ct.sender_address,
    })
}

// ─── Public API ─────────────────────────────────────────────────────────────

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

    let (gift_wrap_event, request_id) = build_friend_request_event(
        my_identity,
        &peer_nostr_pubkey_hex,
        display_name,
        device_id,
        &signal_participant,
        &first_inbox_keys.pubkey_hex(),
    )
    .await?;

    tracing::info!(
        "sent friend request to peer={}",
        &peer_nostr_pubkey_hex[..16.min(peer_nostr_pubkey_hex.len())]
    );
    Ok((
        gift_wrap_event,
        FriendRequestState {
            signal_participant,
            first_inbox_keys,
            request_id,
            peer_nostr_pubkey: peer_nostr_pubkey_hex,
        },
    ))
}

/// Receive and parse a friend request from a Gift Wrap event (§7.1, §7.2).
pub fn receive_friend_request(
    my_identity: &Identity,
    gift_wrap_event: &Event,
) -> Result<FriendRequestReceived> {
    let unwrapped = unwrap_gift_wrap(my_identity.keys(), gift_wrap_event)?;

    let message = KCMessage::try_parse_any(&unwrapped.content)
        .ok_or_else(|| KeychatError::Signal("failed to parse KCMessage from Gift Wrap".into()))?;

    if message.kind != KCMessageKind::FriendRequest {
        return Err(KeychatError::Signal(format!(
            "expected friendRequest, got {:?}",
            message.kind
        )));
    }

    let payload = message
        .friend_request
        .clone()
        .ok_or_else(|| KeychatError::Signal("friendRequest message missing payload".into()))?;

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
        tracing::warn!(
            "globalSign verification failed for friend request from {}",
            &payload.nostr_identity_key[..16.min(payload.nostr_identity_key.len())]
        );
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

    tracing::info!(
        "received friend request from {}",
        &sender_hex[..16.min(sender_hex.len())]
    );
    Ok(FriendRequestReceived {
        sender_pubkey: unwrapped.sender_pubkey,
        sender_pubkey_hex: sender_hex,
        message,
        payload,
        created_at: unwrapped.created_at.as_u64(),
    })
}

/// Accept a friend request (§7.3, §7.4).
pub async fn accept_friend_request(
    my_identity: &Identity,
    friend_request: &FriendRequestReceived,
    display_name: &str,
) -> Result<FriendRequestAccepted> {
    tracing::info!(
        "accepting friend request from {}",
        &friend_request.sender_pubkey_hex[..16.min(friend_request.sender_pubkey_hex.len())]
    );
    let mut my_signal = SignalParticipant::new(my_identity.pubkey_hex(), 1)?;
    build_accept_event(my_identity, &mut my_signal, friend_request, display_name).await
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

    let (gift_wrap_event, request_id) = build_friend_request_event(
        my_identity,
        &peer_nostr_pubkey_hex,
        display_name,
        device_id,
        &signal_participant,
        &first_inbox_keys.pubkey_hex(),
    )
    .await?;

    tracing::info!(
        "sent friend request (persistent) to peer={}",
        &peer_nostr_pubkey_hex[..16.min(peer_nostr_pubkey_hex.len())]
    );
    Ok((
        gift_wrap_event,
        FriendRequestState {
            signal_participant,
            first_inbox_keys,
            request_id,
            peer_nostr_pubkey: peer_nostr_pubkey_hex,
        },
    ))
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
    tracing::info!(
        "accepting friend request (persistent) from {}",
        &friend_request.sender_pubkey_hex[..16.min(friend_request.sender_pubkey_hex.len())]
    );
    let mut my_signal =
        SignalParticipant::persistent(my_identity.pubkey_hex(), signal_device_id, keys, storage)?;
    build_accept_event(my_identity, &mut my_signal, friend_request, display_name).await
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

    // Accept both v2 native and v1 legacy payloads so peers on the older
    // Flutter app that emit `{"c":"signal","type":<n>,...}` after the handshake
    // remain interoperable.
    let message = KCMessage::try_parse_any(&plaintext_str)
        .ok_or_else(|| KeychatError::Signal("not a valid KCMessage".into()))?;

    Ok((message, decrypt_result))
}

use crate::chat::build_mode1_event;
use crate::message::uuid_v4;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the exact wire shape that v1 Flutter 1.40.9 puts on the relay:
    /// outer kind=1059 Gift Wrap whose inner rumor has `kind=1059` (v1 reuses
    /// nip17Kind for both layers) and whose rumor content is the
    /// `KeychatMessage{c,type=101,msg,name}` envelope with `name` carrying a
    /// serialized QRUserModel. The resulting event is what a v1 peer emits on
    /// the wire; libkeychat must accept it end-to-end.
    ///
    /// `sender_signal` supplies real Signal keys so the receiver can finish
    /// X3DH on accept. Callers without a persistent store pass an ephemeral
    /// `SignalParticipant::new(...)`.
    async fn build_v1_flutter_friend_request(
        sender: &Identity,
        sender_signal: &SignalParticipant,
        sender_onetimekey_hex: &str,
        receiver_pubkey: &PublicKey,
        sender_display_name: &str,
    ) -> Event {
        use crate::signal_keys::compute_global_sign;

        let signal_identity_hex = sender_signal.identity_public_key_hex();
        let time: u64 = 1_700_000_000_000; // milliseconds, as v1 emits
        let global_sign = compute_global_sign(
            sender.secret_key(),
            &sender.pubkey_hex(),
            &signal_identity_hex,
            time,
        )
        .unwrap();

        let qr = serde_json::json!({
            "name": sender_display_name,
            "pubkey": sender.pubkey_hex(),
            "curve25519PkHex": signal_identity_hex,
            "onetimekey": sender_onetimekey_hex,
            "signedId": sender_signal.signed_prekey_id(),
            "signedPublic": sender_signal.signed_prekey_public_hex().unwrap(),
            "signedSignature": sender_signal.signed_prekey_signature_hex().unwrap(),
            "prekeyId": sender_signal.prekey_id(),
            "prekeyPubkey": sender_signal.prekey_public_hex().unwrap(),
            "time": time,
            "globalSign": global_sign,
            "relay": "",
        });

        let outer = serde_json::json!({
            "c": "signal",
            "type": 101, // dmAddContactFromAlice
            "msg": "Hi, I'm Alice. Let's start an encrypted chat.",
            "name": qr.to_string(),
        });
        let content = outer.to_string();

        // Build the wire event with rumor kind=1059 (v1's quirk).
        let wrapper = EphemeralKeypair::generate();
        let now = Timestamp::now();
        let rumor: UnsignedEvent = EventBuilder::new(Kind::from(1059), &content)
            .tag(Tag::public_key(*receiver_pubkey))
            .custom_created_at(now)
            .build(sender.public_key());
        let seal_content =
            crate::nip44::encrypt(sender.secret_key(), receiver_pubkey, &rumor.as_json()).unwrap();
        let seal = EventBuilder::new(Kind::from(13), &seal_content)
            .custom_created_at(now)
            .sign(sender.keys())
            .await
            .unwrap();
        let wrap_content =
            crate::nip44::encrypt(wrapper.keys().secret_key(), receiver_pubkey, &seal.as_json())
                .unwrap();
        EventBuilder::new(Kind::GiftWrap, &wrap_content)
            .tag(Tag::public_key(*receiver_pubkey))
            .custom_created_at(now)
            .sign(wrapper.keys())
            .await
            .unwrap()
    }

    /// End-to-end: accepting a v1 Flutter FR must produce a plain
    /// signal-encrypted `kind=4` nostr event p-tagged to alice's onetimekey
    /// (from her FR). No QRUserModel, no KeychatMessage envelope — alice's
    /// v1 client will just decrypt it as the first chat message from bob.
    #[tokio::test]
    async fn v1_accept_is_signal_kind4_to_onetimekey() {
        let alice = Identity::generate().unwrap().identity; // v1 sender
        let bob = Identity::generate().unwrap().identity; // v1.5 receiver
        let alice_onetimekey = EphemeralKeypair::generate();

        let mut alice_signal = SignalParticipant::new(alice.pubkey_hex(), 1).unwrap();
        let fr_gw = build_v1_flutter_friend_request(
            &alice,
            &alice_signal,
            &alice_onetimekey.pubkey_hex(),
            &bob.public_key(),
            "Alice-v1",
        )
        .await;
        let received = receive_friend_request(&bob, &fr_gw).unwrap();
        assert_eq!(received.payload.version, 1);
        assert_eq!(received.payload.first_inbox, alice_onetimekey.pubkey_hex());

        let accepted = accept_friend_request(&bob, &received, "Bob-1.5")
            .await
            .unwrap();

        // Wire shape v1 subscribes to: plain kind=4 with a p-tag to alice's
        // onetimekey. No gift wrap, no QR.
        assert_eq!(accepted.event.kind, Kind::from(4));
        let p_tags: Vec<&str> = accepted
            .event
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)))
            .filter_map(|t| t.content())
            .collect();
        assert_eq!(
            p_tags,
            vec![alice_onetimekey.pubkey_hex().as_str()],
            "v1 accept must p-tag exactly alice's onetimekey"
        );
        // Sender is ephemeral, not bob's main identity.
        assert_ne!(accepted.event.pubkey, bob.public_key());

        // Alice can decrypt the content with her signal session against bob's
        // signal identity — i.e. a real X3DH session was established.
        let bob_signal_addr = ProtocolAddress::new(
            accepted.signal_participant.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        assert!(
            SignalParticipant::is_prekey_message(&ciphertext),
            "first accept ciphertext must be a PrekeyMessage"
        );
        let plaintext = alice_signal
            .decrypt_bytes(&bob_signal_addr, &ciphertext)
            .unwrap();
        let decoded = String::from_utf8(plaintext).unwrap();
        // Plaintext is a PrekeyMessageModel JSON — the shape v1's
        // `decryptPreKeyMessage` parses.
        let pmm: serde_json::Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(pmm["nostrId"], bob.pubkey_hex());
        assert_eq!(pmm["name"], "Bob-1.5");
        assert!(
            pmm["message"].as_str().unwrap().contains("Bob-1.5"),
            "message field should contain hello greeting"
        );
        assert_eq!(
            pmm["signalId"].as_str().unwrap(),
            accepted.signal_participant.identity_public_key_hex()
        );

        // sig verifies as a schnorr sig over `Keychat-{nostrId}-{signalId}-{time}`,
        // exactly what v1's `SignalChatUtil.verifySignedMessage` checks.
        let sig_valid = verify_global_sign(
            pmm["nostrId"].as_str().unwrap(),
            pmm["signalId"].as_str().unwrap(),
            pmm["time"].as_u64().unwrap(),
            pmm["sig"].as_str().unwrap(),
        )
        .unwrap();
        assert!(sig_valid, "PrekeyMessageModel sig must verify");
    }

    /// End-to-end: after bob accepts a v1 FR, his follow-up chat sends (before
    /// alice replies) must still land on alice's onetimekey AND wrap the v1
    /// KeychatMessage JSON as a `PrekeyMessageModel`. v1's
    /// `decryptPreKeyMessage` (the p-tag=onetimekey branch) expects the Signal
    /// plaintext to be PMM JSON — a raw v1 KCMessage JSON would fail the
    /// `PrekeyMessageModel.fromJson` parse and the message would be dropped.
    #[tokio::test]
    async fn v1_follow_up_wraps_v1_json_as_pmm_before_peer_reply() {
        // ── setup: alice sends v1 FR, bob accepts ────────────────────────
        let alice = Identity::generate().unwrap().identity;
        let bob = Identity::generate().unwrap().identity;
        let alice_onetimekey = EphemeralKeypair::generate();

        let mut alice_signal = SignalParticipant::new(alice.pubkey_hex(), 1).unwrap();
        let fr_gw = build_v1_flutter_friend_request(
            &alice,
            &alice_signal,
            &alice_onetimekey.pubkey_hex(),
            &bob.public_key(),
            "Alice-v1",
        )
        .await;
        let received = receive_friend_request(&bob, &fr_gw).unwrap();
        let accepted = accept_friend_request(&bob, &received, "Bob-1.5")
            .await
            .unwrap();

        // Drain the accept ciphertext on alice's side so her Signal session
        // state matches what it would be after receiving bob's accept off the
        // relay — otherwise the follow-up `decrypt` below would still hit the
        // prekey branch incorrectly.
        let bob_signal_addr = ProtocolAddress::new(
            accepted.signal_participant.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );
        let accept_ct = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        alice_signal.decrypt_bytes(&bob_signal_addr, &accept_ct).unwrap();

        // ── bob, still in the "peer hasn't replied" phase, sends a follow-up.
        // This mirrors the v1 path in keychat-app-core's messaging.rs:
        //   1. v2_to_v1 → "{\"c\":\"signal\",\"type\":100,\"msg\":\"…\"}"
        //   2. wrap in PrekeyMessageModel
        //   3. Signal-encrypt
        //   4. build_mode1_event_with_kind (kind=4, p-tag = alice_onetimekey)
        let mut bob_signal = accepted.signal_participant;
        let v1_json =
            r#"{"c":"signal","type":100,"msg":"follow-up from bob"}"#.to_string();

        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let bob_signal_id_hex = bob_signal.identity_public_key_hex();
        let sig = compute_global_sign(
            bob.secret_key(),
            &bob.pubkey_hex(),
            &bob_signal_id_hex,
            time,
        )
        .unwrap();
        let pmm = serde_json::json!({
            "nostrId": bob.pubkey_hex(),
            "signalId": bob_signal_id_hex,
            "time": time,
            "sig": sig,
            "name": "Bob-1.5",
            "message": v1_json.clone(),
        });
        let pmm_bytes = serde_json::to_vec(&pmm).unwrap();

        let alice_signal_addr = ProtocolAddress::new(
            alice_signal.identity_public_key_hex(),
            DeviceId::new(1).unwrap(),
        );
        let ct = bob_signal.encrypt(&alice_signal_addr, &pmm_bytes).unwrap();
        let event = crate::chat::build_mode1_event_with_kind(
            &ct.bytes,
            &alice_onetimekey.pubkey_hex(),
            Kind::from(4),
        )
        .await
        .unwrap();

        // ── wire-shape assertions ──────────────────────────────────────
        assert_eq!(event.kind, Kind::from(4), "v1 follow-up must be kind=4");
        let p_tags: Vec<&str> = event
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)))
            .filter_map(|t| t.content())
            .collect();
        assert_eq!(
            p_tags,
            vec![alice_onetimekey.pubkey_hex().as_str()],
            "v1 follow-up must p-tag alice's onetimekey while she hasn't replied"
        );
        assert_ne!(
            event.pubkey,
            bob.public_key(),
            "v1 follow-up sender must be ephemeral, not bob's main identity"
        );

        // ── alice decrypts: plaintext must parse as PMM (v1 requirement) ─
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&event.content)
            .unwrap();
        // PreKey vs Signal message depends on whether alice has acked yet.
        // We drained accept above, so ratchets have advanced; the follow-up
        // may be either kind depending on ordering. Either way alice decrypts.
        let plaintext = alice_signal
            .decrypt_bytes(&bob_signal_addr, &ciphertext)
            .unwrap();
        let decoded = String::from_utf8(plaintext).unwrap();

        let pmm: serde_json::Value = serde_json::from_str(&decoded)
            .expect("v1 follow-up plaintext must be parseable as PrekeyMessageModel JSON");
        assert_eq!(pmm["nostrId"], bob.pubkey_hex());
        assert_eq!(pmm["signalId"], bob_signal_id_hex);
        assert_eq!(pmm["name"], "Bob-1.5");
        assert_eq!(
            pmm["message"].as_str().unwrap(),
            v1_json,
            "PMM.message must carry the v1 KCMessage JSON unchanged"
        );
        let sig_valid = verify_global_sign(
            pmm["nostrId"].as_str().unwrap(),
            pmm["signalId"].as_str().unwrap(),
            pmm["time"].as_u64().unwrap(),
            pmm["sig"].as_str().unwrap(),
        )
        .unwrap();
        assert!(sig_valid, "PMM sig must verify");
    }

    /// End-to-end: a v1 Flutter-shaped FR must be unwrapped and parsed into
    /// a `FriendRequestReceived` — i.e. the UI can show the accept button.
    #[tokio::test]
    async fn v1_flutter_friend_request_round_trip() {
        let alice = Identity::generate().unwrap().identity;
        let bob = Identity::generate().unwrap().identity;
        let alice_signal = SignalParticipant::new(alice.pubkey_hex(), 1).unwrap();
        let alice_onetimekey = EphemeralKeypair::generate();

        let gw = build_v1_flutter_friend_request(
            &alice,
            &alice_signal,
            &alice_onetimekey.pubkey_hex(),
            &bob.public_key(),
            "Alice-v1",
        )
        .await;
        assert_eq!(gw.kind, Kind::GiftWrap);

        let received = receive_friend_request(&bob, &gw).expect("v1 FR must unwrap + parse");
        assert_eq!(received.sender_pubkey, alice.public_key());
        assert_eq!(received.payload.name, "Alice-v1");
        assert_eq!(received.message.kind, KCMessageKind::FriendRequest);
        assert_eq!(received.payload.version, 1);
        assert!(received.payload.signal_kyber_prekey.is_empty(), "v1 has no Kyber");
        assert!(received.payload.message.is_some(), "greeting message preserved");
    }

    #[tokio::test]
    async fn full_friend_request_roundtrip() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        // Step 1: Alice sends friend request
        let (gift_wrap, alice_state) =
            send_friend_request(&alice_id, &bob_id.pubkey_hex(), "Alice", "device-alice")
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
        let accepted = accept_friend_request(&bob_id, &received, "Bob")
            .await
            .unwrap();
        assert_eq!(accepted.event.kind, Kind::GiftWrap);
        assert_eq!(accepted.message.kind, KCMessageKind::FriendApprove);
        assert!(accepted.message.signal_prekey_auth.is_some());

        // Step 4: Alice decrypts Bob's approval
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        let bob_signal_id = accepted.signal_participant.identity_public_key_hex();
        let bob_signal_addr =
            ProtocolAddress::new(bob_signal_id.clone(), DeviceId::new(1).unwrap());

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

        let (gift_wrap, _) = send_friend_request(&alice_id, &bob_id.pubkey_hex(), "Alice", "dev-1")
            .await
            .unwrap();

        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        let p = &received.payload;

        // Tampered time
        let result = verify_global_sign(
            &p.nostr_identity_key,
            &p.signal_identity_key,
            p.time.unwrap() + 1,
            &p.global_sign,
        )
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

        let (gift_wrap, _) = send_friend_request(&alice_id, &bob_id.pubkey_hex(), "Alice", "dev-1")
            .await
            .unwrap();

        let result = receive_friend_request(&charlie_id, &gift_wrap);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn prekey_message_on_first_approve() {
        let alice_id = Identity::generate().unwrap().identity;
        let bob_id = Identity::generate().unwrap().identity;

        let (gift_wrap, _) = send_friend_request(&alice_id, &bob_id.pubkey_hex(), "Alice", "dev-1")
            .await
            .unwrap();

        let received = receive_friend_request(&bob_id, &gift_wrap).unwrap();
        let accepted = accept_friend_request(&bob_id, &received, "Bob")
            .await
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&accepted.event.content)
            .unwrap();
        assert!(
            SignalParticipant::is_prekey_message(&ciphertext),
            "first message after accept should be a PrekeyMessage"
        );
    }
}
