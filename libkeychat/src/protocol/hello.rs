use libsignal_protocol::{PreKeyBundle, PreKeyId, ProtocolAddress, PublicKey, SignedPreKeyId};

use crate::error::{KeychatError, Result};
use crate::identity::{generate_random_nostr_keypair, NostrKeypair};
use crate::nostr::nip59;
use crate::nostr::{now, sign_message, verify_message, NostrEvent};
use crate::protocol::address::{AddressChange, AddressManager};
use crate::protocol::message_types::{
    AcceptContactReply, KeychatMessage, QRUserModel, TYPE_ADD_CONTACT,
};
use crate::protocol::messaging::send_signal_plaintext_to_address;
use crate::signal::keys::generate_prekey_material;
use crate::signal::SignalParticipant;

#[derive(Clone)]
pub struct HelloInit {
    pub event: NostrEvent,
    pub signal: SignalParticipant,
    pub onetime_key: NostrKeypair,
    pub qr: QRUserModel,
    pub address_changes: Vec<AddressChange>,
}

#[derive(Clone, Debug)]
pub struct HelloReceiveOutcome {
    pub remote_signal_address: ProtocolAddress,
    pub hello_message: KeychatMessage,
    pub peer: QRUserModel,
    pub auto_reply: NostrEvent,
    pub address_changes: Vec<AddressChange>,
}

pub fn create_hello(
    local_nostr_keys: &NostrKeypair,
    recipient_pubkey_hex: &str,
    display_name: &str,
    greeting: &str,
    peer_id: &str,
    address_manager: &mut AddressManager,
) -> Result<HelloInit> {
    let prekeys = generate_prekey_material()?;
    let signal_identity = hex::encode(prekeys.identity_key_pair.identity_key().serialize());
    let signal = SignalParticipant::from_prekey_material(signal_identity.clone(), 1, prekeys)?;
    let onetime_key = generate_random_nostr_keypair();
    let time = now();
    let global_sign = sign_message(
        &local_nostr_keys.secret_key(),
        format!(
            "Keychat-{}-{}-{}",
            local_nostr_keys.public_key_hex(),
            signal_identity,
            time
        )
        .as_bytes(),
    )?;

    let qr = QRUserModel {
        name: display_name.to_owned(),
        pubkey: local_nostr_keys.public_key_hex(),
        curve25519_pk_hex: signal_identity.clone(),
        onetimekey: onetime_key.public_key_hex(),
        signed_id: signal.signed_prekey_id(),
        signed_public: signal.signed_prekey_public_hex()?,
        signed_signature: signal.signed_prekey_signature_hex()?,
        prekey_id: signal.prekey_id(),
        prekey_pubkey: signal.prekey_public_hex()?,
        time,
        global_sign,
        relay: String::new(),
        lightning: String::new(),
        avatar: String::new(),
    };

    let hello_message = KeychatMessage {
        c: "signal".to_owned(),
        r#type: TYPE_ADD_CONTACT,
        msg: greeting.to_owned(),
        name: Some(serde_json::to_string(&qr)?),
    };

    let address_changes = {
        address_manager.track_pending_hello(
            peer_id,
            recipient_pubkey_hex.to_owned(),
            qr.onetimekey.clone(),
            signal_identity,
        );
        address_manager
            .get_all_receiving_addresses()
            .into_iter()
            .map(AddressChange::Subscribe)
            .collect()
    };

    let event = nip59::create_gift_wrap(
        local_nostr_keys,
        recipient_pubkey_hex,
        14,
        hello_message.to_json()?,
        Vec::new(),
    )?;

    Ok(HelloInit {
        event,
        signal,
        onetime_key,
        qr,
        address_changes,
    })
}

pub fn receive_hello(
    local_nostr_keys: &NostrKeypair,
    local_signal: &mut SignalParticipant,
    address_manager: &mut AddressManager,
    event: &NostrEvent,
) -> Result<HelloReceiveOutcome> {
    let rumor = nip59::unwrap_gift_wrap(local_nostr_keys, event)?;
    let hello_message = KeychatMessage::from_json(&rumor.content)?;
    let qr_json = hello_message
        .name
        .as_deref()
        .ok_or(KeychatError::MissingTag("name"))?;
    let peer: QRUserModel = serde_json::from_str(qr_json)?;

    verify_message(
        &peer.pubkey,
        format!(
            "Keychat-{}-{}-{}",
            peer.pubkey, peer.curve25519_pk_hex, peer.time
        )
        .as_bytes(),
        &peer.global_sign,
    )?;

    let remote_signal_address = ProtocolAddress::new(peer.curve25519_pk_hex.clone(), 1u32.into());
    local_signal.process_prekey_bundle(&remote_signal_address, &qr_to_prekey_bundle(&peer)?)?;

    let mut address_changes =
        address_manager.set_sending_address(&peer.pubkey, peer.onetimekey.clone());

    // Build PrekeyMessageModel — required when sending to peer's onetimekey (§6.6, §9.4)
    let reply_time = now();
    let reply_text = format!("Hi, {}", peer.name);
    let reply_sig = sign_message(
        &local_nostr_keys.secret_key(),
        format!(
            "Keychat-{}-{}-{}",
            local_nostr_keys.public_key_hex(),
            local_signal.identity_public_key_hex(),
            reply_time
        )
        .as_bytes(),
    )?;
    let pmm = AcceptContactReply {
        nostr_id: local_nostr_keys.public_key_hex(),
        signal_id: local_signal.identity_public_key_hex(),
        name: "libkeychat".to_owned(),
        message: reply_text,
        time: reply_time,
        sig: reply_sig,
        lightning: String::new(),
        avatar: String::new(),
    };
    let pmm_json = serde_json::to_string(&pmm)?;

    // Send PrekeyMessageModel JSON directly as Signal plaintext (not wrapped in KeychatMessage)
    let (auto_reply, send_changes) = send_signal_plaintext_to_address(
        local_signal,
        &remote_signal_address,
        address_manager,
        &peer.pubkey,
        &peer.onetimekey,
        &pmm_json,
    )?;
    address_changes.extend(send_changes);

    Ok(HelloReceiveOutcome {
        remote_signal_address,
        hello_message,
        peer,
        auto_reply,
        address_changes,
    })
}

fn qr_to_prekey_bundle(peer: &QRUserModel) -> Result<PreKeyBundle> {
    let prekey_public = PublicKey::deserialize(&hex::decode(&peer.prekey_pubkey)?)?;
    let signed_public = PublicKey::deserialize(&hex::decode(&peer.signed_public)?)?;
    let signature = hex::decode(&peer.signed_signature)?;
    let identity = libsignal_protocol::IdentityKey::decode(&hex::decode(&peer.curve25519_pk_hex)?)?;

    Ok(PreKeyBundle::new(
        0,
        1u32.into(),
        Some((PreKeyId::from(peer.prekey_id), prekey_public)),
        SignedPreKeyId::from(peer.signed_id),
        signed_public,
        signature,
        identity,
    )?)
}
