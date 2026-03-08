use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use libsignal_protocol::ProtocolAddress;

use crate::error::{KeychatError, Result};
use crate::identity::NostrKeypair;
use crate::nostr::nip04;
use crate::nostr::{generate_ephemeral_sender, now, NostrEvent};
use crate::protocol::address::{generate_seed_from_ratchetkey_pair, AddressChange, AddressManager};
use crate::protocol::message_types::KeychatMessage;
use crate::signal::{SignalDecryptResult, SignalParticipant};

#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub message: KeychatMessage,
    pub decrypt_result: Option<SignalDecryptResult>,
    pub address_changes: Vec<AddressChange>,
}

pub fn send_signal_message(
    _local_nostr_keys: &NostrKeypair,
    local_signal: &mut SignalParticipant,
    remote_signal_address: &ProtocolAddress,
    address_manager: &mut AddressManager,
    peer_id: &str,
    message: &KeychatMessage,
) -> Result<(NostrEvent, Vec<AddressChange>)> {
    let address = address_manager
        .get_sending_address(peer_id)
        .ok_or_else(|| KeychatError::MissingSendingAddress(peer_id.to_owned()))?;
    send_signal_message_to_address(
        local_signal,
        remote_signal_address,
        address_manager,
        peer_id,
        &address,
        message,
    )
}

pub fn send_signal_message_to_address(
    local_signal: &mut SignalParticipant,
    remote_signal_address: &ProtocolAddress,
    address_manager: &mut AddressManager,
    peer_id: &str,
    recipient_address: &str,
    message: &KeychatMessage,
) -> Result<(NostrEvent, Vec<AddressChange>)> {
    send_signal_plaintext_to_address(
        local_signal,
        remote_signal_address,
        address_manager,
        peer_id,
        recipient_address,
        &message.to_json()?,
    )
}

pub fn send_signal_plaintext_to_address(
    local_signal: &mut SignalParticipant,
    remote_signal_address: &ProtocolAddress,
    address_manager: &mut AddressManager,
    peer_id: &str,
    recipient_address: &str,
    plaintext: &str,
) -> Result<(NostrEvent, Vec<AddressChange>)> {
    let ciphertext =
        local_signal.encrypt_with_metadata(remote_signal_address, plaintext.as_bytes())?;
    let mut changes = Vec::new();
    if let Some(raw_seed) = ciphertext.sender_address.as_ref() {
        if let Ok(nostr_address) = generate_seed_from_ratchetkey_pair(raw_seed) {
            changes.extend(address_manager.note_outbound_address(peer_id, nostr_address));
        }
    }

    let sender = generate_ephemeral_sender();
    let event = NostrEvent::new_unsigned(
        sender.public_key_hex(),
        4,
        vec![vec!["p".to_owned(), recipient_address.to_owned()]],
        STANDARD.encode(ciphertext.bytes),
        now(),
    )
    .sign(&sender)?;
    Ok((event, changes))
}

pub fn receive_message(
    local_nostr_keys: &NostrKeypair,
    local_signal: &mut SignalParticipant,
    remote_signal_address: &ProtocolAddress,
    address_manager: &mut AddressManager,
    peer_id: &str,
    event: &NostrEvent,
) -> Result<ReceivedMessage> {
    if event.kind != 4 {
        return Err(KeychatError::InvalidEventKind {
            expected: 4,
            actual: event.kind,
        });
    }

    let mut address_changes = Vec::new();
    if event.content.contains("?iv=") {
        let plaintext = nip04::decrypt(local_nostr_keys, &event.pubkey, &event.content)?;
        let message = KeychatMessage::from_json(&plaintext)?;
        return Ok(ReceivedMessage {
            message,
            decrypt_result: None,
            address_changes,
        });
    }

    let ciphertext = STANDARD.decode(&event.content)?;

    // Try decrypting with the provided remote address first.
    // If that fails and it's a PreKey message, extract the sender's Signal identity
    // from the ciphertext and retry (needed when we don't know the peer's Signal address yet,
    // e.g. receiving the first reply after sending Hello).
    let decrypt_result = match local_signal
        .decrypt_with_metadata(remote_signal_address, &ciphertext)
    {
        Ok(result) => result,
        Err(_first_err) => {
            if let Ok(prekey_msg) =
                libsignal_protocol::PreKeySignalMessage::try_from(ciphertext.as_slice())
            {
                let identity_hex = hex::encode(prekey_msg.identity_key().public_key().serialize());
                let extracted_addr =
                    libsignal_protocol::ProtocolAddress::new(identity_hex, 1u32.into());
                local_signal
                    .decrypt_with_metadata(&extracted_addr, &ciphertext)
                    .map_err(|_| _first_err)?
            } else {
                return Err(_first_err);
            }
        }
    };
    address_changes.extend(address_manager.on_message_decrypted(peer_id, &decrypt_result));
    if let Some(address) = decrypt_result.bob_derived_address.clone() {
        address_changes.extend(address_manager.set_sending_address(peer_id, address));
    }
    let plaintext_str = String::from_utf8(decrypt_result.plaintext.clone())?;
    // debug output removed — breaks TUI rendering
    let message = KeychatMessage::from_json_flexible(&plaintext_str)?;
    Ok(ReceivedMessage {
        message,
        decrypt_result: Some(decrypt_result),
        address_changes,
    })
}
