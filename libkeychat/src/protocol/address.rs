use std::collections::{BTreeMap, VecDeque};

use libsignal_protocol::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::{KeychatError, Result};
use crate::signal::SignalDecryptResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressChange {
    Subscribe(String),
    Unsubscribe(String),
    UpdateSendAddr { peer_id: String, address: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PeerAddresses {
    receiving: VecDeque<String>,
    sending: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddressManager {
    peers: BTreeMap<String, PeerAddresses>,
}

impl AddressManager {
    pub fn track_pending_hello(
        &mut self,
        peer_id: &str,
        peer_nostr_pubkey: String,
        my_first_inbox: String,
        my_signal_key: String,
    ) {
        let peer = self.peers.entry(peer_id.to_owned()).or_default();
        peer.receiving.clear();
        peer.receiving.push_back(my_first_inbox.clone());
        if my_signal_key != my_first_inbox {
            peer.receiving.push_back(my_signal_key);
        }
        peer.sending = Some(peer_nostr_pubkey);
    }

    pub fn note_outbound_address(&mut self, peer_id: &str, address: String) -> Vec<AddressChange> {
        self.push_receiving(peer_id, vec![address], false)
    }

    pub fn set_sending_address(&mut self, peer_id: &str, address: String) -> Vec<AddressChange> {
        let peer = self.peers.entry(peer_id.to_owned()).or_default();
        peer.sending = Some(address.clone());
        vec![AddressChange::UpdateSendAddr {
            peer_id: peer_id.to_owned(),
            address,
        }]
    }

    pub fn on_message_decrypted(
        &mut self,
        peer_id: &str,
        decrypt_result: &SignalDecryptResult,
    ) -> Vec<AddressChange> {
        let Some(addresses) = decrypt_result.alice_addrs.clone() else {
            return Vec::new();
        };
        self.push_receiving(peer_id, addresses, false)
    }

    pub fn get_all_receiving_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::new();
        for peer in self.peers.values() {
            for address in &peer.receiving {
                if !addresses.contains(address) {
                    addresses.push(address.clone());
                }
            }
        }
        addresses
    }

    pub fn get_sending_address(&self, peer_id: &str) -> Option<String> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.sending.clone())
    }

    pub fn resolve_peer_by_receiving_address(&self, address: &str) -> Option<String> {
        self.peers.iter().find_map(|(peer_id, peer)| {
            peer.receiving
                .iter()
                .any(|current| current == address)
                .then(|| peer_id.clone())
        })
    }

    fn push_receiving(
        &mut self,
        peer_id: &str,
        addresses: Vec<String>,
        update_send_addr: bool,
    ) -> Vec<AddressChange> {
        let peer = self.peers.entry(peer_id.to_owned()).or_default();
        let mut changes = Vec::new();

        for address in addresses {
            if peer.receiving.iter().any(|current| current == &address) {
                continue;
            }
            peer.receiving.push_back(address.clone());
            changes.push(AddressChange::Subscribe(address.clone()));
            while peer.receiving.len() > 3 {
                if let Some(removed) = peer.receiving.pop_front() {
                    changes.push(AddressChange::Unsubscribe(removed));
                }
            }
            if update_send_addr {
                peer.sending = Some(address.clone());
            }
        }

        if update_send_addr {
            if let Some(address) = peer.sending.clone() {
                changes.push(AddressChange::UpdateSendAddr {
                    peer_id: peer_id.to_owned(),
                    address,
                });
            }
        }

        changes
    }
}

pub fn generate_seed_from_ratchetkey_pair(seed_key: &str) -> Result<String> {
    let (private_hex, public_hex) = seed_key.split_once('-').ok_or_else(|| {
        KeychatError::InvalidArgument("expected private-public format".to_owned())
    })?;

    let private = hex::decode(private_hex)?;
    let public = hex::decode(public_hex)?;
    let alice_private = PrivateKey::deserialize(&private)?;
    let bob_public = PublicKey::deserialize(&public)?;

    let mut secrets = Vec::with_capacity(32 * 5);
    secrets.extend_from_slice(&[0xFFu8; 32]);
    secrets.extend_from_slice(&alice_private.calculate_agreement(&bob_public)?);

    let secret_hash = sha2::Sha256::digest(&secrets);
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&secret_hash[..32])?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let x_public_key = public_key.x_only_public_key().0.serialize();

    Ok(hex::encode(x_public_key))
}
