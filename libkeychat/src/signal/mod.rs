pub mod keys;
pub mod session_store;
pub mod store;

use std::collections::BTreeMap;
use std::time::SystemTime;

use futures::executor::block_on;
use libsignal_protocol::{
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, DeviceId, GenericSignedPreKey, InMemIdentityKeyStore, InMemKyberPreKeyStore,
    InMemPreKeyStore, InMemRatchetKeyStore, InMemSignedPreKeyStore, PreKeyBundle, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignalMessage,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{KeychatError, Result};
use crate::protocol::address::generate_seed_from_ratchetkey_pair;
use crate::signal::keys::{generate_prekey_material, SignalPreKeyMaterial};
use crate::signal::session_store::CapturingSessionStore;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalCiphertext {
    pub bytes: Vec<u8>,
    pub sender_address: Option<String>,
    pub message_key_hash: String,
    pub prior_alice_addrs: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalDecryptResult {
    pub plaintext: Vec<u8>,
    pub message_key_hash: String,
    pub alice_addrs: Option<Vec<String>>,
    pub bob_derived_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalParticipantSnapshot {
    pub name: String,
    pub device_id: u32,
    pub registration_id: u32,
    pub identity_key_pair: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey: Vec<u8>,
    pub prekey_id: u32,
    pub prekey: Vec<u8>,
    pub sessions: Vec<SignalSessionSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalSessionSnapshot {
    pub address: String,
    pub device_id: u32,
    pub record: Vec<u8>,
}

#[derive(Clone)]
pub struct SignalParticipant {
    address: ProtocolAddress,
    store: SignalProtocolStore,
    keys: SignalPreKeyMaterial,
    tracked_peers: BTreeMap<String, ProtocolAddress>,
}

#[derive(Clone)]
struct SignalProtocolStore {
    session_store: CapturingSessionStore,
    pre_key_store: InMemPreKeyStore,
    signed_pre_key_store: InMemSignedPreKeyStore,
    kyber_pre_key_store: InMemKyberPreKeyStore,
    identity_store: InMemIdentityKeyStore,
    ratchet_key_store: InMemRatchetKeyStore,
}

impl SignalParticipant {
    pub fn new(name: impl Into<String>, device_id: u32) -> Result<Self> {
        let keys = generate_prekey_material()?;
        Self::from_prekey_material(name.into(), device_id, keys)
    }

    pub fn from_prekey_material(
        name: String,
        device_id: u32,
        keys: SignalPreKeyMaterial,
    ) -> Result<Self> {
        let mut store = SignalProtocolStore {
            session_store: CapturingSessionStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            kyber_pre_key_store: InMemKyberPreKeyStore::new(),
            identity_store: InMemIdentityKeyStore::new(
                keys.identity_key_pair,
                keys.registration_id,
            ),
            ratchet_key_store: InMemRatchetKeyStore::new(),
        };

        block_on(async {
            store
                .pre_key_store
                .save_pre_key(keys.prekey_id, &keys.prekey)
                .await
                .map_err(KeychatError::from)?;
            store
                .signed_pre_key_store
                .save_signed_pre_key(keys.signed_prekey_id, &keys.signed_prekey)
                .await
                .map_err(KeychatError::from)?;
            Ok::<(), KeychatError>(())
        })?;

        Ok(Self {
            address: ProtocolAddress::new(name, DeviceId::from(device_id)),
            store,
            keys,
            tracked_peers: BTreeMap::new(),
        })
    }

    pub fn from_snapshot(snapshot: SignalParticipantSnapshot) -> Result<Self> {
        let keys = SignalPreKeyMaterial {
            identity_key_pair: snapshot.identity_key_pair.as_slice().try_into()?,
            registration_id: snapshot.registration_id,
            signed_prekey_id: snapshot.signed_prekey_id.into(),
            signed_prekey: <SignedPreKeyRecord as GenericSignedPreKey>::deserialize(
                &snapshot.signed_prekey,
            )?,
            prekey_id: snapshot.prekey_id.into(),
            prekey: PreKeyRecord::deserialize(&snapshot.prekey)?,
        };

        let mut participant = Self::from_prekey_material(snapshot.name, snapshot.device_id, keys)?;
        for session in snapshot.sessions {
            let address = ProtocolAddress::new(session.address, DeviceId::from(session.device_id));
            let record = SessionRecord::deserialize(&session.record)?;
            block_on(
                participant
                    .store
                    .session_store
                    .store_session(&address, &record, None, None, None),
            )?;
            participant.track_peer(&address);
        }

        Ok(participant)
    }

    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    pub fn prekey_bundle(&self) -> Result<PreKeyBundle> {
        self.keys.build_prekey_bundle(self.address.device_id())
    }

    pub fn process_prekey_bundle(
        &mut self,
        remote: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<()> {
        block_on(process_prekey_bundle(
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            bundle,
            SystemTime::now(),
            &mut OsRng,
        ))?;
        self.track_peer(remote);
        Ok(())
    }

    pub fn encrypt(&mut self, remote: &ProtocolAddress, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encrypt_with_metadata(remote, plaintext)?.bytes)
    }

    pub fn encrypt_with_metadata(
        &mut self,
        remote: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<SignalCiphertext> {
        let (message, sender_address, message_key_hash, prior_alice_addrs) =
            block_on(message_encrypt(
                plaintext,
                remote,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                SystemTime::now(),
                None,
            ))?;
        self.track_peer(remote);
        Ok(SignalCiphertext {
            bytes: message.serialize().to_vec(),
            sender_address,
            message_key_hash,
            prior_alice_addrs,
        })
    }

    pub fn decrypt(&mut self, remote: &ProtocolAddress, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.decrypt_with_metadata(remote, ciphertext)?.plaintext)
    }

    pub fn decrypt_with_metadata(
        &mut self,
        remote: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<SignalDecryptResult> {
        if let Ok(prekey) = PreKeySignalMessage::try_from(ciphertext) {
            let (plaintext, message_key_hash, alice_addrs) = block_on(message_decrypt_prekey(
                &prekey,
                remote,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut self.store.ratchet_key_store,
                &mut self.store.pre_key_store,
                &self.store.signed_pre_key_store,
                &mut self.store.kyber_pre_key_store,
                0,
                &mut OsRng,
            ))?;
            self.track_peer(remote);
            return Ok(SignalDecryptResult {
                plaintext,
                message_key_hash,
                alice_addrs,
                bob_derived_address: self.derive_bob_address(remote)?,
            });
        }

        if let Ok(signal) = SignalMessage::try_from(ciphertext) {
            let (plaintext, message_key_hash, alice_addrs) = block_on(message_decrypt_signal(
                &signal,
                remote,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut self.store.ratchet_key_store,
                0,
                &mut OsRng,
            ))?;
            self.track_peer(remote);
            return Ok(SignalDecryptResult {
                plaintext,
                message_key_hash,
                alice_addrs,
                bob_derived_address: self.derive_bob_address(remote)?,
            });
        }

        Err(KeychatError::InvalidCiphertext)
    }

    pub fn parse_ciphertext(ciphertext: &[u8]) -> Result<CiphertextMessage> {
        if let Ok(prekey) = PreKeySignalMessage::try_from(ciphertext) {
            return Ok(CiphertextMessage::PreKeySignalMessage(prekey));
        }
        if let Ok(signal) = SignalMessage::try_from(ciphertext) {
            return Ok(CiphertextMessage::SignalMessage(signal));
        }
        Err(KeychatError::InvalidCiphertext)
    }

    pub fn is_prekey_message(ciphertext: &[u8]) -> bool {
        PreKeySignalMessage::try_from(ciphertext).is_ok()
    }

    /// Extract the sender's Signal identity key hex from a PreKeySignalMessage.
    ///
    /// This is the correct remote address to use when decrypting a PreKey message
    /// from an unknown sender. Returns `None` if not a PreKey message.
    pub fn extract_prekey_sender_identity(ciphertext: &[u8]) -> Option<String> {
        PreKeySignalMessage::try_from(ciphertext)
            .ok()
            .map(|msg| hex::encode(msg.identity_key().serialize()))
    }

    pub fn registration_id(&self) -> u32 {
        self.keys.registration_id
    }

    pub fn identity_public_key_hex(&self) -> String {
        hex::encode(self.keys.identity_key_pair.identity_key().serialize())
    }

    pub fn signed_prekey_id(&self) -> u32 {
        u32::from(self.keys.signed_prekey_id)
    }

    pub fn signed_prekey_public_hex(&self) -> Result<String> {
        Ok(hex::encode(
            self.keys.signed_prekey.public_key()?.serialize(),
        ))
    }

    pub fn signed_prekey_signature_hex(&self) -> Result<String> {
        Ok(hex::encode(self.keys.signed_prekey.signature()?))
    }

    pub fn prekey_id(&self) -> u32 {
        u32::from(self.keys.prekey_id)
    }

    pub fn prekey_public_hex(&self) -> Result<String> {
        Ok(hex::encode(self.keys.prekey.public_key()?.serialize()))
    }

    pub fn snapshot(&mut self) -> Result<SignalParticipantSnapshot> {
        let mut sessions = Vec::new();
        for remote in self.tracked_peers.values() {
            if let Some(record) = block_on(self.store.session_store.load_session(remote))? {
                sessions.push(SignalSessionSnapshot {
                    address: remote.name().to_owned(),
                    device_id: u32::from(remote.device_id()),
                    record: record.serialize()?,
                });
            }
        }

        Ok(SignalParticipantSnapshot {
            name: self.address.name().to_owned(),
            device_id: u32::from(self.address.device_id()),
            registration_id: self.keys.registration_id,
            identity_key_pair: self.keys.identity_key_pair.serialize().into_vec(),
            signed_prekey_id: u32::from(self.keys.signed_prekey_id),
            signed_prekey: self.keys.signed_prekey.serialize()?,
            prekey_id: u32::from(self.keys.prekey_id),
            prekey: self.keys.prekey.serialize()?,
            sessions,
        })
    }

    fn track_peer(&mut self, remote: &ProtocolAddress) {
        self.tracked_peers
            .insert(remote.name().to_owned(), remote.clone());
    }

    fn derive_bob_address(&self, remote: &ProtocolAddress) -> Result<Option<String>> {
        let bob_address = self
            .store
            .session_store
            .bob_addresses
            .lock()
            .unwrap()
            .get(remote.name())
            .cloned();
        match bob_address {
            Some(address) if address.starts_with("05") => Ok(None),
            Some(address) => generate_seed_from_ratchetkey_pair(&address).map(Some),
            None => Ok(None),
        }
    }
}
