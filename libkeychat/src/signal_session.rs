//! Signal Protocol session management.
//!
//! Wraps `libsignal-protocol` into a higher-level `SignalParticipant` that manages
//! key material, session state, and encrypt/decrypt operations.
//!
//! Ratchet key extraction: Official libsignal v0.88.3 does NOT return ratchet
//! keys from encrypt/decrypt. We extract them by:
//! 1. Snapshotting the session state before each operation
//! 2. Parsing the updated SessionRecord protobuf after the operation
//! 3. Detecting DH ratchet steps by comparing old vs new sender chain keys

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use zeroize::Zeroize;

use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

use crate::error::{KeychatError, Result};
use crate::signal_store::SignalProtocolStoreBundle;
use crate::storage::SecureStorage;

/// Result of Signal encryption with ratchet metadata.
#[derive(Clone, Debug)]
pub struct SignalCiphertext {
    pub bytes: Vec<u8>,
    pub sender_address: Option<String>,
    pub message_key_hash: String,
    pub prior_alice_addrs: Option<Vec<String>>,
}

/// Result of Signal decryption with ratchet metadata.
#[derive(Clone, Debug)]
pub struct SignalDecryptResult {
    pub plaintext: Vec<u8>,
    pub message_key_hash: String,
    pub alice_addrs: Option<Vec<String>>,
    pub bob_derived_address: Option<String>,
}

/// Pre-key material for a Signal participant.
#[derive(Clone)]
pub struct SignalPreKeyMaterial {
    pub identity_key_pair: IdentityKeyPair,
    pub registration_id: u32,
    pub signed_prekey_id: SignedPreKeyId,
    pub signed_prekey: SignedPreKeyRecord,
    pub prekey_id: PreKeyId,
    pub prekey: PreKeyRecord,
    pub kyber_prekey_id: KyberPreKeyId,
    pub kyber_prekey: KyberPreKeyRecord,
}

impl SignalPreKeyMaterial {
    pub fn build_prekey_bundle(&self, device_id: DeviceId) -> Result<PreKeyBundle> {
        let bundle = PreKeyBundle::new(
            self.registration_id,
            device_id,
            Some((self.prekey_id, self.prekey.public_key()?)),
            self.signed_prekey_id,
            self.signed_prekey.public_key()?,
            self.signed_prekey.signature()?,
            self.kyber_prekey_id,
            self.kyber_prekey.public_key()?,
            self.kyber_prekey.signature()?,
            *self.identity_key_pair.identity_key(),
        )?;
        Ok(bundle)
    }
}

/// Generate fresh Signal pre-key material using libsignal-protocol native types.
///
/// Includes Kyber1024 prekey for PQXDH key agreement.
pub fn generate_prekey_material() -> Result<SignalPreKeyMaterial> {
    let mut rng = ::rand::rng();
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let registration_id: u32 = ::rand::random_range(1..=u32::MAX);

    let signed_prekey_id = SignedPreKeyId::from(::rand::random_range(1..=u32::MAX));
    let signed_prekey_key_pair = KeyPair::generate(&mut rng);
    let signed_prekey_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_prekey_key_pair.public_key.serialize(), &mut rng)
        .map_err(|e| KeychatError::Signal(format!("calculate_signature failed: {e}")))?;
    let signed_prekey = <SignedPreKeyRecord as GenericSignedPreKey>::new(
        signed_prekey_id,
        timestamp_now(),
        &signed_prekey_key_pair,
        &signed_prekey_signature,
    );

    let prekey_id = PreKeyId::from(::rand::random_range(1..=u32::MAX));
    let prekey_key_pair = KeyPair::generate(&mut rng);
    let prekey = PreKeyRecord::new(prekey_id, &prekey_key_pair);

    // Generate Kyber1024 prekey for PQXDH
    let kyber_prekey_id = KyberPreKeyId::from(::rand::random_range(1..=u32::MAX));
    let kyber_prekey = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        kyber_prekey_id,
        identity_key_pair.private_key(),
    )?;

    Ok(SignalPreKeyMaterial {
        identity_key_pair,
        registration_id,
        signed_prekey_id,
        signed_prekey,
        prekey_id,
        prekey,
        kyber_prekey_id,
        kyber_prekey,
    })
}

/// Reconstruct `SignalPreKeyMaterial` from raw serialized bytes.
///
/// Used to restore a participant from persistent storage on restart.
pub fn reconstruct_prekey_material(
    identity_public: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    signed_prekey_id_val: u32,
    signed_prekey_record_bytes: &[u8],
    prekey_id_val: u32,
    prekey_record_bytes: &[u8],
    kyber_prekey_id_val: u32,
    kyber_prekey_record_bytes: &[u8],
) -> Result<SignalPreKeyMaterial> {
    let identity_key = IdentityKey::decode(identity_public)
        .map_err(|e| KeychatError::Signal(format!("failed to decode identity public key: {e}")))?;
    let private_key = PrivateKey::deserialize(identity_private)
        .map_err(|e| KeychatError::Signal(format!("failed to decode identity private key: {e}")))?;
    let identity_key_pair = IdentityKeyPair::new(identity_key, private_key);

    let signed_prekey = SignedPreKeyRecord::deserialize(signed_prekey_record_bytes)
        .map_err(|e| KeychatError::Signal(format!("failed to deserialize signed prekey: {e}")))?;
    let prekey = PreKeyRecord::deserialize(prekey_record_bytes)
        .map_err(|e| KeychatError::Signal(format!("failed to deserialize prekey: {e}")))?;
    let kyber_prekey = KyberPreKeyRecord::deserialize(kyber_prekey_record_bytes)
        .map_err(|e| KeychatError::Signal(format!("failed to deserialize kyber prekey: {e}")))?;

    Ok(SignalPreKeyMaterial {
        identity_key_pair,
        registration_id,
        signed_prekey_id: SignedPreKeyId::from(signed_prekey_id_val),
        signed_prekey,
        prekey_id: PreKeyId::from(prekey_id_val),
        prekey,
        kyber_prekey_id: KyberPreKeyId::from(kyber_prekey_id_val),
        kyber_prekey,
    })
}

/// Serialize `SignalPreKeyMaterial` fields into raw bytes for storage.
///
/// Returns (identity_public, identity_private, registration_id,
///          signed_prekey_id, signed_prekey_record,
///          prekey_id, prekey_record,
///          kyber_prekey_id, kyber_prekey_record).
#[allow(clippy::type_complexity)]
pub fn serialize_prekey_material(
    keys: &SignalPreKeyMaterial,
) -> Result<(
    Vec<u8>,
    Vec<u8>,
    u32,
    u32,
    Vec<u8>,
    u32,
    Vec<u8>,
    u32,
    Vec<u8>,
)> {
    Ok((
        keys.identity_key_pair.identity_key().serialize().to_vec(),
        keys.identity_key_pair.private_key().serialize().to_vec(),
        keys.registration_id,
        u32::from(keys.signed_prekey_id),
        keys.signed_prekey
            .serialize()
            .map_err(|e| KeychatError::Signal(format!("failed to serialize signed prekey: {e}")))?,
        u32::from(keys.prekey_id),
        keys.prekey
            .serialize()
            .map_err(|e| KeychatError::Signal(format!("failed to serialize prekey: {e}")))?,
        u32::from(keys.kyber_prekey_id),
        keys.kyber_prekey
            .serialize()
            .map_err(|e| KeychatError::Signal(format!("failed to serialize kyber prekey: {e}")))?,
    ))
}

/// Helper: create DeviceId from u32 (must be 1..=127).
pub(crate) fn make_device_id(id: u32) -> DeviceId {
    DeviceId::new(id as u8).expect("device ID must be 1..=127")
}

/// A Signal Protocol participant with session management.
#[derive(Clone)]
pub struct SignalParticipant {
    address: ProtocolAddress,
    store: SignalProtocolStoreBundle,
    /// Pre-key material. Present during handshake (new sessions), absent after restore
    /// (established sessions don't need prekeys — session state is in signal_sessions).
    keys: Option<SignalPreKeyMaterial>,
    /// Identity key pair + registration_id, always available (needed for encrypt/decrypt).
    identity_key_pair: IdentityKeyPair,
    registration_id: u32,
    tracked_peers: BTreeMap<String, ProtocolAddress>,
}

impl std::fmt::Debug for SignalParticipant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalParticipant")
            .field("address", &self.address.name())
            .field("identity", &self.identity_public_key_hex())
            .finish_non_exhaustive()
    }
}

impl SignalParticipant {
    pub fn new(name: impl Into<String>, device_id_val: u32) -> Result<Self> {
        let keys = generate_prekey_material()?;
        let name = name.into();
        tracing::info!(
            "signal session created (in-memory): name={}",
            &name[..16.min(name.len())]
        );
        Self::from_prekey_material(name, device_id_val, keys)
    }

    pub fn from_prekey_material(
        name: String,
        device_id_val: u32,
        keys: SignalPreKeyMaterial,
    ) -> Result<Self> {
        let mut store =
            SignalProtocolStoreBundle::new(keys.identity_key_pair, keys.registration_id);

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
            store
                .kyber_pre_key_store
                .save_kyber_pre_key(keys.kyber_prekey_id, &keys.kyber_prekey)
                .await
                .map_err(KeychatError::from)?;
            Ok::<(), KeychatError>(())
        })?;

        let identity_key_pair = keys.identity_key_pair;
        let registration_id = keys.registration_id;
        Ok(Self {
            address: ProtocolAddress::new(name, make_device_id(device_id_val)),
            store,
            keys: Some(keys),
            identity_key_pair,
            registration_id,
            tracked_peers: BTreeMap::new(),
        })
    }

    /// Create a persistent participant backed by SecureStorage (SQLCipher).
    ///
    /// Session state, pre-keys, and identity keys are stored in the database
    /// and survive restarts.
    pub fn persistent(
        name: String,
        device_id_val: u32,
        keys: SignalPreKeyMaterial,
        storage: Arc<Mutex<SecureStorage>>,
    ) -> Result<Self> {
        let mut store = SignalProtocolStoreBundle::persistent(
            storage,
            keys.identity_key_pair,
            keys.registration_id,
        );

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
            store
                .kyber_pre_key_store
                .save_kyber_pre_key(keys.kyber_prekey_id, &keys.kyber_prekey)
                .await
                .map_err(KeychatError::from)?;
            Ok::<(), KeychatError>(())
        })?;

        tracing::info!(
            "signal session created (persistent): name={}",
            &name[..16.min(name.len())]
        );
        let identity_key_pair = keys.identity_key_pair;
        let registration_id = keys.registration_id;
        Ok(Self {
            address: ProtocolAddress::new(name, make_device_id(device_id_val)),
            store,
            keys: Some(keys),
            identity_key_pair,
            registration_id,
            tracked_peers: BTreeMap::new(),
        })
    }

    /// Restore a persistent participant from SQLCipher without prekey material.
    ///
    /// Used on restart for established sessions. Session state (ratchet keys, chain keys)
    /// is loaded on demand from `signal_sessions` by `PersistentSessionStore::load_session()`.
    /// No prekey injection needed — prekeys are only used during the initial handshake.
    pub fn restore_persistent(
        name: String,
        device_id_val: u32,
        identity_key_pair: IdentityKeyPair,
        registration_id: u32,
        storage: Arc<Mutex<SecureStorage>>,
    ) -> Result<Self> {
        let store = SignalProtocolStoreBundle::persistent(
            storage,
            identity_key_pair,
            registration_id,
        );

        tracing::info!(
            "signal session restored (persistent): name={}",
            &name[..16.min(name.len())]
        );
        Ok(Self {
            address: ProtocolAddress::new(name, make_device_id(device_id_val)),
            store,
            keys: None,
            identity_key_pair,
            registration_id,
            tracked_peers: BTreeMap::new(),
        })
    }

    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    /// Access to pre-key material for serialization/persistence.
    /// Returns None for restored sessions (prekeys are consumed after handshake).
    pub fn keys(&self) -> Option<&SignalPreKeyMaterial> {
        self.keys.as_ref()
    }

    pub fn prekey_bundle(&self) -> Result<PreKeyBundle> {
        self.keys
            .as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material (restored session)".into()))?
            .build_prekey_bundle(self.address.device_id())
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
            &mut ::rand::rng(),
        ))?;
        self.track_peer(remote);
        tracing::info!(
            "processed prekey bundle for remote={}",
            &remote.name()[..16.min(remote.name().len())]
        );
        Ok(())
    }

    pub fn encrypt_bytes(&mut self, remote: &ProtocolAddress, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encrypt(remote, plaintext)?.bytes)
    }

    pub fn encrypt(
        &mut self,
        remote: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<SignalCiphertext> {
        // Snapshot session state BEFORE encrypt so store_session can detect changes
        self.store.session_store.snapshot_session(remote);

        let message = block_on(message_encrypt(
            plaintext,
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut ::rand::rng(),
        ))
        .map_err(|e| {
            tracing::error!(
                "encrypt failed for {}: {e}",
                &remote.name()[..16.min(remote.name().len())]
            );
            e
        })?;

        let ciphertext_bytes = message.serialize().to_vec();

        // Extract ratchet info from my_receiver_addresses (set by store_session)
        let sender_address = self
            .store
            .session_store
            .my_receiver_addresses
            .lock()
            .unwrap()
            .get(remote.name())
            .cloned();

        let message_key_hash = compute_message_hash(&ciphertext_bytes);

        self.track_peer(remote);
        Ok(SignalCiphertext {
            bytes: ciphertext_bytes,
            sender_address,
            message_key_hash,
            prior_alice_addrs: None,
        })
    }

    pub fn decrypt_bytes(
        &mut self,
        remote: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(self.decrypt(remote, ciphertext)?.plaintext)
    }

    pub fn decrypt(
        &mut self,
        remote: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<SignalDecryptResult> {
        // Snapshot session state BEFORE decrypt so store_session can detect ratchet steps
        self.store.session_store.snapshot_session(remote);

        let message_key_hash = compute_message_hash(ciphertext);

        if let Ok(prekey) = PreKeySignalMessage::try_from(ciphertext) {
            tracing::info!(
                "decrypting prekey message from {}",
                &remote.name()[..16.min(remote.name().len())]
            );
            let plaintext = block_on(message_decrypt_prekey(
                &prekey,
                remote,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut self.store.pre_key_store,
                &self.store.signed_pre_key_store,
                &mut self.store.kyber_pre_key_store,
                &mut ::rand::rng(),
            ))
            .map_err(|e| {
                tracing::error!(
                    "decrypt (prekey) failed for {}: {e}",
                    &remote.name()[..16.min(remote.name().len())]
                );
                e
            })?;

            self.track_peer(remote);
            let alice_addrs = self.store.session_store.take_alice_addrs(remote.name());

            // On first PreKey decrypt, bob_addresses is empty because there's
            // no "old" snapshot to compare against. But the DH ratchet DID step:
            // the initial sender chain (signed pre-key) was replaced. We can
            // manually compute bob_address using signed_pre_key_private + their_public.
            let mut bob_derived_address = self.derive_bob_address(remote)?;
            if bob_derived_address.is_none() {
                bob_derived_address = self.derive_bob_address_from_prekey(remote)?;
            }

            return Ok(SignalDecryptResult {
                plaintext,
                message_key_hash,
                alice_addrs,
                bob_derived_address,
            });
        }

        if let Ok(signal) = SignalMessage::try_from(ciphertext) {
            let plaintext = block_on(message_decrypt_signal(
                &signal,
                remote,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut ::rand::rng(),
            ))
            .map_err(|e| {
                tracing::error!(
                    "decrypt (signal) failed for {}: {e}",
                    &remote.name()[..16.min(remote.name().len())]
                );
                e
            })?;

            self.track_peer(remote);
            let alice_addrs = self.store.session_store.take_alice_addrs(remote.name());

            return Ok(SignalDecryptResult {
                plaintext,
                message_key_hash,
                alice_addrs,
                bob_derived_address: self.derive_bob_address(remote)?,
            });
        }

        Err(KeychatError::Signal("invalid ciphertext format".into()))
    }

    pub fn is_prekey_message(ciphertext: &[u8]) -> bool {
        PreKeySignalMessage::try_from(ciphertext).is_ok()
    }

    pub fn parse_ciphertext(ciphertext: &[u8]) -> Result<CiphertextMessage> {
        if let Ok(prekey) = PreKeySignalMessage::try_from(ciphertext) {
            return Ok(CiphertextMessage::PreKeySignalMessage(prekey));
        }
        if let Ok(signal) = SignalMessage::try_from(ciphertext) {
            return Ok(CiphertextMessage::SignalMessage(signal));
        }
        Err(KeychatError::Signal("invalid ciphertext format".into()))
    }

    pub fn extract_prekey_sender_identity(ciphertext: &[u8]) -> Option<String> {
        PreKeySignalMessage::try_from(ciphertext)
            .ok()
            .map(|msg| hex::encode(msg.identity_key().serialize()))
    }

    pub fn identity_public_key_hex(&self) -> String {
        hex::encode(self.identity_key_pair.identity_key().serialize())
    }

    /// Move a session record from one ProtocolAddress to another.
    /// Used after decrypting a FriendApprove PreKeySignalMessage:
    /// the decrypt used the local identity key as remote_address (wrong),
    /// but the session needs to be under the peer's identity key (correct).
    pub fn relocate_session(&mut self, from: &ProtocolAddress, to: &ProtocolAddress) -> Result<()> {
        self.store
            .session_store
            .relocate_session(from, to)
            .map_err(|e| KeychatError::Signal(format!("relocate session: {e}")))
    }

    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    pub fn signed_prekey_id(&self) -> u32 {
        self.keys.as_ref().map(|k| u32::from(k.signed_prekey_id)).unwrap_or(0)
    }

    pub fn signed_prekey_public_hex(&self) -> Result<String> {
        let keys = self.keys.as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material".into()))?;
        Ok(hex::encode(keys.signed_prekey.public_key()?.serialize()))
    }

    pub fn signed_prekey_signature_hex(&self) -> Result<String> {
        let keys = self.keys.as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material".into()))?;
        Ok(hex::encode(keys.signed_prekey.signature()?))
    }

    pub fn prekey_id(&self) -> u32 {
        self.keys.as_ref().map(|k| u32::from(k.prekey_id)).unwrap_or(0)
    }

    pub fn prekey_public_hex(&self) -> Result<String> {
        let keys = self.keys.as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material".into()))?;
        Ok(hex::encode(keys.prekey.public_key()?.serialize()))
    }

    pub fn kyber_prekey_id(&self) -> u32 {
        self.keys.as_ref().map(|k| u32::from(k.kyber_prekey_id)).unwrap_or(0)
    }

    pub fn kyber_prekey_public_hex(&self) -> Result<String> {
        let keys = self.keys.as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material".into()))?;
        Ok(hex::encode(keys.kyber_prekey.public_key()?.serialize()))
    }

    pub fn kyber_prekey_signature_hex(&self) -> Result<String> {
        let keys = self.keys.as_ref()
            .ok_or_else(|| KeychatError::Signal("no prekey material".into()))?;
        Ok(hex::encode(keys.kyber_prekey.signature()?))
    }

    pub fn bob_addresses(&self) -> BTreeMap<String, String> {
        self.store
            .session_store
            .bob_addresses
            .lock()
            .unwrap()
            .clone()
    }

    fn track_peer(&mut self, remote: &ProtocolAddress) {
        self.tracked_peers
            .insert(remote.name().to_owned(), remote.clone());
    }

    /// Derive bob_address for the first PreKey decrypt using the signed pre-key
    /// as the "old" sender chain key.
    ///
    /// During PreKey decrypt, initialize_bob_session sets sender chain = signed pre-key,
    /// then get_or_create_chain_key does a DH ratchet step replacing it. The old sender
    /// private key (signed pre-key) + their ephemeral public = bob_address.
    fn derive_bob_address_from_prekey(&self, remote: &ProtocolAddress) -> Result<Option<String>> {
        // Get their_public from my_receiver_addresses ("{new_sender_priv}-{their_pub}")
        let receiver_addr = self
            .store
            .session_store
            .my_receiver_addresses
            .lock()
            .unwrap()
            .get(remote.name())
            .cloned();

        let their_pub = match receiver_addr {
            Some(ref addr) => match addr.split_once('-') {
                Some((_, pub_hex)) => pub_hex.to_owned(),
                None => return Ok(None),
            },
            None => return Ok(None),
        };

        // Get signed pre-key private key (was the initial sender chain)
        let keys = match self.keys.as_ref() {
            Some(k) => k,
            None => return Ok(None), // Restored session: no prekey material available
        };
        let mut signed_priv = hex::encode(
            keys.signed_prekey
                .private_key()
                .map_err(|e| KeychatError::Signal(format!("signed prekey private: {e}")))?
                .serialize(),
        );

        let mut seed = format!("{}-{}", signed_priv, their_pub);
        let result = derive_nostr_address_from_ratchet(&seed).map(Some);
        // Zeroize temporary key material (C-SEC2)
        signed_priv.zeroize();
        seed.zeroize();
        result
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
            Some(ref address) if address.starts_with("05") && address.len() == 66 => Ok(None),
            Some(address) => derive_nostr_address_from_ratchet(&address).map(Some),
            None => Ok(None),
        }
    }
}

/// Compute a deterministic hash from message bytes for deduplication.
fn compute_message_hash(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Derive a Nostr secp256k1 address from a Signal ratchet key pair (spec section 9.1).
///
/// Input format: `"{private_hex}-{public_hex}"`
pub fn derive_nostr_address_from_ratchet(seed_key: &str) -> Result<String> {
    use libsignal_protocol::{PrivateKey, PublicKey};
    use sha2::Digest;

    let (private_hex, public_hex) = seed_key.split_once('-').ok_or_else(|| {
        KeychatError::Signal("expected private-public format for ratchet key".into())
    })?;

    let private_bytes = hex::decode(private_hex)?;
    let public_bytes = hex::decode(public_hex)?;
    let alice_private = PrivateKey::deserialize(&private_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid ratchet private key: {e}")))?;
    let bob_public = PublicKey::deserialize(&public_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid ratchet public key: {e}")))?;

    let agreement = alice_private
        .calculate_agreement(&bob_public)
        .map_err(|e| KeychatError::Signal(format!("ECDH failed: {e}")))?;

    let mut secrets = Vec::with_capacity(64);
    secrets.extend_from_slice(&[0xFFu8; 32]);
    secrets.extend_from_slice(&agreement);

    let secret_hash = sha2::Sha256::digest(&secrets);
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&secret_hash[..32])?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let x_public_key = public_key.x_only_public_key().0.serialize();

    Ok(hex::encode(x_public_key))
}

fn timestamp_now() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Timestamp::from_epoch_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_creation() {
        let p = SignalParticipant::new("alice", 1).unwrap();
        assert_eq!(p.address().name(), "alice");
        assert_eq!(u32::from(p.address().device_id()), 1);
        assert!(!p.identity_public_key_hex().is_empty());
    }

    #[test]
    fn session_establishment_and_encryption() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let plaintext = b"Hello, Bob!";
        let ciphertext = alice.encrypt_bytes(&bob_addr, plaintext).unwrap();
        assert!(SignalParticipant::is_prekey_message(&ciphertext));

        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), make_device_id(1));
        let decrypted = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bidirectional_messaging() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), make_device_id(1));

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct1 = alice.encrypt_bytes(&bob_addr, b"Hello Bob!").unwrap();
        assert!(SignalParticipant::is_prekey_message(&ct1));
        let pt1 = bob.decrypt_bytes(&alice_addr, &ct1).unwrap();
        assert_eq!(pt1, b"Hello Bob!");

        let ct2 = bob.encrypt_bytes(&alice_addr, b"Hi Alice!").unwrap();
        assert!(!SignalParticipant::is_prekey_message(&ct2));
        let pt2 = alice.decrypt_bytes(&bob_addr, &ct2).unwrap();
        assert_eq!(pt2, b"Hi Alice!");

        let ct3 = alice.encrypt_bytes(&bob_addr, b"How are you?").unwrap();
        let pt3 = bob.decrypt_bytes(&alice_addr, &ct3).unwrap();
        assert_eq!(pt3, b"How are you?");
    }

    #[test]
    fn wrong_receiver_cannot_decrypt() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let bob = SignalParticipant::new("bob", 1).unwrap();
        let mut charlie = SignalParticipant::new("charlie", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ciphertext = alice.encrypt_bytes(&bob_addr, b"Secret message").unwrap();
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), make_device_id(1));
        let result = charlie.decrypt_bytes(&alice_addr, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn prekey_message_detection() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), make_device_id(1));

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct1 = alice.encrypt_bytes(&bob_addr, b"first").unwrap();
        assert!(SignalParticipant::is_prekey_message(&ct1));

        bob.decrypt_bytes(&alice_addr, &ct1).unwrap();
        let ct2 = bob.encrypt_bytes(&alice_addr, b"reply").unwrap();
        assert!(!SignalParticipant::is_prekey_message(&ct2));
    }

    #[test]
    fn extract_prekey_sender_identity_test() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct = alice.encrypt_bytes(&bob_addr, b"hello").unwrap();
        let sender_id = SignalParticipant::extract_prekey_sender_identity(&ct);
        assert!(sender_id.is_some());
        assert_eq!(sender_id.unwrap(), alice.identity_public_key_hex());
    }

    #[test]
    fn prekey_decrypt_produces_bob_derived_address() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), make_device_id(1));
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), make_device_id(1));

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct = alice.encrypt_bytes(&bob_addr, b"Hello Bob!").unwrap();
        assert!(SignalParticipant::is_prekey_message(&ct));

        // Bob decrypts the PreKey message — should produce bob_derived_address
        let result = bob.decrypt(&alice_addr, &ct).unwrap();
        assert_eq!(result.plaintext, b"Hello Bob!");
        assert!(
            result.bob_derived_address.is_some(),
            "PreKey decrypt should produce bob_derived_address after ratchet step"
        );
    }
}
