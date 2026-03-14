//! Signal Protocol session management.
//!
//! Wraps `libsignal-protocol` into a higher-level `SignalParticipant` that manages
//! key material, session state, and encrypt/decrypt operations.

use std::collections::BTreeMap;
use std::time::SystemTime;

use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, DeviceId, GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::rngs::OsRng;
use rand::Rng;

use crate::error::{KeychatError, Result};
use crate::signal_store::SignalProtocolStoreBundle;

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
            *self.identity_key_pair.identity_key(),
        )?;
        // Attach Kyber prekey for PQXDH
        Ok(bundle.with_kyber_pre_key(
            self.kyber_prekey_id,
            self.kyber_prekey.public_key()?,
            self.kyber_prekey.signature()?,
        ))
    }
}

/// Generate fresh Signal pre-key material using libsignal-protocol native types.
///
/// Includes Kyber1024 prekey for PQXDH key agreement.
pub fn generate_prekey_material() -> Result<SignalPreKeyMaterial> {
    let mut rng = OsRng;
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let registration_id = rand::thread_rng().gen_range(1..=u32::MAX);

    let signed_prekey_id = SignedPreKeyId::from(1);
    let signed_prekey_key_pair = KeyPair::generate(&mut rng);
    let signed_prekey_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_prekey_key_pair.public_key.serialize(), &mut rng)?;
    let signed_prekey = <SignedPreKeyRecord as GenericSignedPreKey>::new(
        signed_prekey_id,
        timestamp_now(),
        &signed_prekey_key_pair,
        &signed_prekey_signature,
    );

    let prekey_id = PreKeyId::from(1);
    let prekey_key_pair = KeyPair::generate(&mut rng);
    let prekey = PreKeyRecord::new(prekey_id, &prekey_key_pair);

    // Generate Kyber1024 prekey for PQXDH
    let kyber_prekey_id = KyberPreKeyId::from(1);
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

/// A Signal Protocol participant with session management.
#[derive(Clone)]
pub struct SignalParticipant {
    address: ProtocolAddress,
    store: SignalProtocolStoreBundle,
    keys: SignalPreKeyMaterial,
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
    pub fn new(name: impl Into<String>, device_id: u32) -> Result<Self> {
        let keys = generate_prekey_material()?;
        Self::from_prekey_material(name.into(), device_id, keys)
    }

    pub fn from_prekey_material(
        name: String,
        device_id: u32,
        keys: SignalPreKeyMaterial,
    ) -> Result<Self> {
        let mut store = SignalProtocolStoreBundle::new(keys.identity_key_pair, keys.registration_id);

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

        Ok(Self {
            address: ProtocolAddress::new(name, DeviceId::from(device_id)),
            store,
            keys,
            tracked_peers: BTreeMap::new(),
        })
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

    pub fn encrypt_bytes(&mut self, remote: &ProtocolAddress, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encrypt(remote, plaintext)?.bytes)
    }

    pub fn encrypt(
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

    pub fn decrypt_bytes(&mut self, remote: &ProtocolAddress, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.decrypt(remote, ciphertext)?.plaintext)
    }

    pub fn decrypt(
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
        hex::encode(self.keys.identity_key_pair.identity_key().serialize())
    }

    pub fn registration_id(&self) -> u32 {
        self.keys.registration_id
    }

    pub fn signed_prekey_id(&self) -> u32 {
        u32::from(self.keys.signed_prekey_id)
    }

    pub fn signed_prekey_public_hex(&self) -> Result<String> {
        Ok(hex::encode(self.keys.signed_prekey.public_key()?.serialize()))
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

    pub fn kyber_prekey_id(&self) -> u32 {
        u32::from(self.keys.kyber_prekey_id)
    }

    pub fn kyber_prekey_public_hex(&self) -> Result<String> {
        Ok(hex::encode(self.keys.kyber_prekey.public_key()?.serialize()))
    }

    pub fn kyber_prekey_signature_hex(&self) -> Result<String> {
        Ok(hex::encode(self.keys.kyber_prekey.signature()?))
    }

    pub fn bob_addresses(&self) -> BTreeMap<String, String> {
        self.store.session_store.bob_addresses.lock().unwrap().clone()
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
            Some(ref address) if address.starts_with("05") && address.len() == 66 => Ok(None),
            Some(address) => derive_nostr_address_from_ratchet(&address).map(Some),
            None => Ok(None),
        }
    }
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

fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let plaintext = b"Hello, Bob!";
        let ciphertext = alice.encrypt_bytes(&bob_addr, plaintext).unwrap();
        assert!(SignalParticipant::is_prekey_message(&ciphertext));

        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));
        let decrypted = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bidirectional_messaging() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));

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
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ciphertext = alice.encrypt_bytes(&bob_addr, b"Secret message").unwrap();
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));
        let result = charlie.decrypt_bytes(&alice_addr, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn prekey_message_detection() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        let alice_addr = ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::from(1u32));

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
        let bob_addr = ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::from(1u32));
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct = alice.encrypt_bytes(&bob_addr, b"hello").unwrap();
        let sender_id = SignalParticipant::extract_prekey_sender_identity(&ct);
        assert!(sender_id.is_some());
        assert_eq!(sender_id.unwrap(), alice.identity_public_key_hex());
    }
}
