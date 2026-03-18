//! Persistent Signal Protocol stores backed by `SecureStorage` (SQLCipher).
//!
//! Each struct wraps `Arc<Mutex<SecureStorage>>` and implements the corresponding
//! libsignal async trait. Backend enums allow `SignalProtocolStoreBundle` to
//! dispatch to either in-memory or persistent stores without generics.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use libsignal_protocol::{
    GenericSignedPreKey, IdentityKey, IdentityKeyPair, InMemIdentityKeyStore,
    InMemKyberPreKeyStore, InMemPreKeyStore, InMemSessionStore, InMemSignedPreKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, ProtocolAddress, PublicKey,
    SessionRecord, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
};

use crate::storage::SecureStorage;

type Result<T> = std::result::Result<T, SignalProtocolError>;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn to_signal_err(e: crate::error::KeychatError) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(e.to_string())
}

// ─── PersistentSessionStore ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct PersistentSessionStore {
    storage: Arc<Mutex<SecureStorage>>,
}

impl PersistentSessionStore {
    pub fn new(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SessionStore for PersistentSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>> {
        let db = self.storage.lock().unwrap();
        let bytes = db
            .load_session(address.name(), u32::from(address.device_id()))
            .map_err(to_signal_err)?;
        match bytes {
            None => Ok(None),
            Some(b) => Ok(Some(SessionRecord::deserialize(&b)?)),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        let bytes = record.serialize()?;
        let db = self.storage.lock().unwrap();
        db.save_session(address.name(), u32::from(address.device_id()), &bytes)
            .map_err(to_signal_err)?;
        Ok(())
    }
}

// ─── PersistentPreKeyStore ───────────────────────────────────────────────────

#[derive(Clone)]
pub struct PersistentPreKeyStore {
    storage: Arc<Mutex<SecureStorage>>,
}

impl PersistentPreKeyStore {
    pub fn new(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::PreKeyStore for PersistentPreKeyStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> Result<PreKeyRecord> {
        let db = self.storage.lock().unwrap();
        let bytes = db
            .load_pre_key(u32::from(prekey_id))
            .map_err(to_signal_err)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<()> {
        let bytes = record.serialize()?;
        let db = self.storage.lock().unwrap();
        db.save_pre_key(u32::from(prekey_id), &bytes)
            .map_err(to_signal_err)?;
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> Result<()> {
        let db = self.storage.lock().unwrap();
        db.remove_pre_key(u32::from(prekey_id))
            .map_err(to_signal_err)?;
        Ok(())
    }
}

// ─── PersistentSignedPreKeyStore ─────────────────────────────────────────────

#[derive(Clone)]
pub struct PersistentSignedPreKeyStore {
    storage: Arc<Mutex<SecureStorage>>,
}

impl PersistentSignedPreKeyStore {
    pub fn new(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SignedPreKeyStore for PersistentSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        let db = self.storage.lock().unwrap();
        let bytes = db
            .load_signed_pre_key(u32::from(signed_prekey_id))
            .map_err(to_signal_err)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        let bytes = record.serialize()?;
        let db = self.storage.lock().unwrap();
        db.save_signed_pre_key(u32::from(signed_prekey_id), &bytes)
            .map_err(to_signal_err)?;
        Ok(())
    }
}

// ─── PersistentKyberPreKeyStore ──────────────────────────────────────────────

#[derive(Clone)]
pub struct PersistentKyberPreKeyStore {
    storage: Arc<Mutex<SecureStorage>>,
}

impl PersistentKyberPreKeyStore {
    pub fn new(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::KyberPreKeyStore for PersistentKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord> {
        let db = self.storage.lock().unwrap();
        let bytes = db
            .load_kyber_pre_key(u32::from(kyber_prekey_id))
            .map_err(to_signal_err)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        let bytes = record.serialize()?;
        let db = self.storage.lock().unwrap();
        db.save_kyber_pre_key(u32::from(kyber_prekey_id), &bytes)
            .map_err(to_signal_err)?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<()> {
        // One-time keys: remove after use.
        let db = self.storage.lock().unwrap();
        db.remove_kyber_pre_key(u32::from(kyber_prekey_id))
            .map_err(to_signal_err)?;
        Ok(())
    }
}

// ─── PersistentIdentityKeyStore ──────────────────────────────────────────────

#[derive(Clone)]
pub struct PersistentIdentityKeyStore {
    storage: Arc<Mutex<SecureStorage>>,
    key_pair: IdentityKeyPair,
    registration_id: u32,
}

impl PersistentIdentityKeyStore {
    pub fn new(
        storage: Arc<Mutex<SecureStorage>>,
        key_pair: IdentityKeyPair,
        registration_id: u32,
    ) -> Self {
        Self {
            storage,
            key_pair,
            registration_id,
        }
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::IdentityKeyStore for PersistentIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<libsignal_protocol::IdentityChange> {
        use libsignal_protocol::IdentityChange;

        let db = self.storage.lock().unwrap();
        let existing = db
            .load_peer_identity(address.name())
            .map_err(to_signal_err)?;

        let result = match existing {
            None => IdentityChange::NewOrUnchanged,
            Some(ref bytes) => {
                let existing_key = IdentityKey::decode(bytes)?;
                if &existing_key == identity {
                    IdentityChange::NewOrUnchanged
                } else {
                    IdentityChange::ReplacedExisting
                }
            }
        };

        db.save_peer_identity(address.name(), &identity.serialize())
            .map_err(to_signal_err)?;
        Ok(result)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: libsignal_protocol::Direction,
    ) -> Result<bool> {
        let db = self.storage.lock().unwrap();
        let existing = db
            .load_peer_identity(address.name())
            .map_err(to_signal_err)?;
        match existing {
            None => Ok(true), // TOFU: trust on first use
            Some(ref bytes) => {
                let existing_key = IdentityKey::decode(bytes)?;
                Ok(&existing_key == identity)
            }
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>> {
        let db = self.storage.lock().unwrap();
        let bytes = db
            .load_peer_identity(address.name())
            .map_err(to_signal_err)?;
        match bytes {
            None => Ok(None),
            Some(b) => Ok(Some(IdentityKey::decode(&b)?)),
        }
    }
}

// ─── Backend Enums ───────────────────────────────────────────────────────────

/// Session store backend: in-memory or persistent.
#[derive(Clone)]
pub enum SessionStoreBackend {
    InMemory(InMemSessionStore),
    Persistent(PersistentSessionStore),
}

#[async_trait(?Send)]
impl libsignal_protocol::SessionStore for SessionStoreBackend {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>> {
        match self {
            Self::InMemory(s) => s.load_session(address).await,
            Self::Persistent(s) => s.load_session(address).await,
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => s.store_session(address, record).await,
            Self::Persistent(s) => s.store_session(address, record).await,
        }
    }
}

/// Pre-key store backend: in-memory or persistent.
#[derive(Clone)]
pub enum PreKeyStoreBackend {
    InMemory(InMemPreKeyStore),
    Persistent(PersistentPreKeyStore),
}

#[async_trait(?Send)]
impl libsignal_protocol::PreKeyStore for PreKeyStoreBackend {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> Result<PreKeyRecord> {
        match self {
            Self::InMemory(s) => s.get_pre_key(prekey_id).await,
            Self::Persistent(s) => s.get_pre_key(prekey_id).await,
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => s.save_pre_key(prekey_id, record).await,
            Self::Persistent(s) => s.save_pre_key(prekey_id, record).await,
        }
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => s.remove_pre_key(prekey_id).await,
            Self::Persistent(s) => s.remove_pre_key(prekey_id).await,
        }
    }
}

/// Signed pre-key store backend: in-memory or persistent.
#[derive(Clone)]
pub enum SignedPreKeyStoreBackend {
    InMemory(InMemSignedPreKeyStore),
    Persistent(PersistentSignedPreKeyStore),
}

#[async_trait(?Send)]
impl libsignal_protocol::SignedPreKeyStore for SignedPreKeyStoreBackend {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        match self {
            Self::InMemory(s) => s.get_signed_pre_key(signed_prekey_id).await,
            Self::Persistent(s) => s.get_signed_pre_key(signed_prekey_id).await,
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => s.save_signed_pre_key(signed_prekey_id, record).await,
            Self::Persistent(s) => s.save_signed_pre_key(signed_prekey_id, record).await,
        }
    }
}

/// Kyber pre-key store backend: in-memory or persistent.
#[derive(Clone)]
pub enum KyberPreKeyStoreBackend {
    InMemory(InMemKyberPreKeyStore),
    Persistent(PersistentKyberPreKeyStore),
}

#[async_trait(?Send)]
impl libsignal_protocol::KyberPreKeyStore for KyberPreKeyStoreBackend {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord> {
        match self {
            Self::InMemory(s) => s.get_kyber_pre_key(kyber_prekey_id).await,
            Self::Persistent(s) => s.get_kyber_pre_key(kyber_prekey_id).await,
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => s.save_kyber_pre_key(kyber_prekey_id, record).await,
            Self::Persistent(s) => s.save_kyber_pre_key(kyber_prekey_id, record).await,
        }
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        match self {
            Self::InMemory(s) => {
                s.mark_kyber_pre_key_used(kyber_prekey_id, ec_prekey_id, base_key)
                    .await
            }
            Self::Persistent(s) => {
                s.mark_kyber_pre_key_used(kyber_prekey_id, ec_prekey_id, base_key)
                    .await
            }
        }
    }
}

/// Identity key store backend: in-memory or persistent.
#[derive(Clone)]
pub enum IdentityStoreBackend {
    InMemory(InMemIdentityKeyStore),
    Persistent(PersistentIdentityKeyStore),
}

#[async_trait(?Send)]
impl libsignal_protocol::IdentityKeyStore for IdentityStoreBackend {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        match self {
            Self::InMemory(s) => s.get_identity_key_pair().await,
            Self::Persistent(s) => s.get_identity_key_pair().await,
        }
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        match self {
            Self::InMemory(s) => s.get_local_registration_id().await,
            Self::Persistent(s) => s.get_local_registration_id().await,
        }
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<libsignal_protocol::IdentityChange> {
        match self {
            Self::InMemory(s) => s.save_identity(address, identity).await,
            Self::Persistent(s) => s.save_identity(address, identity).await,
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: libsignal_protocol::Direction,
    ) -> Result<bool> {
        match self {
            Self::InMemory(s) => s.is_trusted_identity(address, identity, direction).await,
            Self::Persistent(s) => s.is_trusted_identity(address, identity, direction).await,
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>> {
        match self {
            Self::InMemory(s) => s.get_identity(address).await,
            Self::Persistent(s) => s.get_identity(address).await,
        }
    }
}
