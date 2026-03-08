pub mod memory;
pub mod sqlite;

use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPeer {
    pub peer_id: String,
    pub nostr_pubkey: String,
    pub signal_pubkey: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSignalSession {
    pub peer_id: String,
    pub device_id: u32,
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSignalIdentity {
    pub key_id: String,
    pub registration_id: u32,
    pub record: Vec<u8>,
}

pub trait DataStore {
    fn upsert_signal_session(&mut self, session: StoredSignalSession) -> Result<()>;
    fn load_signal_sessions(&self, peer_id: &str) -> Result<Vec<StoredSignalSession>>;
    fn upsert_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()>;
    fn load_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>>;
    fn upsert_signed_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()>;
    fn load_signed_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>>;
    fn upsert_identity_key(&mut self, identity: StoredSignalIdentity) -> Result<()>;
    fn load_identity_key(&self, key_id: &str) -> Result<Option<StoredSignalIdentity>>;
    fn upsert_peer(&mut self, peer: StoredPeer) -> Result<()>;
    fn load_peer(&self, peer_id: &str) -> Result<Option<StoredPeer>>;
    fn map_receiving_address(&mut self, address: &str, peer_id: &str) -> Result<()>;
    fn resolve_receiving_address(&self, address: &str) -> Result<Option<String>>;
    fn mark_processed_event(&mut self, event_id: &str) -> Result<()>;
    fn has_processed_event(&self, event_id: &str) -> Result<bool>;
}
