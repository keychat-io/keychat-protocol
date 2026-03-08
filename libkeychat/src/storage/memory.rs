use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::storage::{DataStore, StoredPeer, StoredSignalIdentity, StoredSignalSession};

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    sessions: BTreeMap<(String, u32), Vec<u8>>,
    prekeys: BTreeMap<String, Vec<u8>>,
    signed_prekeys: BTreeMap<String, Vec<u8>>,
    identities: BTreeMap<String, StoredSignalIdentity>,
    peers: BTreeMap<String, StoredPeer>,
    receiving_addresses: BTreeMap<String, String>,
    processed_events: BTreeSet<String>,
}

impl DataStore for MemoryStore {
    fn upsert_signal_session(&mut self, session: StoredSignalSession) -> Result<()> {
        self.sessions
            .insert((session.peer_id, session.device_id), session.record);
        Ok(())
    }

    fn load_signal_sessions(&self, peer_id: &str) -> Result<Vec<StoredSignalSession>> {
        Ok(self
            .sessions
            .iter()
            .filter(|((id, _), _)| id == peer_id)
            .map(|((id, device_id), record)| StoredSignalSession {
                peer_id: id.clone(),
                device_id: *device_id,
                record: record.clone(),
            })
            .collect())
    }

    fn upsert_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()> {
        self.prekeys.insert(key_id.to_owned(), record);
        Ok(())
    }

    fn load_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.prekeys.get(key_id).cloned())
    }

    fn upsert_signed_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()> {
        self.signed_prekeys.insert(key_id.to_owned(), record);
        Ok(())
    }

    fn load_signed_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.signed_prekeys.get(key_id).cloned())
    }

    fn upsert_identity_key(&mut self, identity: StoredSignalIdentity) -> Result<()> {
        self.identities.insert(identity.key_id.clone(), identity);
        Ok(())
    }

    fn load_identity_key(&self, key_id: &str) -> Result<Option<StoredSignalIdentity>> {
        Ok(self.identities.get(key_id).cloned())
    }

    fn upsert_peer(&mut self, peer: StoredPeer) -> Result<()> {
        self.peers.insert(peer.peer_id.clone(), peer);
        Ok(())
    }

    fn load_peer(&self, peer_id: &str) -> Result<Option<StoredPeer>> {
        Ok(self.peers.get(peer_id).cloned())
    }

    fn map_receiving_address(&mut self, address: &str, peer_id: &str) -> Result<()> {
        self.receiving_addresses
            .insert(address.to_owned(), peer_id.to_owned());
        Ok(())
    }

    fn resolve_receiving_address(&self, address: &str) -> Result<Option<String>> {
        Ok(self.receiving_addresses.get(address).cloned())
    }

    fn mark_processed_event(&mut self, event_id: &str) -> Result<()> {
        self.processed_events.insert(event_id.to_owned());
        Ok(())
    }

    fn has_processed_event(&self, event_id: &str) -> Result<bool> {
        Ok(self.processed_events.contains(event_id))
    }
}
