//! In-memory Signal Protocol stores.
//!
//! Wraps `libsignal-protocol`'s built-in `InMem*` stores. The `CapturingSessionStore`
//! captures bob_address and my_receiver_address for Keychat's ratchet address rotation (§9).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use libsignal_protocol::{
    InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemRatchetKeyStore,
    InMemSessionStore, InMemSignedPreKeyStore, ProtocolAddress, SessionRecord, SessionStore,
    SignalProtocolError,
};

/// A session store wrapper that captures ratchet-derived address information.
#[derive(Clone, Default)]
pub struct CapturingSessionStore {
    inner: InMemSessionStore,
    /// Peer name → peer's current receiving address
    pub bob_addresses: Arc<Mutex<BTreeMap<String, String>>>,
    /// Peer name → our derived receiving address
    pub my_receiver_addresses: Arc<Mutex<BTreeMap<String, String>>>,
}

impl CapturingSessionStore {
    pub fn new() -> Self {
        Self {
            inner: InMemSessionStore::new(),
            bob_addresses: Arc::new(Mutex::new(BTreeMap::new())),
            my_receiver_addresses: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl SessionStore for CapturingSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> std::result::Result<Option<SessionRecord>, SignalProtocolError> {
        self.inner.load_session(address).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<String>,
        to_receiver_address: Option<String>,
        sender_ratchet_key: Option<String>,
    ) -> std::result::Result<(u32, Option<Vec<String>>), SignalProtocolError> {
        if let Some(value) = to_receiver_address.as_ref() {
            self.bob_addresses
                .lock()
                .unwrap()
                .insert(address.name().to_owned(), value.clone());
        }
        if let Some(value) = my_receiver_address.as_ref() {
            self.my_receiver_addresses
                .lock()
                .unwrap()
                .insert(address.name().to_owned(), value.clone());
        }
        self.inner
            .store_session(address, record, my_receiver_address, to_receiver_address, sender_ratchet_key)
            .await
            .map(|(_, alice_addrs)| (3, alice_addrs))
    }
}

/// Complete Signal Protocol store bundle for a single participant.
#[derive(Clone)]
pub struct SignalProtocolStoreBundle {
    pub session_store: CapturingSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub kyber_pre_key_store: InMemKyberPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub ratchet_key_store: InMemRatchetKeyStore,
}

impl SignalProtocolStoreBundle {
    pub fn new(
        identity_key_pair: libsignal_protocol::IdentityKeyPair,
        registration_id: u32,
    ) -> Self {
        Self {
            session_store: CapturingSessionStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            kyber_pre_key_store: InMemKyberPreKeyStore::new(),
            identity_store: InMemIdentityKeyStore::new(identity_key_pair, registration_id),
            ratchet_key_store: InMemRatchetKeyStore::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyPair;
    use rand::rngs::OsRng;

    #[test]
    fn store_bundle_creation() {
        let identity = IdentityKeyPair::generate(&mut OsRng);
        let bundle = SignalProtocolStoreBundle::new(identity, 42);
        assert!(bundle.session_store.bob_addresses.lock().unwrap().is_empty());
    }
}
