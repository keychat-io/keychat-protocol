use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use libsignal_protocol::{
    InMemSessionStore, ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError,
};

#[derive(Clone, Default)]
pub struct CapturingSessionStore {
    inner: InMemSessionStore,
    pub bob_addresses: Arc<Mutex<BTreeMap<String, String>>>,
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

        // Capture my_receiver_address so encrypt_with_metadata can read it
        if let Some(value) = my_receiver_address.as_ref() {
            self.my_receiver_addresses
                .lock()
                .unwrap()
                .insert(address.name().to_owned(), value.clone());
        }

        // Return (3, None) so message_encrypt returns Some(my_receiver_address)
        // InMemSessionStore returns (0, None) which causes encrypt to discard it
        self.inner
            .store_session(
                address,
                record,
                my_receiver_address,
                to_receiver_address,
                sender_ratchet_key,
            )
            .await
            .map(|(_, alice_addrs)| (3, alice_addrs))
    }
}
