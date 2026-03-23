use std::collections::HashMap;
use std::sync::Arc;

use libkeychat::{
    ChatSession, FriendRequestState, FriendRequestReceived as LibFriendRequestReceived,
    Identity, SecureStorage, Transport,
};

use crate::error::KeychatUniError;
use crate::types::*;

pub(crate) struct ClientInner {
    pub identity: Option<Identity>,
    pub transport: Option<Transport>,
    pub storage: Arc<std::sync::Mutex<SecureStorage>>,
    pub sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    pub peer_nostr_to_signal: HashMap<String, String>,
    pub pending_outbound: HashMap<String, FriendRequestState>,
    pub pending_inbound: HashMap<String, LibFriendRequestReceived>,
    pub next_signal_device_id: u32,
    pub event_listener: Option<Box<dyn EventListener>>,
    pub event_loop_stop: Option<tokio::sync::watch::Sender<bool>>,
}

#[derive(uniffi::Object)]
pub struct KeychatClient {
    pub(crate) inner: tokio::sync::RwLock<ClientInner>,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
    pub(crate) db_path: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    #[uniffi::constructor]
    pub fn new(db_path: String, db_key: String) -> Result<Self, KeychatUniError> {
        let storage = SecureStorage::open(&db_path, &db_key)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;

        Ok(Self {
            inner: tokio::sync::RwLock::new(ClientInner {
                identity: None,
                transport: None,
                storage: Arc::new(std::sync::Mutex::new(storage)),
                sessions: HashMap::new(),
                peer_nostr_to_signal: HashMap::new(),
                pending_outbound: HashMap::new(),
                pending_inbound: HashMap::new(),
                next_signal_device_id: 1,
                event_listener: None,
                event_loop_stop: None,
            }),
            runtime: Arc::new(runtime),
            db_path,
        })
    }

    pub async fn create_identity(&self) -> Result<CreateIdentityResult, KeychatUniError> {
        let result = Identity::generate()?;
        let pubkey_hex = result.identity.pubkey_hex();
        let mnemonic = result.mnemonic.clone();

        let mut inner = self.inner.write().await;
        inner.identity = Some(result.identity);

        Ok(CreateIdentityResult { pubkey_hex, mnemonic })
    }

    pub async fn import_identity(&self, mnemonic: String) -> Result<String, KeychatUniError> {
        let identity = Identity::from_mnemonic_str(&mnemonic)?;
        let pubkey_hex = identity.pubkey_hex();

        let mut inner = self.inner.write().await;
        inner.identity = Some(identity);

        Ok(pubkey_hex)
    }

    pub async fn get_pubkey_hex(&self) -> Result<String, KeychatUniError> {
        let inner = self.inner.read().await;
        inner.identity.as_ref()
            .map(|id| id.pubkey_hex())
            .ok_or(KeychatUniError::NotInitialized { msg: "no identity set".into() })
    }
}
