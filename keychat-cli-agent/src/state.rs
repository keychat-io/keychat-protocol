//! Shared application state.

use libkeychat::group::{GroupManager, SignalGroup};
use libkeychat::mls::MlsParticipant;
use libkeychat::storage::SecureStorage;
use libkeychat::{AddressManager, Identity, SignalParticipant};
use nostr::prelude::*;
use nostr_sdk::Client;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::config::Config;

/// Wrapper to make SecureStorage Send+Sync via Mutex.
/// rusqlite::Connection is safe to use from one thread at a time;
/// the Mutex guarantees exclusive access.
pub struct SendStorage(pub SecureStorage);
unsafe impl Send for SendStorage {}
unsafe impl Sync for SendStorage {}

/// Same wrapper for MlsParticipant (contains OpenMLS SQLite storage).
pub struct SendMls(pub MlsParticipant);
unsafe impl Send for SendMls {}
unsafe impl Sync for SendMls {}

impl std::ops::Deref for SendMls {
    type Target = MlsParticipant;
    fn deref(&self) -> &MlsParticipant { &self.0 }
}
impl std::ops::DerefMut for SendMls {
    fn deref_mut(&mut self) -> &mut MlsParticipant { &mut self.0 }
}

/// A connected 1:1 peer.
pub struct Peer {
    pub nostr_pubkey: String,
    pub signal_id: String,
    pub name: String,
    pub signal: SignalParticipant,
    pub address_manager: AddressManager,
}

/// Chat target — either a peer or a group.
#[derive(Debug, Clone)]
pub enum ChatTarget {
    Peer(String),        // nostr pubkey
    SignalGroup(String), // group_id
    MlsGroup(String),    // group_id
}

impl std::fmt::Display for ChatTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Peer(p) => write!(f, "{}...", &p[..8.min(p.len())]),
            Self::SignalGroup(g) => write!(f, "sg:{}...", &g[..8.min(g.len())]),
            Self::MlsGroup(g) => write!(f, "mls:{}...", &g[..8.min(g.len())]),
        }
    }
}

pub struct AppState {
    pub identity: Identity,
    pub keys: Keys,
    pub client: Client,
    pub storage: Mutex<SendStorage>,
    pub peers: Arc<RwLock<HashMap<String, Peer>>>,
    pub active_chat: Arc<RwLock<Option<ChatTarget>>>,
    pub relay_urls: Vec<String>,
    pub name: String,
    pub config: Config,
    pub data_dir: PathBuf,
    pub signal_groups: Arc<RwLock<GroupManager>>,
    pub mls: Arc<Mutex<Option<SendMls>>>,
    /// Pending outbound friend requests (we sent, waiting for acceptance).
    pub pending_outbound_frs: Arc<RwLock<HashMap<String, OutboundFriendRequest>>>,
    /// Pending inbound friend requests (need owner approval).
    pub pending_friend_requests: Arc<RwLock<Vec<PendingFriendRequest>>>,
    /// Owner's nostr pubkey. First peer to add us becomes owner.
    pub owner: Arc<RwLock<Option<String>>>,
}

/// Pending outbound friend request (we sent, waiting for acceptance).
pub struct OutboundFriendRequest {
    pub signal: SignalParticipant,
    pub first_inbox_pubkey: String,
    pub first_inbox_secret: String,
}

/// Pending inbound friend request (needs owner approval).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingFriendRequest {
    pub sender_npub: String,
    pub sender_name: String,
    pub signal_identity_key: String,
    pub first_inbox: String,
    /// Serialized KCFriendRequestPayload JSON for later acceptance.
    pub payload_json: String,
}

impl AppState {
    pub async fn new(
        identity: Identity,
        config: Config,
        relay_urls: &[String],
        data_dir: &Path,
        db_key: &str,
    ) -> anyhow::Result<Self> {
        let keys = identity.keys().clone();
        let client = Client::new(keys.clone());
        for url in relay_urls {
            client.add_relay(url.as_str()).await?;
        }
        client.connect().await;

        let db_path = data_dir.join("keychat.db");
        let storage = SecureStorage::open(db_path.to_str().unwrap(), db_key)?;

        // Load existing peers
        let mut peers = HashMap::new();
        for pm in storage.list_peers()? {
            let signal = SignalParticipant::new(&pm.signal_id, 1)?;
            let addr_mgr = AddressManager::new();
            peers.insert(pm.nostr_pubkey.clone(), Peer {
                nostr_pubkey: pm.nostr_pubkey,
                signal_id: pm.signal_id,
                name: pm.name,
                signal,
                address_manager: addr_mgr,
            });
        }

        let mls = MlsParticipant::new(identity.pubkey_hex());

        let owner = config.owner.clone();

        Ok(Self {
            identity,
            keys,
            client,
            storage: Mutex::new(SendStorage(storage)),
            peers: Arc::new(RwLock::new(peers)),
            active_chat: Arc::new(RwLock::new(None)),
            relay_urls: relay_urls.to_vec(),
            name: config.name.clone(),
            config,
            data_dir: data_dir.to_path_buf(),
            signal_groups: Arc::new(RwLock::new(GroupManager::new())),
            mls: Arc::new(Mutex::new(Some(SendMls(mls)))),
            pending_outbound_frs: Arc::new(RwLock::new(HashMap::new())),
            pending_friend_requests: Arc::new(RwLock::new(Vec::new())),
            owner: Arc::new(RwLock::new(owner)),
        })
    }

    pub fn npub(&self) -> String {
        self.identity.pubkey_hex()
    }

    pub fn db(&self) -> impl std::ops::Deref<Target = SecureStorage> + '_ {
        struct Guard<'a>(std::sync::MutexGuard<'a, SendStorage>);
        impl<'a> std::ops::Deref for Guard<'a> {
            type Target = SecureStorage;
            fn deref(&self) -> &SecureStorage { &self.0.0 }
        }
        Guard(self.storage.lock().unwrap())
    }
}
