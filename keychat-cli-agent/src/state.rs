//! Shared application state.

use libkeychat::group::{GroupManager, SignalGroup};
use libkeychat::mls::MlsParticipant;
use libkeychat::storage::SecureStorage;
use libkeychat::{reconstruct_prekey_material, AddressManager, Identity, SignalParticipant};
use nostr::prelude::*;
use nostr_sdk::{Client, ClientBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::config::Config;

/// Wrapper to make SecureStorage Send+Sync.
/// rusqlite::Connection is Send but not Sync; Arc<Mutex<>> provides both.
pub struct SendStorage(pub Arc<Mutex<SecureStorage>>);
unsafe impl Send for SendStorage {}
unsafe impl Sync for SendStorage {}

/// Same wrapper for MlsParticipant (contains OpenMLS SQLite storage).
pub struct SendMls(pub MlsParticipant);
unsafe impl Send for SendMls {}
unsafe impl Sync for SendMls {}

impl std::ops::Deref for SendMls {
    type Target = MlsParticipant;
    fn deref(&self) -> &MlsParticipant {
        &self.0
    }
}
impl std::ops::DerefMut for SendMls {
    fn deref_mut(&mut self) -> &mut MlsParticipant {
        &mut self.0
    }
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
    pub storage: Arc<Mutex<SecureStorage>>,
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
    /// Ecash stamp manager for paid relay publishing.
    pub stamp_manager: Arc<libkeychat::StampManager>,
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
        let opts =
            nostr_sdk::Options::new().connection_timeout(Some(std::time::Duration::from_secs(10)));
        let client = ClientBuilder::new().signer(keys.clone()).opts(opts).build();
        for url in relay_urls {
            client.add_relay(url.as_str()).await?;
        }
        // Connect in background — don't block startup
        let connect_client = client.clone();
        tokio::spawn(async move { connect_client.connect().await });

        let db_path = data_dir.join("keychat.db");
        let storage = Arc::new(Mutex::new(SecureStorage::open(
            db_path.to_str().unwrap(),
            db_key,
        )?));

        // Load existing peers with persisted Signal key material + session state
        let mut peers = HashMap::new();
        {
            let store = storage.lock().unwrap();
            let peer_list = store.list_peers()?;
            let all_addresses: HashMap<String, _> = store
                .load_all_peer_addresses()
                .unwrap_or_default()
                .into_iter()
                .collect();
            drop(store);

            for pm in peer_list {
                // Load from DB then drop lock before persistent() which also locks
                let loaded = {
                    let store = storage.lock().unwrap();
                    store.load_signal_participant(&pm.signal_id)
                };
                let signal = match loaded {
                    Ok(Some((
                        device_id,
                        id_pub,
                        id_priv,
                        reg_id,
                        spk_id,
                        spk_rec,
                        pk_id,
                        pk_rec,
                        kpk_id,
                        kpk_rec,
                    ))) => {
                        match reconstruct_prekey_material(
                            &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id,
                            &kpk_rec,
                        ) {
                            Ok(keys) => {
                                match SignalParticipant::persistent(
                                    pm.signal_id.clone(),
                                    device_id,
                                    keys,
                                    storage.clone(),
                                ) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        eprintln!(
                                            "restore peer {}: create participant failed: {e}",
                                            &pm.signal_id[..16.min(pm.signal_id.len())]
                                        );
                                        SignalParticipant::new(&pm.signal_id, 1)?
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "restore peer {}: reconstruct keys failed: {e}",
                                    &pm.signal_id[..16.min(pm.signal_id.len())]
                                );
                                SignalParticipant::new(&pm.signal_id, 1)?
                            }
                        }
                    }
                    _ => SignalParticipant::new(&pm.signal_id, 1)?,
                };

                let addr_mgr = if let Some(addr_state) = all_addresses.get(&pm.signal_id) {
                    AddressManager::from_serialized(&pm.signal_id, addr_state.clone())
                } else {
                    AddressManager::new()
                };
                peers.insert(
                    pm.nostr_pubkey.clone(),
                    Peer {
                        nostr_pubkey: pm.nostr_pubkey,
                        signal_id: pm.signal_id,
                        name: pm.name,
                        signal,
                        address_manager: addr_mgr,
                    },
                );
            }
        }

        let mls_db_path = data_dir.join("mls.db");
        let mls_provider = libkeychat::mls::MlsProvider::open(mls_db_path.to_str().unwrap())
            .unwrap_or_else(|e| {
                eprintln!("MLS storage open failed, falling back to in-memory: {e}");
                libkeychat::mls::MlsProvider::new()
            });
        let mls = MlsParticipant::with_provider(identity.pubkey_hex(), mls_provider)?;

        let owner = config.owner.clone();

        // Initialize stamp manager (without wallet for now — wallet setup is optional)
        let stamp_manager = Arc::new(libkeychat::StampManager::without_wallet());
        {
            let sm = stamp_manager.clone();
            let urls: Vec<String> = relay_urls.to_vec();
            tokio::spawn(async move {
                let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
                sm.fetch_and_cache_fees(&url_refs).await;
            });
        }

        // Load groups
        let mut group_manager = GroupManager::new();
        {
            let store = storage.lock().unwrap();
            let _ = group_manager.load_all(&store);
        }

        Ok(Self {
            identity,
            keys,
            client,
            storage,
            peers: Arc::new(RwLock::new(peers)),
            active_chat: Arc::new(RwLock::new(None)),
            relay_urls: relay_urls.to_vec(),
            name: config.name.clone(),
            config,
            data_dir: data_dir.to_path_buf(),
            signal_groups: Arc::new(RwLock::new(group_manager)),
            mls: Arc::new(Mutex::new(Some(SendMls(mls)))),
            pending_outbound_frs: Arc::new(RwLock::new(HashMap::new())),
            pending_friend_requests: Arc::new(RwLock::new(Vec::new())),
            owner: Arc::new(RwLock::new(owner)),
            stamp_manager,
        })
    }

    pub fn npub(&self) -> String {
        self.identity.pubkey_hex()
    }

    pub fn db(&self) -> std::sync::MutexGuard<'_, SecureStorage> {
        self.storage.lock().unwrap()
    }

    pub fn storage_arc(&self) -> Arc<Mutex<SecureStorage>> {
        self.storage.clone()
    }
}
