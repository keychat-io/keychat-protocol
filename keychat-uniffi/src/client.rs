use std::collections::HashMap;
use std::sync::Arc;

use libkeychat::{
    reconstruct_prekey_material, AddressManager, ChatSession, EphemeralKeypair, FriendRequestState,
    GroupManager, Identity, SecureStorage, SignalParticipant, Transport,
};

use std::sync::Once;

use crate::error::KeychatUniError;
use crate::types::*;

static TRACING_INIT: Once = Once::new();

pub(crate) struct ClientInner {
    pub identity: Option<Identity>,
    pub transport: Option<Transport>,
    pub storage: Arc<std::sync::Mutex<SecureStorage>>,
    pub sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    pub peer_nostr_to_signal: HashMap<String, String>,
    pub pending_outbound: HashMap<String, FriendRequestState>,
    pub group_manager: GroupManager,
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
        // Initialize tracing subscriber once so Rust logs appear in Xcode console
        TRACING_INIT.call_once(|| {
            let level = if cfg!(debug_assertions) {
                tracing::Level::DEBUG
            } else {
                tracing::Level::INFO
            };
            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_target(true)
                .with_thread_names(true)
                .without_time() // os_log already timestamps
                .init();
        });

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
                group_manager: GroupManager::new(),
                next_signal_device_id: 1,
                event_listener: None,
                event_loop_stop: None,
            }),
            runtime: Arc::new(runtime),
            db_path,
        })
    }

    pub async fn create_identity(&self) -> Result<CreateIdentityResult, KeychatUniError> {
        let result = Identity::generate().map_err(|e| {
            tracing::error!("create_identity failed: {e}");
            e
        })?;
        let pubkey_hex = result.identity.pubkey_hex();
        let mnemonic = result.mnemonic.clone();

        let mut inner = self.inner.write().await;
        inner.identity = Some(result.identity);
        tracing::info!("identity created: {}", &pubkey_hex[..16]);

        Ok(CreateIdentityResult {
            pubkey_hex,
            mnemonic,
        })
    }

    pub async fn import_identity(&self, mnemonic: String) -> Result<String, KeychatUniError> {
        let identity = Identity::from_mnemonic_str(&mnemonic).map_err(|e| {
            tracing::error!("import_identity failed: {e}");
            e
        })?;
        let pubkey_hex = identity.pubkey_hex();

        let mut inner = self.inner.write().await;
        inner.identity = Some(identity);
        tracing::info!("identity imported: {}", &pubkey_hex[..16]);

        Ok(pubkey_hex)
    }

    /// Debug: return a summary of stored state in the database + in-memory.
    pub async fn debug_state_summary(&self) -> Result<String, KeychatUniError> {
        let inner = self.inner.read().await;

        // In-memory state
        let mem_sessions = inner.sessions.len();
        let mem_pending_out = inner.pending_outbound.len();
        let mem_peer_map = inner.peer_nostr_to_signal.len();

        // DB state
        let store = inner
            .storage
            .lock()
            .map_err(|e| KeychatUniError::Transport {
                msg: format!("storage lock: {e}"),
            })?;
        let db_participants =
            store
                .list_signal_participants()
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("list_signal_participants: {e}"),
                })?;
        let db_peers = store.list_peers().map_err(|e| KeychatUniError::Storage {
            msg: format!("list_peers: {e}"),
        })?;
        let db_pending_frs = store
            .list_pending_frs()
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("list_pending_frs: {e}"),
            })?;
        let db_inbound_frs = store
            .list_inbound_frs()
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("list_inbound_frs: {e}"),
            })?;

        Ok(format!(
            "MEM: sessions={} pending_out={} peer_map={} | DB: participants={} peers={} pending_frs={} inbound_frs={}",
            mem_sessions, mem_pending_out, mem_peer_map,
            db_participants.len(), db_peers.len(), db_pending_frs.len(), db_inbound_frs.len()
        ))
    }

    /// Restore all persisted sessions and pending friend requests from SQLCipher.
    /// Must be called after import_identity() and before connect().
    pub async fn restore_sessions(&self) -> Result<u32, KeychatUniError> {
        let mut inner = self.inner.write().await;
        let identity = inner
            .identity
            .clone()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "call import_identity first".into(),
            })?;
        let storage = inner.storage.clone();

        let store = storage.lock().map_err(|e| KeychatUniError::Transport {
            msg: format!("storage lock: {e}"),
        })?;

        let mut restored_count: u32 = 0;
        let mut max_device_id: u32 = 0;

        // ── Phase 1: Read all data from DB while holding the lock ──
        let peers;
        let peer_ids;
        let all_addresses;
        let fr_ids;

        // Loaded participant data: (peer_signal_id, device_id, serialized fields...)
        type ParticipantRow = (
            String,
            u32,
            Vec<u8>,
            Vec<u8>,
            u32,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
        );
        let mut participant_rows: Vec<ParticipantRow> = Vec::new();

        // Loaded pending FR data
        type FrRow = (
            String,
            u32,
            Vec<u8>,
            Vec<u8>,
            u32,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            String,
            String,
        );
        let mut fr_rows: Vec<FrRow> = Vec::new();

        {
            peers = store.list_peers().map_err(|e| {
                tracing::error!("restore: list_peers failed: {e}");
                KeychatUniError::Storage {
                    msg: format!("list_peers: {e}"),
                }
            })?;
            peer_ids = store.list_signal_participants().map_err(|e| {
                tracing::error!("restore: list_signal_participants failed: {e}");
                KeychatUniError::Storage {
                    msg: format!("list_signal_participants: {e}"),
                }
            })?;
            all_addresses = store.load_all_peer_addresses().map_err(|e| {
                tracing::error!("restore: load_all_peer_addresses failed: {e}");
                KeychatUniError::Storage {
                    msg: format!("load_all_peer_addresses: {e}"),
                }
            })?;
            fr_ids = store.list_pending_frs().map_err(|e| {
                tracing::error!("restore: list_pending_frs failed: {e}");
                KeychatUniError::Storage {
                    msg: format!("list_pending_frs: {e}"),
                }
            })?;
            tracing::info!(
                "RESTORE-V2: peers={} participants={} addresses={} frs={}",
                peers.len(),
                peer_ids.len(),
                all_addresses.len(),
                fr_ids.len()
            );

            for peer_signal_id in &peer_ids {
                match store.load_signal_participant(peer_signal_id) {
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
                        participant_rows.push((
                            peer_signal_id.clone(),
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
                        ));
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "restore: no data for participant {}",
                            &peer_signal_id[..16.min(peer_signal_id.len())]
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "restore: load participant {} failed: {e}",
                            &peer_signal_id[..16.min(peer_signal_id.len())]
                        );
                    }
                }
            }

            for fr_id in &fr_ids {
                match store.load_pending_fr(fr_id) {
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
                        first_inbox_secret,
                        peer_nostr_pubkey,
                    ))) => {
                        fr_rows.push((
                            fr_id.clone(),
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
                            first_inbox_secret,
                            peer_nostr_pubkey,
                        ));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!(
                            "restore pending FR {} failed: {e}",
                            &fr_id[..16.min(fr_id.len())]
                        );
                    }
                }
            }
        }
        // ── Drop the Mutex guard so SignalParticipant::persistent can lock it ──
        drop(store);

        // ── Phase 2: Reconstruct objects (may lock storage internally) ──

        // 1. Restore peer mappings
        for peer in &peers {
            inner
                .peer_nostr_to_signal
                .insert(peer.nostr_pubkey.clone(), peer.signal_id.clone());
        }
        if !peers.is_empty() {
            tracing::info!("restored {} peer mappings", peers.len());
        }

        // 2. Restore active sessions
        let addr_map: HashMap<String, _> = all_addresses.into_iter().collect();

        for (
            peer_signal_id,
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
        ) in participant_rows
        {
            if device_id > max_device_id {
                max_device_id = device_id;
            }

            let keys = match reconstruct_prekey_material(
                &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
            ) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore session {}: reconstruct keys failed: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                    continue;
                }
            };

            // SignalParticipant::persistent locks storage internally — safe now
            let signal = match SignalParticipant::persistent(
                identity.pubkey_hex(),
                device_id,
                keys,
                storage.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "restore session {}: create participant failed: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                    continue;
                }
            };

            let addresses = if let Some(addr_state) = addr_map.get(&peer_signal_id) {
                AddressManager::from_serialized(&peer_signal_id, addr_state.clone())
            } else {
                AddressManager::new()
            };

            let session = ChatSession::new(signal, addresses, identity.clone());
            inner.sessions.insert(
                peer_signal_id.clone(),
                Arc::new(tokio::sync::Mutex::new(session)),
            );
            restored_count += 1;
        }

        // 3. Restore pending outbound friend requests
        for (
            fr_id,
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
            first_inbox_secret,
            peer_nostr_pubkey,
        ) in fr_rows
        {
            if device_id > max_device_id {
                max_device_id = device_id;
            }

            let keys = match reconstruct_prekey_material(
                &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
            ) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {}: reconstruct keys failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                    continue;
                }
            };

            let signal = match SignalParticipant::persistent(
                identity.pubkey_hex(),
                device_id,
                keys,
                storage.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {}: create participant failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                    continue;
                }
            };

            let first_inbox_keys = match EphemeralKeypair::from_secret_hex(&first_inbox_secret) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {}: reconstruct first_inbox failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                    continue;
                }
            };

            inner.pending_outbound.insert(
                fr_id.clone(),
                FriendRequestState {
                    signal_participant: signal,
                    first_inbox_keys,
                    request_id: fr_id.clone(),
                    peer_nostr_pubkey,
                },
            );
        }
        if !fr_ids.is_empty() {
            tracing::info!("restored {} pending friend requests", fr_ids.len());
        }

        // 4. Restore signal groups
        {
            let storage_arc = inner.storage.clone();
            let store = storage_arc.lock().map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
            inner.group_manager.load_all(&store).map_err(|e| {
                tracing::error!("restore: load_all groups failed: {e}");
                KeychatUniError::Storage {
                    msg: format!("load_all groups: {e}"),
                }
            })?;
            if inner.group_manager.group_count() > 0 {
                tracing::info!(
                    "restored {} signal groups",
                    inner.group_manager.group_count()
                );
            }
        }

        // Update device_id counter to avoid collisions
        if max_device_id >= inner.next_signal_device_id {
            inner.next_signal_device_id = max_device_id + 1;
        }

        tracing::info!(
            "restore complete: {} sessions, {} pending FRs, {} groups, next_device_id={}",
            restored_count,
            inner.pending_outbound.len(),
            inner.group_manager.group_count(),
            inner.next_signal_device_id
        );

        Ok(restored_count)
    }

    /// Checkpoint the WAL and close the database cleanly.
    /// Call before dropping the client if another client will reopen the same DB.
    pub async fn close_storage(&self) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store.checkpoint().map_err(|e| KeychatUniError::Storage {
            msg: format!("checkpoint: {e}"),
        })?;
        Ok(())
    }

    pub async fn get_pubkey_hex(&self) -> Result<String, KeychatUniError> {
        let inner = self.inner.read().await;
        inner
            .identity
            .as_ref()
            .map(|id| id.pubkey_hex())
            .ok_or(KeychatUniError::NotInitialized {
                msg: "no identity set".into(),
            })
    }

    pub async fn connect(&self, relay_urls: Vec<String>) -> Result<(), KeychatUniError> {
        // 1. Resolve relay URLs: parameter → DB → defaults
        let (identity, urls) = {
            let inner = self.inner.read().await;
            let identity = inner
                .identity
                .clone()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "call create_identity first".into(),
                })?;

            let urls = if !relay_urls.is_empty() {
                relay_urls
            } else {
                // Try loading from DB
                let storage = inner.storage.clone();
                let db_relays = storage
                    .lock()
                    .ok()
                    .and_then(|s| s.list_relays().ok())
                    .unwrap_or_default();
                if !db_relays.is_empty() {
                    db_relays
                } else {
                    libkeychat::DEFAULT_RELAYS
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                }
            };
            (identity, urls)
        };

        tracing::info!("connecting to {} relays: {:?}", urls.len(), urls);

        // 2. Create transport, inject storage for persistent dedup, add relays, connect
        let mut transport = Transport::new(identity.keys()).await?;
        let storage_for_transport = {
            let inner = self.inner.read().await;
            inner.storage.clone()
        };
        transport.set_storage(storage_for_transport.clone());
        // Prune old dedup records on connect
        if let Ok(store) = storage_for_transport.lock() {
            let _ = store.prune_processed_events(86400 * 7); // 7 days
        }
        drop(storage_for_transport);
        for url in &urls {
            transport.add_relay(url).await.map_err(|e| {
                tracing::error!("add_relay({url}) failed: {e}");
                e
            })?;
        }
        transport.connect().await;
        tracing::info!("relay transport connected");

        // 3. Persist the relay list to DB
        {
            let storage = self.inner.read().await.storage.clone();
            let store = storage.lock();
            if let Ok(store) = store {
                for url in &urls {
                    let _ = store.save_relay(url);
                }
            }
        }

        // 4. Re-acquire lock to store transport
        let mut inner = self.inner.write().await;
        inner.transport = Some(transport);
        Ok(())
    }

    /// Add a relay at runtime, connect to it, and persist to DB.
    pub async fn add_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        transport.add_relay_and_connect(&url).await?;

        let storage = inner.storage.clone();
        if let Ok(store) = storage.lock() {
            let _ = store.save_relay(&url);
        }
        tracing::info!("added relay: {url}");
        Ok(())
    }

    /// Remove a relay at runtime and delete from DB.
    pub async fn remove_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        transport.remove_relay(&url).await?;

        let storage = inner.storage.clone();
        if let Ok(store) = storage.lock() {
            let _ = store.delete_relay(&url);
        }
        tracing::info!("removed relay: {url}");
        Ok(())
    }

    /// Get the current relay URL list.
    pub async fn get_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        Ok(transport.get_relays().await)
    }

    /// Get only the currently connected relay URLs.
    pub async fn connected_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        Ok(transport.connected_relays().await)
    }

    /// Get relay URLs with their connection status.
    pub async fn get_relay_statuses(&self) -> Result<Vec<RelayStatusInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        Ok(transport
            .get_relay_statuses()
            .await
            .into_iter()
            .map(|(url, status)| RelayStatusInfo { url, status })
            .collect())
    }

    /// Reconnect to all relays (re-enables disabled ones).
    pub async fn reconnect_relays(&self) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        transport.reconnect().await?;
        tracing::info!("reconnected to all relays");
        Ok(())
    }

    /// Reconnect a specific relay.
    pub async fn reconnect_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        transport.reconnect_relay(&url).await?;
        tracing::info!("reconnected relay: {url}");
        Ok(())
    }

    /// Rebroadcast an event (JSON) to all connected relays.
    pub async fn rebroadcast_event(
        &self,
        event_json: String,
    ) -> Result<PublishResultInfo, KeychatUniError> {
        let event: nostr::Event =
            serde_json::from_str(&event_json).map_err(|e| KeychatUniError::Transport {
                msg: format!("invalid event JSON: {e}"),
            })?;
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        let result = transport.rebroadcast_event(event).await?;
        Ok(PublishResultInfo {
            event_id: result.event_id.to_hex(),
            success_relays: result.success_relays,
            failed_relays: result
                .failed_relays
                .into_iter()
                .map(|(url, error)| FailedRelayInfo { url, error })
                .collect(),
        })
    }

    pub async fn disconnect(&self) -> Result<(), KeychatUniError> {
        tracing::info!("disconnecting from relays");
        // Take transport out, drop lock, then disconnect
        let transport = {
            let mut inner = self.inner.write().await;
            inner.transport.take()
        };
        // Lock dropped here
        if let Some(t) = transport {
            t.disconnect().await.map_err(|e| {
                tracing::error!("disconnect failed: {e}");
                e
            })?;
        }
        tracing::info!("disconnected");
        Ok(())
    }

    /// Remove the current identity and all associated data.
    ///
    /// Stops the event loop, disconnects transport, clears all in-memory state,
    /// and deletes all persisted data from SQLCipher (except relay config).
    pub async fn remove_identity(&self) -> Result<(), KeychatUniError> {
        tracing::info!("remove_identity: clearing all data");

        // 1. Stop event loop
        {
            let inner = self.inner.read().await;
            if let Some(ref stop_tx) = inner.event_loop_stop {
                let _ = stop_tx.send(true);
            }
        }

        // 2. Disconnect transport
        {
            let mut inner = self.inner.write().await;
            if let Some(t) = inner.transport.take() {
                let _ = t.disconnect().await;
            }
        }

        // 3. Clear all in-memory state + DB
        let storage = self.inner.read().await.storage.clone();
        {
            let mut inner = self.inner.write().await;
            inner.sessions.clear();
            inner.peer_nostr_to_signal.clear();
            inner.pending_outbound.clear();
            inner.group_manager = libkeychat::GroupManager::new();
            inner.identity = None;
            inner.next_signal_device_id = 1;
            inner.event_loop_stop = None;
        }
        if let Ok(store) = storage.lock() {
            store
                .delete_all_data()
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("delete_all_data: {e}"),
                })?;
        }

        tracing::info!("remove_identity: done");
        Ok(())
    }

    /// Remove a room (1:1 peer or group) and all associated data.
    ///
    /// For 1:1: clears session, signal participant, peer mapping, addresses.
    /// For groups: removes from GroupManager + storage.
    pub async fn remove_room(&self, room_id: String) -> Result<(), KeychatUniError> {
        let storage = self.inner.read().await.storage.clone();

        // Try as 1:1 peer first (room_id = nostr pubkey)
        {
            let mut inner = self.inner.write().await;
            if let Some(signal_id) = inner.peer_nostr_to_signal.remove(&room_id) {
                inner.sessions.remove(&signal_id);

                // Remove any pending outbound FR for this peer
                let pending_keys: Vec<String> = inner.pending_outbound.keys().cloned().collect();
                for key in pending_keys {
                    if let Some(state) = inner.pending_outbound.get(&key) {
                        if state.peer_nostr_pubkey == room_id {
                            inner.pending_outbound.remove(&key);
                            break;
                        }
                    }
                }
                drop(inner);

                // Delete from DB (no write lock held)
                if let Ok(store) = storage.lock() {
                    let _ = store.delete_peer_data(&signal_id, &room_id);
                }

                tracing::info!(
                    "remove_room: removed 1:1 peer {}",
                    &room_id[..16.min(room_id.len())]
                );
                return Ok(());
            }
        }

        // Try as Signal group
        {
            let mut inner = self.inner.write().await;
            if inner.group_manager.get_group(&room_id).is_some() {
                if let Ok(store) = storage.lock() {
                    let _ = inner
                        .group_manager
                        .remove_group_persistent(&room_id, &store);
                } else {
                    inner.group_manager.remove_group(&room_id);
                }
                tracing::info!(
                    "remove_room: removed group {}",
                    &room_id[..16.min(room_id.len())]
                );
                return Ok(());
            }
        }

        // Try as MLS group
        if let Ok(store) = storage.lock() {
            let _ = store.delete_mls_group_id(&room_id);
        }

        tracing::warn!(
            "remove_room: room {} not found",
            &room_id[..16.min(room_id.len())]
        );
        Ok(())
    }

    /// Register an event listener for receiving async events from the event loop.
    pub async fn set_event_listener(&self, listener: Box<dyn EventListener>) {
        let mut inner = self.inner.write().await;
        inner.event_listener = Some(listener);
    }

    /// Start the event loop: subscribe to relay notifications and dispatch
    /// incoming events to the registered EventListener.
    ///
    /// Uses `Arc<Self>` so the event loop task can hold a reference.
    pub async fn start_event_loop(self: Arc<Self>) -> Result<(), KeychatUniError> {
        // Collect pubkeys to subscribe to
        let pubkeys = self.collect_subscribe_pubkeys().await;
        tracing::info!("event loop: subscribing to {} pubkeys", pubkeys.len());
        if pubkeys.is_empty() {
            tracing::error!("event loop: no pubkeys to subscribe — no identity set");
            return Err(KeychatUniError::NotInitialized {
                msg: "no pubkeys to subscribe to — set identity first".into(),
            });
        }

        // Subscribe via Transport
        {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                })?;
            transport.subscribe(pubkeys, None).await.map_err(|e| {
                tracing::error!("event loop: subscribe failed: {e}");
                e
            })?;
        } // lock dropped

        // Create stop channel
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut inner = self.inner.write().await;
            inner.event_loop_stop = Some(stop_tx);
        }

        // Spawn the event loop task
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.run_event_loop(stop_rx).await;
        });

        Ok(())
    }

    /// Stop the event loop.
    pub async fn stop_event_loop(&self) {
        let mut inner = self.inner.write().await;
        if let Some(stop_tx) = inner.event_loop_stop.take() {
            let _ = stop_tx.send(true);
        }
    }
}
