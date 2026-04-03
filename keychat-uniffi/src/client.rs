use std::collections::HashMap;
use std::sync::Arc;

use libkeychat::{
    reconstruct_prekey_material, AddressManager, ChatSession, DeviceId, EphemeralKeypair,
    FriendRequestState, GroupManager, Identity, SecureStorage, SignalParticipant, Transport,
};

/// Default Signal device ID used throughout the FFI layer.
pub(crate) fn default_device_id() -> DeviceId {
    DeviceId::new(1).expect("device_id 1 is always valid")
}

use std::sync::Once;

use crate::app_storage::AppStorage;
use crate::error::KeychatUniError;
use crate::relay_tracker::RelaySendTracker;
use crate::types::*;

static TRACING_INIT: Once = Once::new();

/// Lock app_storage Mutex, recovering from poison and logging if poisoned.
pub(crate) fn lock_app_storage(
    mutex: &std::sync::Mutex<crate::app_storage::AppStorage>,
) -> std::sync::MutexGuard<'_, crate::app_storage::AppStorage> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!("app_storage Mutex poisoned, recovering: {e}");
        e.into_inner()
    })
}

/// Lock app_storage Mutex, returning Result for functions that need error propagation.
pub(crate) fn lock_app_storage_result(
    mutex: &std::sync::Mutex<crate::app_storage::AppStorage>,
) -> Result<std::sync::MutexGuard<'_, crate::app_storage::AppStorage>, KeychatUniError> {
    mutex.lock().map_err(|e| KeychatUniError::Storage {
        msg: format!("app_storage lock: {e}"),
    })
}

pub(crate) struct ClientInner {
    pub identity: Option<Identity>,
    pub transport: Option<Transport>,
    pub storage: Arc<std::sync::Mutex<SecureStorage>>,
    pub app_storage: Arc<std::sync::Mutex<AppStorage>>,
    pub sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    pub peer_nostr_to_signal: HashMap<String, String>,
    pub pending_outbound: HashMap<String, FriendRequestState>,
    pub group_manager: GroupManager,
    pub next_signal_device_id: u32,
    pub event_listener: Option<Box<dyn EventListener>>,
    pub data_listener: Option<Box<dyn DataListener>>,
    pub event_loop_stop: Option<tokio::sync::watch::Sender<bool>>,
    pub reconnect_stop: Option<tokio::sync::watch::Sender<bool>>,
    pub last_relay_urls: Vec<String>,
}

#[derive(uniffi::Object)]
pub struct KeychatClient {
    pub(crate) inner: tokio::sync::RwLock<ClientInner>,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
    pub(crate) db_path: String,
    /// Base directory for file storage: {app_support}/files/
    pub(crate) files_dir: String,
    pub(crate) relay_tracker: std::sync::Mutex<RelaySendTracker>,
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
            let _ = tracing_subscriber::fmt()
                .with_max_level(level)
                .with_target(true)
                .with_thread_names(true)
                .without_time() // os_log already timestamps
                .try_init();
        });

        let storage = SecureStorage::open(&db_path, &db_key)?;

        // Derive app database path: protocol.db → protocol_app.db
        let app_db_path = if db_path.ends_with(".db") {
            db_path.replace(".db", "_app.db")
        } else {
            format!("{}_app", db_path)
        };
        let app_storage =
            AppStorage::open(&app_db_path, &db_key).map_err(|e| KeychatUniError::Storage {
                msg: format!("open app database: {e}"),
            })?;

        // Derive files directory: db_path is {app_support}/libkeychat/libkeychat.db
        // files_dir becomes {app_support}/files/
        let files_dir = {
            let db_dir = std::path::Path::new(&db_path)
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let base = db_dir.parent().unwrap_or(db_dir);
            base.join("files").to_string_lossy().to_string()
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;

        Ok(Self {
            inner: tokio::sync::RwLock::new(ClientInner {
                identity: None,
                transport: None,
                storage: Arc::new(std::sync::Mutex::new(storage)),
                app_storage: Arc::new(std::sync::Mutex::new(app_storage)),
                sessions: HashMap::new(),
                peer_nostr_to_signal: HashMap::new(),
                pending_outbound: HashMap::new(),
                group_manager: GroupManager::new(),
                next_signal_device_id: 1,
                event_listener: None,
                data_listener: None,
                event_loop_stop: None,
                reconnect_stop: None,
                last_relay_urls: Vec::new(),
            }),
            runtime: Arc::new(runtime),
            db_path,
            files_dir,
            relay_tracker: std::sync::Mutex::new(RelaySendTracker::new()),
        })
    }

    // ─── File Storage ────────────────────────────────────────────────

    /// Get the base files directory path.
    pub fn get_files_dir(&self) -> String {
        self.files_dir.clone()
    }

    /// Resolve a downloaded file's absolute path from the file_attachments table.
    /// Returns None if not downloaded or the file has been deleted from disk.
    pub async fn resolve_local_file(&self, msgid: String, file_hash: String) -> Option<String> {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        let local_path = store.get_attachment_local_path(&msgid, &file_hash).ok()??;
        let abs_path = std::path::Path::new(&self.files_dir).join(&local_path);
        if abs_path.exists() {
            Some(abs_path.to_string_lossy().to_string())
        } else {
            None
        }
    }

    /// Insert or update a file attachment record.
    /// transfer_state: 0=pending, 1=downloading, 2=downloaded, 3=failed
    pub async fn upsert_attachment(
        &self,
        msgid: String,
        file_hash: String,
        room_id: String,
        local_path: Option<String>,
        transfer_state: u32,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .upsert_attachment(
                &msgid,
                &file_hash,
                &room_id,
                local_path.as_deref(),
                transfer_state as i32,
            )
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("upsert_attachment: {e}"),
            })
    }

    /// Mark a voice attachment as played.
    pub async fn set_audio_played(
        &self,
        msgid: String,
        file_hash: String,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .set_audio_played(&msgid, &file_hash)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("set_audio_played: {e}"),
            })
    }

    /// Check if a voice attachment has been played.
    pub async fn is_audio_played(&self, msgid: String, file_hash: String) -> bool {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store.is_audio_played(&msgid, &file_hash)
    }

    /// Get the files directory for a specific room.
    pub fn get_room_files_dir(&self, room_id: String) -> String {
        std::path::Path::new(&self.files_dir)
            .join(&room_id)
            .to_string_lossy()
            .to_string()
    }

    // ─── Media Upload/Download (delegates to free functions, runs in client's runtime) ──

    /// Encrypt and upload data to a Blossom server.
    /// This is a method wrapper around the free function `encrypt_and_upload`,
    /// ensuring it runs in the client's tokio runtime (needed for Swift/UniFFI).
    pub async fn upload_encrypted(
        &self,
        plaintext: Vec<u8>,
        server_url: String,
    ) -> Result<crate::media::FileUploadResult, KeychatUniError> {
        crate::media::encrypt_and_upload(plaintext, server_url).await
    }

    /// Encrypt and upload, routing to relay or Blossom based on server URL.
    /// If server_url is None, uses the active media server from settings.
    pub async fn upload_encrypted_routed(
        &self,
        plaintext: Vec<u8>,
        server_url: Option<String>,
    ) -> Result<crate::media::FileUploadResult, KeychatUniError> {
        let server = match server_url {
            Some(s) => s,
            None => self.get_active_media_server().await?,
        };
        crate::media::encrypt_and_upload_routed(plaintext, server).await
    }

    /// Download and decrypt data from a Blossom server.
    /// Method wrapper around the free function `download_and_decrypt`.
    pub async fn download_decrypted(
        &self,
        url: String,
        key: String,
        iv: String,
        hash: String,
    ) -> Result<Vec<u8>, KeychatUniError> {
        crate::media::download_and_decrypt(url, key, iv, hash).await
    }

    /// Download, decrypt, save to {files_dir}/{room_id}/{local_file_name}, and record in file_attachments.
    /// Returns the absolute path of the saved file.
    /// Idempotent: if the attachment is already downloaded, returns the existing path.
    pub async fn download_and_save(
        &self,
        url: String,
        key: String,
        iv: String,
        hash: String,
        source_name: Option<String>,
        suffix: Option<String>,
        room_id: String,
        msgid: Option<String>,
    ) -> Result<String, KeychatUniError> {
        // Idempotent: check attachment table first
        if let Some(ref mid) = msgid {
            if let Some(abs) = self.resolve_local_file(mid.clone(), hash.clone()).await {
                return Ok(abs);
            }
        }

        let file_name = crate::media::local_file_name(source_name, hash.clone(), suffix);
        let room_dir = std::path::Path::new(&self.files_dir).join(&room_id);
        let file_path = room_dir.join(&file_name);
        let relative_path = format!("{room_id}/{file_name}");

        // File exists on disk but no record — backfill the record
        if file_path.exists() {
            if let Some(ref mid) = msgid {
                let _ = self
                    .upsert_attachment(
                        mid.clone(),
                        hash.clone(),
                        room_id.clone(),
                        Some(relative_path),
                        2,
                    )
                    .await;
            }
            return Ok(file_path.to_string_lossy().to_string());
        }

        // Create directory
        std::fs::create_dir_all(&room_dir).map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("create dir {}: {e}", room_dir.display()),
        })?;

        // Download + decrypt
        let plaintext = crate::media::download_and_decrypt(url, key, iv, hash.clone()).await?;

        // Atomic write via temp file
        let tmp_path = room_dir.join(format!(".{file_name}.tmp"));
        std::fs::write(&tmp_path, &plaintext).map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("write temp file: {e}"),
        })?;
        std::fs::rename(&tmp_path, &file_path).map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("rename temp file: {e}"),
        })?;

        tracing::info!("Downloaded {} ({} bytes)", file_name, plaintext.len());

        // Record in file_attachments
        if let Some(ref mid) = msgid {
            let _ = self
                .upsert_attachment(
                    mid.clone(),
                    hash.clone(),
                    room_id.clone(),
                    Some(relative_path),
                    2,
                )
                .await;
        }

        Ok(file_path.to_string_lossy().to_string())
    }

    /// Save plaintext data to {files_dir}/{room_id}/{file_name} for local caching.
    /// Used by the send path to cache sent files for immediate display.
    /// Returns the absolute path of the saved file.
    pub fn save_file_locally(
        &self,
        data: Vec<u8>,
        file_name: String,
        room_id: String,
    ) -> Result<String, KeychatUniError> {
        let room_dir = std::path::Path::new(&self.files_dir).join(&room_id);
        let file_path = room_dir.join(&file_name);

        if file_path.exists() {
            return Ok(file_path.to_string_lossy().to_string());
        }

        std::fs::create_dir_all(&room_dir).map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("create dir: {e}"),
        })?;

        std::fs::write(&file_path, &data).map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("write file: {e}"),
        })?;

        Ok(file_path.to_string_lossy().to_string())
    }

    // ─── Identity ──

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

        let store = storage.lock().map_err(|e| KeychatUniError::Storage {
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

        // 4. Re-acquire lock to store transport and relay list
        let mut inner = self.inner.write().await;
        inner.transport = Some(transport);
        inner.last_relay_urls = urls;
        Ok(())
    }

    /// Add a relay at runtime, connect to it, and persist to DB.
    pub async fn add_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
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
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
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
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
        })?;
        Ok(transport.get_relays().await)
    }

    /// Get only the currently connected relay URLs.
    pub async fn connected_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
        })?;
        Ok(transport.connected_relays().await)
    }

    /// Get relay URLs with their connection status.
    pub async fn get_relay_statuses(&self) -> Result<Vec<RelayStatusInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
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
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
        })?;
        transport.reconnect().await?;
        tracing::info!("reconnected to all relays");
        Ok(())
    }

    /// Reconnect a specific relay.
    pub async fn reconnect_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
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
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
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
        // Also clear application-layer data
        let app_storage = self.inner.read().await.app_storage.clone();
        {
            let store = lock_app_storage(&app_storage);
            store
                .delete_all_data()
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("delete_all_app_data: {e}"),
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
        let mut found = false;

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
                found = true;
            }
        }

        // Try as Signal group
        if !found {
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
                found = true;
            }
        }

        // Try as MLS group
        if !found {
            if let Ok(store) = storage.lock() {
                let _ = store.delete_mls_group_id(&room_id);
            }
            tracing::warn!(
                "remove_room: room {} not found",
                &room_id[..16.min(room_id.len())]
            );
        }

        // Clean up app_* tables (in app database)
        let identity_pubkey = {
            let inner = self.inner.read().await;
            inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default()
        };
        if !identity_pubkey.is_empty() {
            let app_room_id = format!("{}:{}", room_id, identity_pubkey);
            let app_storage = self.inner.read().await.app_storage.clone();
            {
                let store = lock_app_storage(&app_storage);
                if let Err(e) = store.delete_app_room(&app_room_id) {
                    tracing::warn!("remove_room: delete_app_room: {e}");
                }
                if let Err(e) = store.delete_app_contact(&room_id, &identity_pubkey) {
                    tracing::warn!("remove_room: delete_app_contact: {e}");
                }
            }
            self.emit_data_change(DataChange::RoomListChanged).await;
            self.emit_data_change(DataChange::ContactListChanged).await;
        }

        Ok(())
    }

    /// Remove a specific Signal session for a peer.
    ///
    /// Clears session, pending_outbound, peer mapping, and all related data from memory and DB.
    /// This API is designed for situations where you want to clean up just one peer's session
    /// without removing the entire room/contact.
    pub async fn remove_session(&self, peer_pubkey: String) -> Result<(), KeychatUniError> {
        let storage = self.inner.read().await.storage.clone();

        {
            let mut inner = self.inner.write().await;

            // Remove signal session
            if let Some(signal_id) = inner.peer_nostr_to_signal.remove(&peer_pubkey) {
                inner.sessions.remove(&signal_id);

                // Remove any pending outbound FR for this peer
                let pending_keys: Vec<String> = inner.pending_outbound.keys().cloned().collect();
                for key in pending_keys {
                    if let Some(state) = inner.pending_outbound.get(&key) {
                        if state.peer_nostr_pubkey == peer_pubkey {
                            inner.pending_outbound.remove(&key);
                            break;
                        }
                    }
                }

                // Clean up in DB (no write lock held during DB operations)
                drop(inner);

                if let Ok(store) = storage.lock() {
                    let _ = store.delete_peer_data(&signal_id, &peer_pubkey);
                }

                tracing::info!(
                    "remove_session: removed session for peer {}",
                    &peer_pubkey[..16.min(peer_pubkey.len())]
                );
            } else {
                tracing::warn!(
                    "remove_session: no session found for peer {}",
                    &peer_pubkey[..16.min(peer_pubkey.len())]
                );
            }
        }

        // Clean up app_* tables (in app database)
        let identity_pubkey = {
            let inner = self.inner.read().await;
            inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default()
        };

        if !identity_pubkey.is_empty() {
            let app_storage = self.inner.read().await.app_storage.clone();
            {
                let store = crate::client::lock_app_storage(&app_storage);
                // Only delete contact data, not the room as the room might still be needed
                if let Err(e) = store.delete_app_contact(&peer_pubkey, &identity_pubkey) {
                    tracing::warn!("remove_session: delete_app_contact: {e}");
                }
            }
            // Notify that contact list has changed
            self.emit_data_change(DataChange::ContactListChanged).await;
        }

        Ok(())
    }

    /// Register an event listener for receiving async events from the event loop.
    pub async fn set_event_listener(&self, listener: Box<dyn EventListener>) {
        let mut inner = self.inner.write().await;
        inner.event_listener = Some(listener);
    }

    pub async fn set_data_listener(&self, listener: Box<dyn DataListener>) {
        let mut inner = self.inner.write().await;
        inner.data_listener = Some(listener);
    }

    /// Start the event loop: subscribe to relay notifications and dispatch
    /// incoming events to the registered EventListener.
    ///
    /// Uses `Arc<Self>` so the event loop task can hold a reference.
    pub async fn start_event_loop(self: Arc<Self>) -> Result<(), KeychatUniError> {
        // Collect pubkeys split by type: identity keys vs ratchet keys
        let (identity_pubkeys, ratchet_pubkeys) = self.collect_subscribe_pubkeys().await;
        let total = identity_pubkeys.len() + ratchet_pubkeys.len();
        tracing::info!(
            "event loop: subscribing to {} pubkeys ({} identity, {} ratchet)",
            total,
            identity_pubkeys.len(),
            ratchet_pubkeys.len()
        );
        if identity_pubkeys.is_empty() && ratchet_pubkeys.is_empty() {
            tracing::error!("event loop: no pubkeys to subscribe — no identity set");
            return Err(KeychatUniError::NotInitialized {
                msg: "no pubkeys to subscribe to — set identity first".into(),
            });
        }

        // Read relay subscription cursor for identity key `since` parameter.
        // Identity keys receive NIP-59 GiftWrap with ±2 day outer timestamp randomization,
        // so we subtract 2 days from the cursor as a safety window.
        // Ratchet keys are newly derived addresses with no history — use now().
        let identity_since = {
            let inner = self.inner.read().await;
            let storage = inner.storage.lock().unwrap_or_else(|e| e.into_inner());
            let cursor = storage.get_min_relay_cursor().unwrap_or(0);
            drop(storage);
            drop(inner);

            if cursor > 0 {
                let two_days_secs: u64 = 2 * 24 * 60 * 60;
                let since_ts = cursor.saturating_sub(two_days_secs);
                tracing::info!(
                    "event loop: identity since = cursor({}) - 2days = {}",
                    cursor,
                    since_ts
                );
                Some(libkeychat::Timestamp::from(since_ts))
            } else {
                // First launch — no cursor yet. Subscribe without `since` to get
                // initial history. The relay's own retention policy limits the result.
                // After the first event is processed, the cursor will be set.
                tracing::info!(
                    "event loop: no cursor yet, subscribing without since for initial sync"
                );
                None
            }
        };

        let ratchet_since = Some(libkeychat::Timestamp::now());

        // Log all pubkeys being subscribed to — useful for debugging missing messages
        tracing::info!(
            "📡 SUBSCRIBE identity keys ({}): [{}]",
            identity_pubkeys.len(),
            identity_pubkeys
                .iter()
                .map(|pk| pk.to_hex()[..16].to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        tracing::info!(
            "📡 SUBSCRIBE ratchet keys ({}): [{}]",
            ratchet_pubkeys.len(),
            ratchet_pubkeys
                .iter()
                .map(|pk| pk.to_hex()[..16].to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Subscribe via Transport — separate subscriptions for identity and ratchet keys
        {
            let inner = self.inner.read().await;
            let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;

            if !identity_pubkeys.is_empty() {
                transport
                    .subscribe(identity_pubkeys, identity_since)
                    .await
                    .map_err(|e| {
                        tracing::error!("event loop: identity subscribe failed: {e}");
                        e
                    })?;
            }

            if !ratchet_pubkeys.is_empty() {
                transport
                    .subscribe(ratchet_pubkeys, ratchet_since)
                    .await
                    .map_err(|e| {
                        tracing::error!("event loop: ratchet subscribe failed: {e}");
                        e
                    })?;
            }
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

    // ─── Auto-Reconnect ─────────────────────────────────────

    /// Enable automatic reconnection with exponential backoff.
    /// When connection is lost, the Rust layer will:
    /// 1. Retry connection with exponential backoff (2s, 4s, 8s, ... up to max_delay_secs)
    /// 2. Emit DataChange::ConnectionStatusChanged on every state change
    /// 3. Auto-retry failed messages after successful reconnection
    ///
    /// Call this once after initial `connect()` + `start_event_loop()`.
    /// Call `disable_auto_reconnect()` to stop.
    pub async fn enable_auto_reconnect(
        self: Arc<Self>,
        max_delay_secs: u32,
    ) -> Result<(), KeychatUniError> {
        // Stop any existing reconnect task
        {
            let mut inner = self.inner.write().await;
            if let Some(stop_tx) = inner.reconnect_stop.take() {
                let _ = stop_tx.send(true);
            }
        }

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut inner = self.inner.write().await;
            inner.reconnect_stop = Some(stop_tx);
        }

        let max_delay = std::cmp::max(max_delay_secs, 2) as u64;
        let self_clone = self.clone();

        tokio::spawn(async move {
            self_clone.reconnect_loop(stop_rx, max_delay).await;
        });

        tracing::info!("auto-reconnect enabled (max_delay={}s)", max_delay);
        Ok(())
    }

    /// Disable automatic reconnection.
    pub async fn disable_auto_reconnect(&self) {
        let mut inner = self.inner.write().await;
        if let Some(stop_tx) = inner.reconnect_stop.take() {
            let _ = stop_tx.send(true);
        }
        tracing::info!("auto-reconnect disabled");
    }

    /// Check connectivity and reconnect if needed. Call on app foreground.
    /// Returns the current connection status.
    pub async fn check_connection(self: Arc<Self>) -> ConnectionStatus {
        let connected = self.connected_relays().await.unwrap_or_default();
        if !connected.is_empty() {
            self.notify_connection_status(ConnectionStatus::Connected, None)
                .await;
            ConnectionStatus::Connected
        } else {
            // Trigger immediate reconnect attempt
            self.notify_connection_status(ConnectionStatus::Reconnecting, None)
                .await;
            match self.try_reconnect().await {
                Ok(_) => {
                    self.notify_connection_status(ConnectionStatus::Connected, None)
                        .await;
                    // Auto-retry failed messages after reconnect (delayed to let relays stabilize)
                    let client = Arc::clone(&self);
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        match client.retry_failed_messages().await {
                            Ok(count) => {
                                if count > 0 {
                                    tracing::info!(
                                        "auto-retry after reconnect: {count} messages retried"
                                    );
                                }
                            }
                            Err(e) => tracing::warn!("auto-retry after reconnect failed: {e}"),
                        }
                    });
                    ConnectionStatus::Connected
                }
                Err(e) => {
                    let msg = format!("{e}");
                    self.notify_connection_status(ConnectionStatus::Failed, Some(msg))
                        .await;
                    ConnectionStatus::Failed
                }
            }
        }
    }
}

// ─── Private methods (not exported via UniFFI) ───────────────────

impl KeychatClient {
    /// Internal: reconnect loop with exponential backoff.
    pub(crate) async fn reconnect_loop(
        self: Arc<Self>,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
        max_delay_secs: u64,
    ) {
        // Monitor loop: check connectivity periodically
        let check_interval = std::time::Duration::from_secs(10);

        loop {
            // Wait for check interval or stop signal
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {}
                _ = stop_rx.changed() => {
                    tracing::info!("reconnect loop: stop signal received");
                    return;
                }
            }

            if *stop_rx.borrow() {
                return;
            }

            // Check if we're still connected
            let connected = self.connected_relays().await.unwrap_or_default();
            if !connected.is_empty() {
                continue; // Still connected, keep monitoring
            }

            // Lost connection — start reconnect attempts
            tracing::info!("reconnect loop: connection lost, starting backoff");
            let mut attempt: u32 = 0;

            loop {
                if *stop_rx.borrow() {
                    return;
                }

                attempt += 1;
                let delay_secs = std::cmp::min(2u64.saturating_pow(attempt), max_delay_secs);

                self.notify_connection_status(
                    ConnectionStatus::Reconnecting,
                    Some(format!("attempt {attempt}, retry in {delay_secs}s")),
                )
                .await;

                tracing::info!("reconnect attempt {attempt} in {delay_secs}s…");

                // Wait for delay or stop signal
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {}
                    _ = stop_rx.changed() => {
                        tracing::info!("reconnect loop: stop signal during backoff");
                        return;
                    }
                }

                if *stop_rx.borrow() {
                    return;
                }

                match self.try_reconnect().await {
                    Ok(_) => {
                        tracing::info!("reconnected on attempt {attempt}");
                        self.notify_connection_status(ConnectionStatus::Connected, None)
                            .await;

                        // Check if the event loop is still alive; restart if it has exited.
                        // The stop sender's receiver_count drops to 0 when the event loop task
                        // has exited (all stop_rx handles dropped), indicating a dead loop.
                        let event_loop_dead = {
                            let inner = self.inner.read().await;
                            inner
                                .event_loop_stop
                                .as_ref()
                                .map(|tx| tx.receiver_count() == 0)
                                .unwrap_or(true)
                        };
                        if event_loop_dead {
                            tracing::warn!("reconnect: event loop is dead, restarting");
                            let client = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = client.start_event_loop().await {
                                    tracing::error!("reconnect: failed to restart event loop: {e}");
                                } else {
                                    tracing::info!("reconnect: event loop restarted successfully");
                                }
                            });
                        }

                        // Auto-retry failed messages (delayed to let relay connections stabilize)
                        let client = Arc::clone(&self);
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            match client.retry_failed_messages().await {
                                Ok(count) => {
                                    if count > 0 {
                                        tracing::info!(
                                            "auto-retry after reconnect: {count} messages retried"
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!("auto-retry after reconnect failed: {e}"),
                            }
                        });

                        break; // Back to monitoring loop
                    }
                    Err(e) => {
                        tracing::warn!("reconnect attempt {attempt} failed: {e}");
                        self.notify_connection_status(
                            ConnectionStatus::Failed,
                            Some(format!("attempt {attempt}: {e}")),
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Internal: attempt to reconnect using stored relay URLs.
    pub(crate) async fn try_reconnect(&self) -> Result<(), KeychatUniError> {
        let relay_urls = {
            let inner = self.inner.read().await;
            inner.last_relay_urls.clone()
        };

        if relay_urls.is_empty() {
            return Err(KeychatUniError::NotInitialized {
                msg: "no relay URLs stored".into(),
            });
        }

        // Reconnect existing transport if available
        {
            let inner = self.inner.read().await;
            if let Some(ref transport) = inner.transport {
                transport.reconnect().await?;
                return Ok(());
            }
        }

        // No transport — do a full connect
        self.connect(relay_urls).await
    }

    /// Internal: notify DataListener of connection status change.
    pub(crate) async fn notify_connection_status(
        &self,
        status: ConnectionStatus,
        message: Option<String>,
    ) {
        let inner = self.inner.read().await;
        if let Some(ref listener) = inner.data_listener {
            listener.on_data_change(DataChange::ConnectionStatusChanged { status, message });
        }
    }
}
