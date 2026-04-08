use std::collections::HashMap;
use std::sync::Arc;

use keychat_app_core::AppClient;
use libkeychat::{
    reconstruct_prekey_material, AddressManager, ChatSession, DeviceId, EphemeralKeypair,
    FriendRequestState, GroupManager, Identity, ProtocolClient, SecureStorage, SignalParticipant,
    Transport,
};

use crate::error::KeychatUniError;
use crate::types::*;

/// Re-export from keychat-app-core for use in other keychat-uniffi modules.
pub(crate) fn default_device_id() -> DeviceId {
    keychat_app_core::default_device_id()
}

/// Re-export from keychat-app-core for use in other keychat-uniffi modules.
pub(crate) fn lock_app_storage(
    mutex: &std::sync::Mutex<keychat_app_core::AppStorage>,
) -> std::sync::MutexGuard<'_, keychat_app_core::AppStorage> {
    keychat_app_core::lock_app_storage(mutex)
}

/// Re-export from keychat-app-core for use in other keychat-uniffi modules.
pub(crate) fn lock_app_storage_result(
    mutex: &std::sync::Mutex<keychat_app_core::AppStorage>,
) -> Result<std::sync::MutexGuard<'_, keychat_app_core::AppStorage>, KeychatUniError> {
    keychat_app_core::lock_app_storage_result(mutex)
        .map_err(|e| KeychatUniError::Storage { msg: e.to_string() })
}

#[derive(uniffi::Object)]
pub struct KeychatClient {
    /// The shared AppClient that holds all state.
    /// CLI and other Rust consumers use AppClient directly.
    /// Swift/Kotlin use KeychatClient (this struct) which adds #[uniffi::export].
    /// Arc-wrapped so start_event_loop(self: Arc<AppClient>) can be called.
    pub(crate) app: std::sync::Arc<AppClient>,
}

// ─── Trait Bridge Adapters ──────────────────────────────────────
// UniFFI requires its own trait definitions with #[uniffi::export(callback_interface)].
// AppClientInner uses keychat_app_core's plain traits. These adapters bridge them.

struct EventListenerBridge(Box<dyn crate::types::EventListener>);

impl keychat_app_core::EventListener for EventListenerBridge {
    fn on_event(&self, event: keychat_app_core::ClientEvent) {
        self.0.on_event(convert_client_event(event));
    }
}

struct DataListenerBridge(Box<dyn crate::types::DataListener>);

impl keychat_app_core::DataListener for DataListenerBridge {
    fn on_data_change(&self, change: keychat_app_core::DataChange) {
        self.0.on_data_change(convert_data_change(change));
    }
}

pub(crate) fn convert_client_event(e: keychat_app_core::ClientEvent) -> crate::types::ClientEvent {
    use crate::types::ClientEvent as UE;
    use keychat_app_core::ClientEvent as CE;
    match e {
        CE::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            created_at,
        } => UE::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            created_at,
        },
        CE::FriendRequestAccepted {
            peer_pubkey,
            peer_name,
        } => UE::FriendRequestAccepted {
            peer_pubkey,
            peer_name,
        },
        CE::FriendRequestRejected { peer_pubkey } => UE::FriendRequestRejected { peer_pubkey },
        CE::MessageReceived {
            room_id,
            sender_pubkey,
            kind,
            content,
            payload,
            event_id,
            fallback,
            reply_to_event_id,
            group_id,
            thread_id,
            nostr_event_json,
            relay_url,
        } => UE::MessageReceived {
            room_id,
            sender_pubkey,
            kind: convert_message_kind(kind),
            content,
            payload,
            event_id,
            fallback,
            reply_to_event_id,
            group_id,
            thread_id,
            nostr_event_json,
            relay_url,
        },
        CE::GroupInviteReceived {
            room_id,
            group_type,
            group_name,
            inviter_pubkey,
        } => UE::GroupInviteReceived {
            room_id,
            group_type,
            group_name,
            inviter_pubkey,
        },
        CE::GroupMemberChanged {
            room_id,
            kind,
            member_pubkey,
            new_value,
        } => UE::GroupMemberChanged {
            room_id,
            kind: convert_group_change_kind(kind),
            member_pubkey,
            new_value,
        },
        CE::GroupDissolved { room_id } => UE::GroupDissolved { room_id },
        CE::EventLoopError { description } => UE::EventLoopError { description },
        CE::RelayOk {
            event_id,
            relay_url,
            success,
            message,
        } => UE::RelayOk {
            event_id,
            relay_url,
            success,
            message,
        },
    }
}

pub(crate) fn convert_message_kind(k: keychat_app_core::MessageKind) -> crate::types::MessageKind {
    use crate::types::MessageKind as UK;
    use keychat_app_core::MessageKind as MK;
    match k {
        MK::Text => UK::Text,
        MK::Files => UK::Files,
        MK::Cashu => UK::Cashu,
        MK::LightningInvoice => UK::LightningInvoice,
        MK::FriendRequest => UK::FriendRequest,
        MK::FriendApprove => UK::FriendApprove,
        MK::FriendReject => UK::FriendReject,
        MK::ProfileSync => UK::ProfileSync,
        MK::SignalGroupInvite => UK::SignalGroupInvite,
        MK::SignalGroupMemberRemoved => UK::SignalGroupMemberRemoved,
        MK::SignalGroupSelfLeave => UK::SignalGroupSelfLeave,
        MK::SignalGroupDissolve => UK::SignalGroupDissolve,
        MK::SignalGroupNameChanged => UK::SignalGroupNameChanged,
        MK::MlsGroupInvite => UK::MlsGroupInvite,
        MK::AgentReply => UK::AgentReply,
        _ => UK::Text,
    }
}

pub(crate) fn convert_group_change_kind(
    k: keychat_app_core::GroupChangeKind,
) -> crate::types::GroupChangeKind {
    match k {
        keychat_app_core::GroupChangeKind::MemberRemoved => {
            crate::types::GroupChangeKind::MemberRemoved
        }
        keychat_app_core::GroupChangeKind::SelfLeave => crate::types::GroupChangeKind::SelfLeave,
        keychat_app_core::GroupChangeKind::NameChanged => {
            crate::types::GroupChangeKind::NameChanged
        }
    }
}

pub(crate) fn convert_data_change(c: keychat_app_core::DataChange) -> crate::types::DataChange {
    use crate::types::DataChange as UD;
    use keychat_app_core::DataChange as DC;
    match c {
        DC::RoomUpdated { room_id } => UD::RoomUpdated { room_id },
        DC::RoomDeleted { room_id } => UD::RoomDeleted { room_id },
        DC::RoomListChanged => UD::RoomListChanged,
        DC::MessageAdded { room_id, msgid } => UD::MessageAdded { room_id, msgid },
        DC::MessageUpdated { room_id, msgid } => UD::MessageUpdated { room_id, msgid },
        DC::ContactUpdated { pubkey } => UD::ContactUpdated { pubkey },
        DC::ContactListChanged => UD::ContactListChanged,
        DC::IdentityListChanged => UD::IdentityListChanged,
        DC::ConnectionStatusChanged { status, message } => UD::ConnectionStatusChanged {
            status: match status {
                keychat_app_core::ConnectionStatus::Disconnected => {
                    crate::types::ConnectionStatus::Disconnected
                }
                keychat_app_core::ConnectionStatus::Connecting => {
                    crate::types::ConnectionStatus::Connecting
                }
                keychat_app_core::ConnectionStatus::Connected => {
                    crate::types::ConnectionStatus::Connected
                }
                keychat_app_core::ConnectionStatus::Reconnecting => {
                    crate::types::ConnectionStatus::Reconnecting
                }
                keychat_app_core::ConnectionStatus::Failed => {
                    crate::types::ConnectionStatus::Failed
                }
            },
            message,
        },
    }
}

// ─── Shared type conversions (used by messaging.rs + group.rs) ──

pub(crate) fn convert_file_payload(f: crate::types::FilePayload) -> keychat_app_core::FilePayload {
    keychat_app_core::FilePayload {
        category: convert_file_category(f.category),
        url: f.url,
        mime_type: f.mime_type,
        suffix: f.suffix,
        size: f.size,
        key: f.key,
        iv: f.iv,
        hash: f.hash,
        source_name: f.source_name,
        audio_duration: f.audio_duration,
        amplitude_samples: f.amplitude_samples,
    }
}

pub(crate) fn convert_file_category(
    c: crate::types::FileCategory,
) -> keychat_app_core::FileCategory {
    match c {
        crate::types::FileCategory::Image => keychat_app_core::FileCategory::Image,
        crate::types::FileCategory::Video => keychat_app_core::FileCategory::Video,
        crate::types::FileCategory::Voice => keychat_app_core::FileCategory::Voice,
        crate::types::FileCategory::Audio => keychat_app_core::FileCategory::Audio,
        crate::types::FileCategory::Document => keychat_app_core::FileCategory::Document,
        crate::types::FileCategory::Text => keychat_app_core::FileCategory::Text,
        crate::types::FileCategory::Archive => keychat_app_core::FileCategory::Archive,
        crate::types::FileCategory::Other => keychat_app_core::FileCategory::Other,
    }
}

pub(crate) fn convert_reply_to(
    r: crate::types::ReplyToPayload,
) -> keychat_app_core::ReplyToPayload {
    keychat_app_core::ReplyToPayload {
        target_event_id: r.target_event_id,
        content: r.content,
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    #[uniffi::constructor]
    pub fn new(db_path: String, db_key: String) -> Result<Self, KeychatUniError> {
        let app = std::sync::Arc::new(
            AppClient::new(db_path, db_key)
                .map_err(|e| KeychatUniError::Storage { msg: e.to_string() })?,
        );
        Ok(Self { app })
    }

    // ─── File Storage ────────────────────────────────────────────────

    /// Get the base files directory path.
    pub fn get_files_dir(&self) -> String {
        self.app.files_dir.clone()
    }

    /// Resolve a downloaded file's absolute path from the file_attachments table.
    /// Returns None if not downloaded or the file has been deleted from disk.
    pub async fn resolve_local_file(&self, msgid: String, file_hash: String) -> Option<String> {
        let inner = self.app.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        let local_path = store.get_attachment_local_path(&msgid, &file_hash).ok()??;
        let abs_path = std::path::Path::new(&self.app.files_dir).join(&local_path);
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
        let inner = self.app.inner.read().await;
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
        let inner = self.app.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .set_audio_played(&msgid, &file_hash)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("set_audio_played: {e}"),
            })
    }

    /// Check if a voice attachment has been played.
    pub async fn is_audio_played(&self, msgid: String, file_hash: String) -> bool {
        let inner = self.app.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store.is_audio_played(&msgid, &file_hash)
    }

    /// Get the files directory for a specific room.
    pub fn get_room_files_dir(&self, room_id: String) -> String {
        // Sanitize room_id to prevent path traversal
        let sanitized: String = room_id.replace(['/', '\\'], "_").replace("..", "__");
        let path = std::path::Path::new(&self.app.files_dir).join(&sanitized);
        path.to_string_lossy().to_string()
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
        let room_dir = std::path::Path::new(&self.app.files_dir).join(&room_id);
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
        let room_dir = std::path::Path::new(&self.app.files_dir).join(&room_id);
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

        let mut inner = self.app.inner.write().await;
        inner.protocol.identity = Some(result.identity);
        tracing::info!("identity created: {}", &pubkey_hex[..16]);

        let _ = self.app.identity_pubkey_hex.set(pubkey_hex.clone());

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

        let mut inner = self.app.inner.write().await;
        inner.protocol.identity = Some(identity);
        tracing::info!("identity imported: {}", &pubkey_hex[..16]);

        // Cache identity pubkey — immutable after import.
        let _ = self.app.identity_pubkey_hex.set(pubkey_hex.clone());

        Ok(pubkey_hex)
    }

    /// Return the cached identity pubkey hex, or empty string if not yet imported.
    pub(crate) fn cached_identity_pubkey(&self) -> String {
        self.app
            .identity_pubkey_hex
            .get()
            .cloned()
            .unwrap_or_default()
    }

    /// Debug: return a summary of stored state in the database + in-memory.
    pub async fn debug_state_summary(&self) -> Result<String, KeychatUniError> {
        let inner = self.app.inner.read().await;

        // In-memory state
        let mem_sessions = inner.protocol.sessions.len();
        let mem_pending_out = inner.protocol.pending_outbound.len();
        let mem_peer_map = inner.protocol.peer_nostr_to_signal.len();

        // DB state
        let store = inner
            .protocol
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
    ///
    /// Sessions are restored using `SignalParticipant::restore_persistent()` which
    /// only sets up the persistent store bundle pointing to the DB. Session records
    /// (ratchet state, chain keys) are loaded on demand by libsignal's
    /// `PersistentSessionStore::load_session()` — no prekey re-injection needed.
    pub async fn restore_sessions(&self) -> Result<u32, KeychatUniError> {
        let mut inner = self.app.inner.write().await;
        inner.protocol.restore_sessions().map_err(Into::into)
    }

    /// Call before dropping the client if another client will reopen the same DB.
    pub async fn close_storage(&self) -> Result<(), KeychatUniError> {
        let inner = self.app.inner.read().await;
        let store = inner
            .protocol
            .storage
            .lock()
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
        store.checkpoint().map_err(|e| KeychatUniError::Storage {
            msg: format!("checkpoint: {e}"),
        })?;
        Ok(())
    }

    pub async fn get_pubkey_hex(&self) -> Result<String, KeychatUniError> {
        self.app
            .identity_pubkey_hex
            .get()
            .cloned()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "no identity set".into(),
            })
    }

    pub async fn connect(&self, relay_urls: Vec<String>) -> Result<(), KeychatUniError> {
        // 1. Resolve relay URLs: parameter → DB → defaults
        let (identity, urls) = {
            let inner = self.app.inner.read().await;
            let identity =
                inner
                    .protocol
                    .identity
                    .clone()
                    .ok_or(KeychatUniError::NotInitialized {
                        msg: "call create_identity first".into(),
                    })?;

            let urls = if !relay_urls.is_empty() {
                relay_urls
            } else {
                // Try loading from DB
                let storage = inner.protocol.storage.clone();
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
            let inner = self.app.inner.read().await;
            inner.protocol.storage.clone()
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
            let storage = self.app.inner.read().await.protocol.storage.clone();
            let store = storage.lock();
            if let Ok(store) = store {
                for url in &urls {
                    let _ = store.save_relay(url);
                }
            }
        }

        // 4. Re-acquire lock to store transport and relay list
        let mut inner = self.app.inner.write().await;
        inner.protocol.transport = Some(transport);
        inner.protocol.last_relay_urls = urls;
        // Clear any stale subscription IDs from a previous connect session
        inner.protocol.subscription_ids.clear();
        Ok(())
    }

    /// Add a relay at runtime, connect to it, and persist to DB.
    pub async fn add_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        transport.add_relay_and_connect(&url).await?;

        let storage = inner.protocol.storage.clone();
        if let Ok(store) = storage.lock() {
            let _ = store.save_relay(&url);
        }
        tracing::info!("added relay: {url}");
        Ok(())
    }

    /// Remove a relay at runtime and delete from DB.
    pub async fn remove_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        transport.remove_relay(&url).await?;

        let storage = inner.protocol.storage.clone();
        if let Ok(store) = storage.lock() {
            let _ = store.delete_relay(&url);
        }
        tracing::info!("removed relay: {url}");
        Ok(())
    }

    /// Get the current relay URL list.
    pub async fn get_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        Ok(transport.get_relays().await)
    }

    /// Get only the currently connected relay URLs.
    pub async fn connected_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        Ok(transport.connected_relays().await)
    }

    /// Get relay URLs with their connection status.
    pub async fn get_relay_statuses(&self) -> Result<Vec<RelayStatusInfo>, KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
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
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        transport.reconnect().await?;
        tracing::info!("reconnected to all relays");
        Ok(())
    }

    /// Reconnect a specific relay.
    pub async fn reconnect_relay(&self, url: String) -> Result<(), KeychatUniError> {
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
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
        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
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
        // Stop event loop, reconnect loop, take transport — all under single write lock
        let (transport, event_loop_tx, reconnect_tx) = {
            let mut inner = self.app.inner.write().await;
            // Clear subscription IDs — they belong to the old transport
            inner.protocol.subscription_ids.clear();
            (
                inner.protocol.transport.take(),
                inner.event_loop_stop.take(),
                inner.reconnect_stop.take(),
            )
        };
        if let Some(tx) = event_loop_tx {
            let _ = tx.send(true);
        }
        if let Some(tx) = reconnect_tx {
            let _ = tx.send(true);
        }
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
        self.app.remove_identity().await.map_err(Into::into)
    }

    pub async fn remove_room(&self, room_id: String) -> Result<(), KeychatUniError> {
        self.app.remove_room(room_id).await.map_err(Into::into)
    }

    pub async fn remove_session(&self, peer_pubkey: String) -> Result<(), KeychatUniError> {
        self.app
            .remove_session(peer_pubkey)
            .await
            .map_err(Into::into)
    }

    /// Register an event listener for receiving async events from the event loop.
    pub async fn set_event_listener(&self, listener: Box<dyn EventListener>) {
        let mut inner = self.app.inner.write().await;
        inner.event_listener = Some(Box::new(EventListenerBridge(listener)));
    }

    pub async fn set_data_listener(&self, listener: Box<dyn DataListener>) {
        let mut inner = self.app.inner.write().await;
        inner.data_listener = Some(Box::new(DataListenerBridge(listener)));
    }
}
