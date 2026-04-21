use std::sync::Arc;

use keychat_app_core::AppClient;
use libkeychat::DeviceId;

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

impl KeychatClient {
    /// Access the underlying `AppClient` for direct Rust consumers (e.g. CLI).
    pub fn app_client(&self) -> &std::sync::Arc<AppClient> {
        &self.app
    }
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

    /// Debug: show subscription state for diagnostics.
    pub async fn debug_subscription_state(&self) -> String {
        self.app.debug_subscription_state().await
    }

    /// Debug/test-only: flip a room's `session_type` back to `"x3dh"` and
    /// `peer_version` back to `1`, as if it had just come out of the v1 →
    /// v1.5 migration. Used by the UI-test harness to simulate a migrated
    /// room on a sim that actually handshook natively, so the background
    /// PQXDH auto-upgrade path can be exercised end-to-end without
    /// needing a real v1 Isar dump.
    ///
    /// Fails quietly (returns Ok) if no room matches the peer.
    pub async fn debug_downgrade_room_to_v1(
        &self,
        peer_hex: String,
    ) -> Result<(), KeychatUniError> {
        let identity_pubkey = self.app.identity_pubkey_hex.get().cloned().unwrap_or_default();
        if identity_pubkey.is_empty() {
            return Err(KeychatUniError::Storage {
                msg: "no identity loaded".into(),
            });
        }
        let room_id = format!("{peer_hex}:{identity_pubkey}");
        let inner = self.app.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        // Directly downgrade both markers back to the v1-migration baseline.
        // Bypasses the monotonic guard in `set_peer_version` on purpose —
        // this is the one case where we *want* to decrement.
        store
            .transaction(|conn| {
                conn.execute(
                    "UPDATE app_rooms SET session_type='x3dh', peer_version=1 WHERE id=?1",
                    rusqlite::params![room_id],
                )
                .map_err(|e| libkeychat::KeychatError::Storage(
                    format!("debug_downgrade_room_to_v1: {e}"),
                ))?;
                Ok(())
            })
            .map_err(|e| KeychatUniError::Storage { msg: e.to_string() })
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
        let result = self.app.create_identity().await?;
        tracing::info!("identity created: {}", &result.pubkey_hex[..16]);
        Ok(CreateIdentityResult {
            pubkey_hex: result.pubkey_hex,
            mnemonic: result.mnemonic,
        })
    }

    pub async fn import_identity(&self, mnemonic: String) -> Result<String, KeychatUniError> {
        let pubkey_hex = self.app.import_identity(mnemonic).await?;
        tracing::info!("identity imported: {}", &pubkey_hex[..16]);
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

    pub async fn debug_state_summary(&self) -> Result<String, KeychatUniError> {
        self.app.debug_state_summary().await.map_err(Into::into)
    }

    /// Restore all persisted sessions and pending friend requests from SQLCipher.
    /// Must be called after import_identity() and before connect().
    ///
    /// Sessions are restored using `SignalParticipant::restore_persistent()` which
    /// only sets up the persistent store bundle pointing to the DB. Session records
    /// (ratchet state, chain keys) are loaded on demand by libsignal's
    /// `PersistentSessionStore::load_session()` — no prekey re-injection needed.
    pub async fn restore_sessions(&self) -> Result<u32, KeychatUniError> {
        self.app.restore_sessions().await.map_err(Into::into)
    }

    /// Call before dropping the client if another client will reopen the same DB.
    pub async fn close_storage(&self) -> Result<(), KeychatUniError> {
        self.app.close_storage().await.map_err(Into::into)
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
        self.app.connect(relay_urls).await.map_err(Into::into)
    }

    pub async fn add_relay(&self, url: String) -> Result<(), KeychatUniError> {
        self.app.add_relay(url).await.map_err(Into::into)
    }

    pub async fn remove_relay(&self, url: String) -> Result<(), KeychatUniError> {
        self.app.remove_relay(url).await.map_err(Into::into)
    }

    pub async fn get_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        self.app.get_relays().await.map_err(Into::into)
    }

    pub async fn connected_relays(&self) -> Result<Vec<String>, KeychatUniError> {
        self.app.connected_relays().await.map_err(Into::into)
    }

    pub async fn get_relay_statuses(&self) -> Result<Vec<RelayStatusInfo>, KeychatUniError> {
        let statuses = self.app.get_relay_statuses().await?;
        Ok(statuses
            .into_iter()
            .map(|s| RelayStatusInfo {
                url: s.url,
                status: s.status,
            })
            .collect())
    }

    pub async fn reconnect_relays(&self) -> Result<(), KeychatUniError> {
        self.app.reconnect_relays().await.map_err(Into::into)
    }

    pub async fn reconnect_relay(&self, url: String) -> Result<(), KeychatUniError> {
        self.app.reconnect_relay(url).await.map_err(Into::into)
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
            .transport()
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
        self.app.disconnect().await.map_err(Into::into)
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
