//! AppClient — the shared application client for all UI consumers.
//!
//! Composes `ProtocolClient` (from libkeychat) with `AppStorage` and
//! `RelaySendTracker` to provide the full Keychat client API.
//!
//! - Swift/Kotlin use this through `keychat-uniffi::KeychatClient` (thin UniFFI wrapper)
//! - keychat-cli uses this directly (no FFI overhead, no UniFFI dependency)
//! - Lightweight agents use only `libkeychat::ProtocolClient` (skip app-core entirely)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};

use libkeychat::{
    AddressManager, ChatSession, DeviceId, EphemeralKeypair, FriendRequestState, GroupManager,
    Identity, IdentityWithMnemonic, ProtocolClient, SecureStorage, SignalParticipant, Transport,
};

use crate::app_storage::AppStorage;
use crate::relay_tracker::RelaySendTracker;
use crate::types::*;

/// Errors from the application client layer.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Identity error: {0}")]
    Identity(String),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Signal error: {0}")]
    Signal(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("MLS error: {0}")]
    Mls(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Media crypto error: {0}")]
    MediaCrypto(String),
    #[error("Media transfer error: {0}")]
    MediaTransfer(String),
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Not initialized: {0}")]
    NotInitialized(String),
}

impl From<libkeychat::KeychatError> for AppError {
    fn from(err: libkeychat::KeychatError) -> Self {
        use libkeychat::KeychatError::*;
        match err {
            InvalidMnemonic(msg) | Identity(msg) | KeyDerivation(msg) => AppError::Identity(msg),
            Transport(msg) => AppError::Transport(msg),
            Storage(msg) => AppError::Storage(msg),
            Signal(msg) | SignalEncrypt(msg) | SignalDecrypt(msg) | SignalSession(msg)
            | SignalKey(msg) | FriendRequest(msg) => AppError::Signal(msg),
            Nip44Encrypt(msg) | Nip44Decrypt(msg) | GiftWrap(msg) => AppError::Crypto(msg),
            InvalidCiphertext => AppError::Crypto("invalid ciphertext".into()),
            Mls(msg) => AppError::Mls(msg),
            MediaCrypto(msg) => AppError::MediaCrypto(msg),
            InvalidEvent(msg) | Nostr(msg) | Stamp(msg) => AppError::Signal(msg),
            Serialization(e) => AppError::Serialization(e.to_string()),
            Hex(e) => AppError::Serialization(e.to_string()),
        }
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;

// ─── Internal State ─────────────────────────────────────────────

pub struct AppClientInner {
    /// Protocol-level state: sessions, peer mappings, transport, etc.
    pub protocol: ProtocolClient,
    /// App-layer SQLCipher database (rooms, messages, contacts, settings).
    pub app_storage: Arc<Mutex<AppStorage>>,
    pub event_listener: Option<Box<dyn EventListener>>,
    pub data_listener: Option<Box<dyn DataListener>>,
    pub event_loop_stop: Option<tokio::sync::watch::Sender<bool>>,
    pub reconnect_stop: Option<tokio::sync::watch::Sender<bool>>,
}

/// Lock app_storage Mutex, recovering from poison.
pub fn lock_app_storage(
    mutex: &Mutex<AppStorage>,
) -> std::sync::MutexGuard<'_, AppStorage> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!("app_storage Mutex poisoned, recovering: {e}");
        e.into_inner()
    })
}

/// Lock app_storage Mutex, returning Result for error propagation.
pub fn lock_app_storage_result(
    mutex: &Mutex<AppStorage>,
) -> AppResult<std::sync::MutexGuard<'_, AppStorage>> {
    mutex.lock().map_err(|e| AppError::Storage(format!("app_storage lock: {e}")))
}

/// Default Signal device ID.
pub fn default_device_id() -> DeviceId {
    DeviceId::new(1).expect("device_id 1 is always valid")
}

static TRACING_INIT: Once = Once::new();

// ─── AppClient ──────────────────────────────────────────────────

/// The shared application client — used by CLI, daemon, TUI, and (via UniFFI wrapper) mobile apps.
pub struct AppClient {
    pub inner: tokio::sync::RwLock<AppClientInner>,
    pub runtime: Arc<tokio::runtime::Runtime>,
    pub db_path: String,
    /// Base directory for file storage: {app_support}/files/
    pub files_dir: String,
    pub relay_tracker: Mutex<RelaySendTracker>,
    /// Cached identity pubkey hex — set once in import_identity(), never changes.
    pub identity_pubkey_hex: tokio::sync::OnceCell<String>,
}

impl AppClient {
    /// Create a new AppClient with encrypted storage at the given path.
    pub fn new(db_path: String, db_key: String) -> AppResult<Self> {
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
                .without_time()
                .try_init();
        });

        let storage = SecureStorage::open(&db_path, &db_key)?;

        let app_db_path = if db_path.ends_with(".db") {
            db_path.replace(".db", "_app.db")
        } else {
            format!("{}_app", db_path)
        };
        let app_storage =
            AppStorage::open(&app_db_path, &db_key).map_err(|e| AppError::Storage(format!("open app database: {e}")))?;

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
            .map_err(|e| AppError::Transport(e.to_string()))?;

        let protocol_storage = Arc::new(Mutex::new(storage));
        Ok(Self {
            inner: tokio::sync::RwLock::new(AppClientInner {
                protocol: ProtocolClient::new(protocol_storage),
                app_storage: Arc::new(Mutex::new(app_storage)),
                event_listener: None,
                data_listener: None,
                event_loop_stop: None,
                reconnect_stop: None,
            }),
            runtime: Arc::new(runtime),
            db_path,
            files_dir,
            relay_tracker: Mutex::new(RelaySendTracker::new()),
            identity_pubkey_hex: tokio::sync::OnceCell::new(),
        })
    }

    /// Get the cached identity pubkey hex.
    pub(crate) fn cached_identity_pubkey(&self) -> String {
        self.identity_pubkey_hex
            .get()
            .cloned()
            .unwrap_or_default()
    }

    // ─── Identity ───────────────────────────────────────────────

    pub async fn create_identity(&self) -> AppResult<CreateIdentityResult> {
        let result = Identity::generate()?;
        let pubkey_hex = result.identity.pubkey_hex();
        let mnemonic = result.mnemonic.clone();

        let mut inner = self.inner.write().await;
        inner.protocol.identity = Some(result.identity);

        let _ = self.identity_pubkey_hex.set(pubkey_hex.clone());

        Ok(CreateIdentityResult { pubkey_hex, mnemonic })
    }

    pub async fn import_identity(&self, mnemonic: String) -> AppResult<String> {
        let identity = Identity::from_mnemonic_str(&mnemonic)?;
        let pubkey_hex = identity.pubkey_hex();

        let mut inner = self.inner.write().await;
        inner.protocol.identity = Some(identity);

        let _ = self.identity_pubkey_hex.set(pubkey_hex.clone());
        Ok(pubkey_hex)
    }

    pub async fn get_pubkey_hex(&self) -> AppResult<String> {
        self.identity_pubkey_hex
            .get()
            .cloned()
            .ok_or(AppError::NotInitialized("no identity set".into()))
    }

    // ─── Session Restore & Storage ──────────────────────────────

    pub async fn restore_sessions(&self) -> AppResult<u32> {
        let mut inner = self.inner.write().await;
        inner.protocol.restore_sessions().map_err(Into::into)
    }

    pub async fn close_storage(&self) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = inner.protocol.storage.lock()
            .map_err(|e| AppError::Storage(format!("storage lock: {e}")))?;
        store.checkpoint().map_err(|e| AppError::Storage(format!("checkpoint: {e}")))?;
        Ok(())
    }

    // ─── Relay Connection ───────────────────────────────────────

    pub async fn connect(&self, relay_urls: Vec<String>) -> AppResult<()> {
        let mut inner = self.inner.write().await;
        inner.protocol.connect(relay_urls).await.map_err(Into::into)
    }

    pub async fn disconnect(&self) -> AppResult<()> {
        tracing::info!("disconnecting from relays");
        let (event_loop_tx, reconnect_tx) = {
            let mut inner = self.inner.write().await;
            (inner.event_loop_stop.take(), inner.reconnect_stop.take())
        };
        if let Some(tx) = event_loop_tx {
            let _ = tx.send(true);
        }
        if let Some(tx) = reconnect_tx {
            let _ = tx.send(true);
        }
        let mut inner = self.inner.write().await;
        inner.protocol.disconnect().await.map_err(Into::into)
    }

    pub async fn add_relay(&self, url: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        inner.protocol.add_relay(&url).await.map_err(Into::into)
    }

    pub async fn remove_relay(&self, url: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        inner.protocol.remove_relay(&url).await.map_err(Into::into)
    }

    pub async fn get_relays(&self) -> AppResult<Vec<String>> {
        let inner = self.inner.read().await;
        inner.protocol.get_relays().await.map_err(Into::into)
    }

    pub async fn connected_relays(&self) -> AppResult<Vec<String>> {
        let inner = self.inner.read().await;
        inner.protocol.connected_relays().await.map_err(Into::into)
    }

    pub async fn get_relay_statuses(&self) -> AppResult<Vec<RelayStatusInfo>> {
        let inner = self.inner.read().await;
        let statuses = inner.protocol.get_relay_statuses().await?;
        Ok(statuses
            .into_iter()
            .map(|(url, status)| RelayStatusInfo { url, status })
            .collect())
    }

    pub async fn reconnect_relays(&self) -> AppResult<()> {
        let inner = self.inner.read().await;
        inner.protocol.reconnect_relays().await.map_err(Into::into)
    }

    // ─── Listeners ──────────────────────────────────────────────

    pub async fn set_event_listener(&self, listener: Box<dyn EventListener>) {
        let mut inner = self.inner.write().await;
        inner.event_listener = Some(listener);
    }

    pub async fn set_data_listener(&self, listener: Box<dyn DataListener>) {
        let mut inner = self.inner.write().await;
        inner.data_listener = Some(listener);
    }

    pub async fn stop_event_loop(&self) {
        let tx = {
            let mut inner = self.inner.write().await;
            inner.event_loop_stop.take()
        };
        if let Some(tx) = tx {
            let _ = tx.send(true);
        }
    }

    // ─── Address Queries ────────────────────────────────────────

    pub async fn get_all_receiving_addresses(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner.protocol.get_all_receiving_addresses().await
    }

    // ─── File Storage ───────────────────────────────────────────

    pub fn get_files_dir(&self) -> String {
        self.files_dir.clone()
    }

    pub fn get_room_files_dir(&self, room_id: String) -> String {
        format!("{}/{}", self.files_dir, room_id)
    }

    // ─── Data Store Queries ─────────────────────────────────────

    pub async fn get_rooms(&self, identity_pubkey: String) -> AppResult<Vec<RoomInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store.get_app_rooms(&identity_pubkey)
            .map_err(|e| AppError::Storage(format!("get_rooms: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| RoomInfo {
                id: r.id,
                to_main_pubkey: r.to_main_pubkey,
                identity_pubkey: r.identity_pubkey,
                status: RoomStatus::from_i32(r.status),
                room_type: RoomType::from_i32(r.room_type),
                name: r.name,
                avatar: r.avatar,
                peer_signal_identity_key: r.peer_signal_identity_key,
                parent_room_id: r.parent_room_id,
                last_message_content: r.last_message_content,
                last_message_at: r.last_message_at,
                unread_count: r.unread_count,
                created_at: r.created_at,
            })
            .collect())
    }

    pub async fn get_messages(
        &self,
        room_id: String,
        limit: i32,
        offset: i32,
    ) -> AppResult<Vec<MessageInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store.get_app_messages(&room_id, limit, offset)
            .map_err(|e| AppError::Storage(format!("get_messages: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| MessageInfo {
                msgid: r.msgid,
                event_id: r.event_id,
                room_id: r.room_id,
                identity_pubkey: r.identity_pubkey,
                sender_pubkey: r.sender_pubkey,
                content: r.content,
                is_me_send: r.is_me_send,
                is_read: r.is_read,
                status: MessageStatus::from_i32(r.status),
                reply_to_event_id: r.reply_to_event_id,
                reply_to_content: r.reply_to_content,
                payload_json: r.payload_json,
                nostr_event_json: r.nostr_event_json,
                relay_status_json: r.relay_status_json,
                local_file_path: r.local_file_path,
                local_meta: r.local_meta,
                created_at: r.created_at,
            })
            .collect())
    }

    pub async fn get_contacts(
        &self,
        identity_pubkey: String,
    ) -> AppResult<Vec<ContactInfoFull>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store.get_app_contacts(&identity_pubkey)
            .map_err(|e| AppError::Storage(format!("get_contacts: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| ContactInfoFull {
                pubkey: r.pubkey,
                npubkey: r.npubkey,
                identity_pubkey: r.identity_pubkey,
                petname: r.petname,
                name: r.name,
                avatar: r.avatar,
            })
            .collect())
    }

    pub async fn get_setting(&self, key: String) -> AppResult<Option<String>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store.get_setting(&key)
            .map_err(|e| AppError::Storage(format!("get_setting: {e}")))
    }

    pub async fn set_setting(&self, key: String, value: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store.set_setting(&key, &value)
            .map_err(|e| AppError::Storage(format!("set_setting: {e}")))
    }

    pub async fn get_identities(&self) -> AppResult<Vec<IdentityInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store.get_app_identities()
            .map_err(|e| AppError::Storage(format!("get_identities: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| IdentityInfo {
                npub: r.npub,
                nostr_pubkey_hex: r.nostr_pubkey_hex,
                name: r.name,
                avatar: r.avatar,
                idx: r.idx,
                is_default: r.is_default,
                created_at: r.created_at,
            })
            .collect())
    }

    pub async fn mark_room_read(&self, room_id: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store.mark_app_messages_read(&room_id)
            .map_err(|e| AppError::Storage(format!("mark_messages_read: {e}")))?;
        store.clear_app_room_unread(&room_id)
            .map_err(|e| AppError::Storage(format!("clear_unread: {e}")))?;
        Ok(())
    }

    pub async fn get_message_count(&self, room_id: String) -> AppResult<i32> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store.get_app_message_count(&room_id)
            .map_err(|e| AppError::Storage(format!("get_message_count: {e}")))
    }

    // ─── Event Emission Helpers ─────────────────────────────────

    pub(crate) async fn emit_event(&self, event: ClientEvent) {
        let inner = self.inner.read().await;
        if let Some(listener) = &inner.event_listener {
            listener.on_event(event);
        }
    }

    pub(crate) async fn emit_data_change(&self, change: DataChange) {
        let inner = self.inner.read().await;
        if let Some(listener) = &inner.data_listener {
            listener.on_data_change(change);
        }
    }

    // ─── Debug ──────────────────────────────────────────────────

    pub async fn debug_state_summary(&self) -> AppResult<String> {
        let inner = self.inner.read().await;
        let sessions = inner.protocol.sessions.len();
        let peers = inner.protocol.peer_nostr_to_signal.len();
        let addrs = inner.protocol.receiving_addr_to_peer.len();
        let pending = inner.protocol.pending_outbound.len();
        let groups = inner.protocol.group_manager.group_count();
        let transport = if inner.protocol.transport.is_some() { "connected" } else { "none" };
        let identity = inner.protocol.identity.as_ref()
            .map(|i| format!("{}…", &i.pubkey_hex()[..16]))
            .unwrap_or("none".into());
        Ok(format!(
            "identity={identity} transport={transport} sessions={sessions} peers={peers} \
             addrs={addrs} pending_fr={pending} groups={groups}"
        ))
    }
}
