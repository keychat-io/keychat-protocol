//! AppClient — the shared application client for all UI consumers.
//!
//! ## Lock ordering (to prevent deadlock)
//!
//! 1. `inner: RwLock<AppClientInner>` — outermost
//! 2. `inner.protocol.storage: Mutex<SecureStorage>`
//! 3. `inner.app_storage: Mutex<AppStorage>`
//! 4. `inner.protocol.sessions[*]: tokio::Mutex<ChatSession>` — per-peer
//! 5. `relay_tracker: Mutex<RelaySendTracker>`
//!
//! Rules:
//! - Never hold a higher-numbered lock when acquiring a lower-numbered one.
//! - Drop `RwLock` guards before any `.await` that acquires session mutexes.
//! - Clone `Arc<Mutex<...>>` out of the `RwLock` guard, drop the guard, then lock.
//!
//! Composes `ProtocolClient` (from libkeychat) with `AppStorage` and
//! `RelaySendTracker` to provide the full Keychat client API.
//!
//! - Swift/Kotlin use this through `keychat-uniffi::KeychatClient` (thin UniFFI wrapper)
//! - keychat-cli uses this directly (no FFI overhead, no UniFFI dependency)
//! - Lightweight agents use only `libkeychat::ProtocolClient` (skip app-core entirely)

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Once};

use libkeychat::{
    AddressManager, ChatSession, DeviceId, EphemeralKeypair, FriendRequestState, GroupManager,
    Identity, IdentityWithMnemonic, ProtocolClient, SecureStorage, SignalParticipant, Transport,
};

use nostr::nips::nip19::{FromBech32, ToBech32};

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
pub fn lock_app_storage(mutex: &Mutex<AppStorage>) -> std::sync::MutexGuard<'_, AppStorage> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!("app_storage Mutex poisoned, recovering: {e}");
        e.into_inner()
    })
}

/// Lock app_storage Mutex, returning Result for error propagation.
pub fn lock_app_storage_result(
    mutex: &Mutex<AppStorage>,
) -> AppResult<std::sync::MutexGuard<'_, AppStorage>> {
    mutex
        .lock()
        .map_err(|e| AppError::Storage(format!("app_storage lock: {e}")))
}

/// Default Signal device ID.
pub fn default_device_id() -> DeviceId {
    DeviceId::new(1).expect("device_id 1 is always valid")
}

static TRACING_INIT: Once = Once::new();

/// Generate a local file name from source name or hash.
pub fn local_file_name(
    source_name: Option<String>,
    hash: String,
    suffix: Option<String>,
) -> String {
    if let Some(name) = source_name {
        // Use the original file name if provided
        name
    } else if let Some(ext) = suffix {
        format!("{}.{}", &hash[..16.min(hash.len())], ext)
    } else {
        hash[..16.min(hash.len())].to_string()
    }
}

/// Download ciphertext from URL, verify hash, decrypt.
pub async fn download_and_decrypt(
    url: String,
    key: String,
    iv: String,
    hash: String,
) -> AppResult<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| AppError::MediaTransfer(format!("HTTP client: {e}")))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("download failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::MediaTransfer(format!(
            "HTTP {} from {}",
            resp.status().as_u16(),
            url
        )));
    }

    let ciphertext = resp
        .bytes()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("read error: {e}")))?;

    let key_bytes: [u8; 32] = hex::decode(&key)
        .map_err(|e| AppError::MediaCrypto(format!("invalid key hex: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("key must be 32 bytes".into()))?;
    let iv_bytes: [u8; 16] = hex::decode(&iv)
        .map_err(|e| AppError::MediaCrypto(format!("invalid iv hex: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("iv must be 16 bytes".into()))?;
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|e| AppError::MediaCrypto(format!("invalid hash hex: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("hash must be 32 bytes".into()))?;

    libkeychat::decrypt_file(&ciphertext, &key_bytes, &iv_bytes, &hash_bytes)
        .map_err(|e| AppError::MediaCrypto(format!("decrypt: {e}")))
}

/// Convert a hex public key to npub (bech32) format.
pub fn npub_from_hex(hex: String) -> AppResult<String> {
    let pk = libkeychat::PublicKey::from_hex(&hex)
        .map_err(|e| AppError::Identity(format!("invalid hex pubkey: {e}")))?;
    pk.to_bech32()
        .map_err(|e| AppError::Identity(format!("bech32 encode failed: {e}")))
}

/// Convert an npub (bech32) string to hex public key.
pub fn hex_from_npub(npub: String) -> AppResult<String> {
    let pk = libkeychat::PublicKey::from_bech32(&npub)
        .map_err(|e| AppError::Identity(format!("invalid npub: {e}")))?;
    Ok(pk.to_hex())
}

/// Accept both npub1... and hex formats, normalize to hex.
pub fn normalize_to_hex(input: String) -> AppResult<String> {
    if input.starts_with("npub1") {
        hex_from_npub(input)
    } else {
        Ok(input)
    }
}

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
    /// MLS participant for large group operations (lazy-initialized).
    pub mls_participant: Mutex<Option<libkeychat::MlsParticipant>>,
    /// Path to the MLS storage database (file-backed OpenMLS provider).
    pub mls_db_path: String,
    /// Cached MLS signer public key (hex) — avoids try_read() race in mls_participant_guard.
    pub mls_signer_pk: Mutex<Option<String>>,
    /// MLS temp_inbox → group_id routing map (O(1) lookup on receive).
    pub mls_inbox_map: Mutex<HashMap<String, String>>,
    /// MLS group_id → current Nostr SubscriptionId (for clean unsubscribe on epoch rotation).
    pub mls_sub_ids: Mutex<HashMap<String, nostr::SubscriptionId>>,
    /// Sender half of the background PQXDH-upgrade trigger channel. Set once
    /// in `start_event_loop` after the consumer task is spawned; call sites
    /// that observe a peer_version bump push the room_id here to request an
    /// auto-upgrade from X3DH to PQXDH. `None` until the event loop starts
    /// (migration paths bumping peer_version before start just no-op).
    pub upgrade_trigger_tx:
        tokio::sync::OnceCell<tokio::sync::mpsc::UnboundedSender<String>>,
    /// Room IDs with an in-flight background upgrade FR. Prevents re-firing
    /// while a previous trigger's FR publish is still outstanding. Cleared
    /// when the spawned task completes (success or final failure), so a
    /// transiently-failed upgrade retries on the next observed v2 event.
    pub pqxdh_upgrade_inflight: Mutex<HashSet<String>>,
}

impl AppClient {
    /// Create a new AppClient with encrypted storage at the given path.
    pub fn new(db_path: String, db_key: String) -> AppResult<Self> {
        TRACING_INIT.call_once(|| {
            let level = tracing::Level::DEBUG;
            // Write tracing logs to a file so they are visible on iOS
            let log_path = {
                let mut p = std::path::PathBuf::from(&db_path);
                p.pop(); // remove db filename
                p.push("keychat_trace.log");
                p
            };
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                let _ = tracing_subscriber::fmt()
                    .with_max_level(level)
                    .with_target(true)
                    .with_thread_names(true)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .try_init();
            } else {
                let _ = tracing_subscriber::fmt()
                    .with_max_level(level)
                    .with_target(true)
                    .with_thread_names(true)
                    .without_time()
                    .try_init();
            }
        });

        let storage = SecureStorage::open(&db_path, &db_key)?;

        let app_db_path = if db_path.ends_with(".db") {
            db_path.replace(".db", "_app.db")
        } else {
            format!("{}_app", db_path)
        };
        let app_storage = AppStorage::open(&app_db_path, &db_key)
            .map_err(|e| AppError::Storage(format!("open app database: {e}")))?;

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

        let mls_db_path = {
            let db_dir = std::path::Path::new(&db_path)
                .parent()
                .unwrap_or(std::path::Path::new("."));
            db_dir.join("mls_storage.db").to_string_lossy().to_string()
        };

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
            mls_participant: Mutex::new(None),
            mls_db_path,
            mls_signer_pk: Mutex::new(None),
            mls_inbox_map: Mutex::new(HashMap::new()),
            mls_sub_ids: Mutex::new(HashMap::new()),
            upgrade_trigger_tx: tokio::sync::OnceCell::new(),
            pqxdh_upgrade_inflight: Mutex::new(HashSet::new()),
        })
    }

    /// Get the cached identity pubkey hex.
    pub(crate) fn cached_identity_pubkey(&self) -> String {
        self.identity_pubkey_hex.get().cloned().unwrap_or_default()
    }

    // ─── Identity ───────────────────────────────────────────────

    pub async fn create_identity(&self) -> AppResult<CreateIdentityResult> {
        let result = Identity::generate()?;
        let pubkey_hex = result.identity.pubkey_hex();
        let mnemonic = result.mnemonic.clone();

        let mut inner = self.inner.write().await;
        inner.protocol.set_identity(Some(result.identity));

        let _ = self.identity_pubkey_hex.set(pubkey_hex.clone());

        Ok(CreateIdentityResult {
            pubkey_hex,
            mnemonic,
        })
    }

    pub async fn import_identity(&self, mnemonic: String) -> AppResult<String> {
        let identity = Identity::from_mnemonic_str(&mnemonic)?;
        let pubkey_hex = identity.pubkey_hex();

        let mut inner = self.inner.write().await;
        inner.protocol.set_identity(Some(identity));

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
        let store = inner
            .protocol
            .storage()
            .lock()
            .map_err(|e| AppError::Storage(format!("storage lock: {e}")))?;
        store
            .checkpoint()
            .map_err(|e| AppError::Storage(format!("checkpoint: {e}")))?;
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

    pub async fn reconnect_relay(&self, url: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        inner
            .protocol
            .reconnect_relay(&url)
            .await
            .map_err(Into::into)
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
        let rows = store
            .get_app_rooms(&identity_pubkey)
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
                peer_version: r.peer_version,
                session_type: r.session_type,
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
        let rows = store
            .get_app_messages(&room_id, limit, offset)
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

    pub async fn get_contacts(&self, identity_pubkey: String) -> AppResult<Vec<ContactInfoFull>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store
            .get_app_contacts(&identity_pubkey)
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
        store
            .get_setting(&key)
            .map_err(|e| AppError::Storage(format!("get_setting: {e}")))
    }

    pub async fn set_setting(&self, key: String, value: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .set_setting(&key, &value)
            .map_err(|e| AppError::Storage(format!("set_setting: {e}")))
    }

    pub async fn get_identities(&self) -> AppResult<Vec<IdentityInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let rows = store
            .get_app_identities()
            .map_err(|e| AppError::Storage(format!("get_identities: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| IdentityInfo {
                npub: r.npub,
                nostr_pubkey_hex: r.nostr_pubkey_hex,
                name: r.name,
                avatar: r.avatar,
                index: r.idx,
                is_default: r.is_default,
                created_at: r.created_at,
            })
            .collect())
    }

    pub async fn mark_room_read(&self, room_id: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .mark_app_messages_read(&room_id)
            .map_err(|e| AppError::Storage(format!("mark_messages_read: {e}")))?;
        store
            .clear_app_room_unread(&room_id)
            .map_err(|e| AppError::Storage(format!("clear_unread: {e}")))?;
        Ok(())
    }

    pub async fn get_message_count(&self, room_id: String) -> AppResult<i32> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .get_app_message_count(&room_id)
            .map_err(|e| AppError::Storage(format!("get_message_count: {e}")))
    }

    /// Debug: print subscription state — receiving addresses and subscription IDs.
    pub async fn debug_subscription_state(&self) -> String {
        let inner = self.inner.read().await;
        let sub_ids = inner.protocol.subscription_ids();
        let addr_count = inner.protocol.receiving_addr_count();
        let (identity_pks, ratchet_pks) = inner.protocol.collect_subscribe_pubkeys().await;
        let ratchet_hex: Vec<String> = ratchet_pks
            .iter()
            .map(|pk| pk.to_hex()[..16].to_string())
            .collect();
        format!(
            "sub_ids={} addr_to_peer={} identity_pks={} ratchet_pks=[{}]",
            sub_ids.len(),
            addr_count,
            identity_pks.len(),
            ratchet_hex.join(", ")
        )
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

    // ─── Auto-Reconnect ──────────────────────────────────────────

    pub async fn enable_auto_reconnect(&self, _max_delay_secs: u32) -> AppResult<()> {
        // TODO: Implement auto-reconnect loop (was in keychat-uniffi client.rs)
        tracing::warn!("enable_auto_reconnect: not yet implemented in app-core");
        Ok(())
    }

    pub async fn disable_auto_reconnect(&self) {
        let mut inner = self.inner.write().await;
        if let Some(tx) = inner.reconnect_stop.take() {
            let _ = tx.send(true);
        }
    }

    pub async fn check_connection(&self) -> ConnectionStatus {
        let inner = self.inner.read().await;
        match inner.protocol.transport() {
            Some(t) => {
                if t.connected_relays().await.is_empty() {
                    ConnectionStatus::Disconnected
                } else {
                    ConnectionStatus::Connected
                }
            }
            None => ConnectionStatus::Disconnected,
        }
    }

    // ─── Debug ──────────────────────────────────────────────────

    pub async fn debug_state_summary(&self) -> AppResult<String> {
        let inner = self.inner.read().await;
        let sessions = inner.protocol.sessions_len();
        let peers = inner.protocol.peer_count();
        let addrs = inner.protocol.receiving_addr_count();
        let pending = inner.protocol.pending_outbound_len();
        let groups = inner.protocol.group_manager().group_count();
        let transport = if inner.protocol.has_transport() {
            "connected"
        } else {
            "none"
        };
        let identity = inner
            .protocol
            .identity()
            .map(|i| format!("{}…", &i.pubkey_hex()[..16]))
            .unwrap_or("none".into());
        Ok(format!(
            "identity={identity} transport={transport} sessions={sessions} peers={peers} \
             addrs={addrs} pending_fr={pending} groups={groups}"
        ))
    }

    // ─── Identity / Room / Session Removal ──────────────────────

    pub async fn remove_identity(&self) -> AppResult<()> {
        tracing::info!("remove_identity: clearing all data");

        // 1. Stop event loop and reconnect loop
        {
            let inner = self.inner.read().await;
            if let Some(ref stop_tx) = inner.event_loop_stop {
                let _ = stop_tx.send(true);
            }
            if let Some(ref stop_tx) = inner.reconnect_stop {
                let _ = stop_tx.send(true);
            }
        }

        // 2. Disconnect transport
        {
            let mut inner = self.inner.write().await;
            if let Some(t) = inner.protocol.take_transport() {
                let _ = t.disconnect().await;
            }
        }

        // 3. Clear all in-memory state + DB
        let storage = self.inner.read().await.protocol.storage().clone();
        {
            let mut inner = self.inner.write().await;
            inner.protocol.reset();
            inner.event_loop_stop = None;
            inner.reconnect_stop = None;
        }
        if let Ok(store) = storage.lock() {
            store
                .delete_all_data()
                .map_err(|e| AppError::Storage(format!("delete_all_data: {e}")))?;
        }
        let app_storage = self.inner.read().await.app_storage.clone();
        {
            let store = lock_app_storage(&app_storage);
            store
                .delete_all_data()
                .map_err(|e| AppError::Storage(format!("delete_all_app_data: {e}")))?;
        }

        tracing::info!("remove_identity: done");
        Ok(())
    }

    pub async fn remove_room(&self, room_id: String) -> AppResult<()> {
        let storage = self.inner.read().await.protocol.storage().clone();
        let mut found = false;

        // Try as 1:1 peer first
        {
            let mut inner = self.inner.write().await;
            if let Some(signal_id) = inner.protocol.remove_peer(&room_id) {
                drop(inner);

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
            if inner.protocol.group_manager().get_group(&room_id).is_some() {
                if let Ok(store) = storage.lock() {
                    let _ = inner
                        .protocol
                        .group_manager_mut()
                        .remove_group_persistent(&room_id, &store);
                } else {
                    inner.protocol.group_manager_mut().remove_group(&room_id);
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

        // Clean up app_* tables
        let identity_pubkey = self.cached_identity_pubkey();
        if !identity_pubkey.is_empty() {
            let app_room_id = make_room_id(&room_id, &identity_pubkey);
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

    pub async fn remove_session(&self, peer_pubkey: String) -> AppResult<()> {
        let storage = self.inner.read().await.protocol.storage().clone();

        {
            let mut inner = self.inner.write().await;
            if let Some(signal_id) = inner.protocol.remove_peer(&peer_pubkey) {
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

        let identity_pubkey = self.cached_identity_pubkey();
        if !identity_pubkey.is_empty() {
            let app_storage = self.inner.read().await.app_storage.clone();
            {
                let store = lock_app_storage(&app_storage);
                if let Err(e) = store.delete_app_contact(&peer_pubkey, &identity_pubkey) {
                    tracing::warn!("remove_session: delete_app_contact: {e}");
                }
            }
            self.emit_data_change(DataChange::ContactListChanged).await;
        }

        Ok(())
    }

    // ─── File Storage Operations ────────────────────────────────

    pub async fn resolve_local_file(&self, msgid: String, file_hash: String) -> Option<String> {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store
            .get_attachment_local_path(&msgid, &file_hash)
            .ok()
            .flatten()
            .and_then(|p| {
                if std::path::Path::new(&p).exists() {
                    Some(p)
                } else {
                    None
                }
            })
    }

    pub async fn upsert_attachment(
        &self,
        msgid: String,
        file_hash: String,
        room_id: String,
        local_path: Option<String>,
        transfer_state: u32,
    ) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store
            .upsert_attachment(
                &msgid,
                &file_hash,
                &room_id,
                local_path.as_deref(),
                transfer_state as i32,
            )
            .map_err(|e| AppError::Storage(format!("upsert_attachment: {e}")))
    }

    pub async fn set_audio_played(&self, msgid: String, file_hash: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store
            .set_audio_played(&msgid, &file_hash)
            .map_err(|e| AppError::Storage(format!("set_audio_played: {e}")))
    }

    pub async fn is_audio_played(&self, msgid: String, file_hash: String) -> bool {
        let inner = self.inner.read().await;
        let store = lock_app_storage(&inner.app_storage);
        store.is_audio_played(&msgid, &file_hash)
    }

    pub fn save_file_locally(
        &self,
        data: Vec<u8>,
        file_name: String,
        room_id: String,
    ) -> AppResult<String> {
        let dir = self.get_room_files_dir(room_id);
        std::fs::create_dir_all(&dir).map_err(|e| AppError::Storage(format!("create dir: {e}")))?;
        let path = format!("{}/{}", dir, file_name);
        std::fs::write(&path, &data).map_err(|e| AppError::Storage(format!("write file: {e}")))?;
        Ok(path)
    }

    /// Rebroadcast raw event JSON. Returns (success_urls, failed_url_error_pairs).
    pub async fn rebroadcast_event_internal(
        &self,
        event_json: &str,
    ) -> AppResult<(Vec<String>, Vec<(String, String)>)> {
        let event: nostr::Event = serde_json::from_str(event_json)
            .map_err(|e| AppError::Transport(format!("invalid event JSON: {e}")))?;
        let inner = self.inner.read().await;
        let transport = inner
            .protocol
            .transport()
            .ok_or(AppError::Transport("Not connected.".into()))?;
        let result = transport.rebroadcast_event(event).await?;
        Ok((result.success_relays, result.failed_relays))
    }

    pub async fn rebroadcast_event(&self, event_json: String) -> AppResult<PublishResultInfo> {
        let (success_relays, failed_relays) = self.rebroadcast_event_internal(&event_json).await?;
        Ok(PublishResultInfo {
            event_id: {
                let event: nostr::Event = serde_json::from_str(&event_json)
                    .map_err(|e| AppError::Transport(format!("invalid event JSON: {e}")))?;
                event.id.to_hex()
            },
            success_relays,
            failed_relays: failed_relays
                .into_iter()
                .map(|(url, error)| FailedRelayInfo { url, error })
                .collect(),
        })
    }

    // ─── Data Store Write Methods ───────────────────────────────

    pub async fn delete_setting(&self, key: String) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .delete_setting(&key)
            .map_err(|e| AppError::Storage(format!("delete_setting: {e}")))
    }

    pub async fn get_room(&self, room_id: String) -> AppResult<Option<RoomInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        match store
            .get_app_room(&room_id)
            .map_err(|e| AppError::Storage(format!("get_room: {e}")))?
        {
            Some(r) => Ok(Some(RoomInfo {
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
                peer_version: r.peer_version,
                session_type: r.session_type,
            })),
            None => Ok(None),
        }
    }

    pub async fn get_message_by_msgid(&self, msgid: String) -> AppResult<Option<MessageInfo>> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        match store
            .get_app_message_by_msgid(&msgid)
            .map_err(|e| AppError::Storage(format!("get_message: {e}")))?
        {
            Some(r) => Ok(Some(MessageInfo {
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
            })),
            None => Ok(None),
        }
    }

    pub async fn should_auto_download(&self, file_size: u64) -> AppResult<bool> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        let limit_mb = store
            .get_setting("autoDownloadLimitMB")
            .unwrap_or(None)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);
        Ok(file_size <= limit_mb * 1024 * 1024)
    }

    pub async fn get_active_media_server(&self) -> AppResult<String> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        Ok(store
            .get_setting("activeMediaServer")
            .unwrap_or(None)
            .unwrap_or_else(|| "https://blossom.keychat.io".to_string()))
    }

    pub async fn update_contact_petname(
        &self,
        pubkey: String,
        identity_pubkey: String,
        petname: String,
    ) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .update_app_contact(&pubkey, &identity_pubkey, Some(&petname), None, None)
            .map_err(|e| AppError::Storage(format!("update_petname: {e}")))
    }

    /// Get the protocol-level inbound request ID for a sender.
    /// Download, decrypt, save to disk, record in file_attachments.
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
    ) -> AppResult<String> {
        // Idempotent check
        if let Some(ref mid) = msgid {
            if let Some(abs) = self.resolve_local_file(mid.clone(), hash.clone()).await {
                return Ok(abs);
            }
        }

        let file_name = local_file_name(source_name, hash.clone(), suffix);
        let room_dir = std::path::Path::new(&self.files_dir).join(&room_id);
        let file_path = room_dir.join(&file_name);
        let relative_path = format!("{room_id}/{file_name}");

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

        std::fs::create_dir_all(&room_dir)
            .map_err(|e| AppError::MediaTransfer(format!("create dir: {e}")))?;

        let plaintext = download_and_decrypt(url, key, iv, hash.clone()).await?;

        let tmp_path = room_dir.join(format!(".{file_name}.tmp"));
        std::fs::write(&tmp_path, &plaintext)
            .map_err(|e| AppError::MediaTransfer(format!("write: {e}")))?;
        std::fs::rename(&tmp_path, &file_path)
            .map_err(|e| AppError::MediaTransfer(format!("rename: {e}")))?;

        tracing::info!("Downloaded {} ({} bytes)", file_name, plaintext.len());

        if let Some(ref mid) = msgid {
            let _ = self
                .upsert_attachment(mid.clone(), hash, room_id, Some(relative_path), 2)
                .await;
        }

        Ok(file_path.to_string_lossy().to_string())
    }

    /// Save an app identity record.
    pub async fn save_app_identity(
        &self,
        pubkey_hex: String,
        npub: String,
        name: String,
        index: i32,
        is_default: bool,
    ) -> AppResult<()> {
        let inner = self.inner.read().await;
        let store = lock_app_storage_result(&inner.app_storage)?;
        store
            .save_app_identity(&pubkey_hex, &npub, &name, index, is_default)
            .map_err(|e| AppError::Storage(format!("save_app_identity: {e}")))
    }

    pub async fn get_inbound_request_id(&self, sender_pubkey: String) -> AppResult<Option<String>> {
        let inner = self.inner.read().await;
        let store = inner
            .protocol
            .storage()
            .lock()
            .map_err(|e| AppError::Storage(format!("storage lock: {e}")))?;
        store
            .get_inbound_fr_request_id_by_sender(&sender_pubkey)
            .map_err(|e| AppError::Storage(format!("get_inbound_request_id: {e}")))
    }
}
