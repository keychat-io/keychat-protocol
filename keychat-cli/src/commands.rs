use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::TimeZone;
use keychat_app_core::{
    AppClient, AppError, ClientEvent, DataChange, DataListener, EventListener, FileCategory,
    FilePayload, RoomType,
};
use tokio::sync::broadcast;

const KEY_FILE_NAME: &str = "db.key";
const KEYCHAIN_DB_KEY: &str = "db-key";

/// Get or create the database encryption key.
///
/// Strategy:
/// 1. Try system keychain (macOS Keychain / Linux keyring).
/// 2. Generate new key, store in keychain.
pub fn get_or_create_db_key(_data_dir: &str) -> anyhow::Result<String> {
    // 1. Try system keychain
    match crate::secrets::retrieve(KEYCHAIN_DB_KEY) {
        Ok(Some(key)) if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) => {
            tracing::info!("DB key loaded from system keychain");
            return Ok(key);
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("Keychain read failed: {e}"),
    }

    // 2. Generate and store in keychain
    let key = generate_hex_key()?;
    match crate::secrets::store(KEYCHAIN_DB_KEY, &key) {
        Ok(true) => {
            tracing::info!("Generated new DB key, stored in system keychain");
        }
        _ => {
            return Err(anyhow::anyhow!(
                "System keychain not available — cannot store DB key securely"
            ));
        }
    }
    Ok(key)
}

/// Generate a random 32-byte hex string (64 hex chars).
pub(crate) fn generate_hex_key() -> anyhow::Result<String> {
    let mut buf = [0u8; 32];

    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)?;
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, compile error to signal that an RNG dep is needed.
        compile_error!(
            "keychat-cli requires Unix for /dev/urandom; add a rand crate for other platforms"
        );
    }

    Ok(bytes_to_hex(&buf))
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ─── Identity Restore ───────────────────────────────────────────

pub const SETTING_MNEMONIC: &str = "identity_mnemonic";

/// Restore identity from saved mnemonic in DB. Shared by all modes.
/// Returns the pubkey hex if successful.
pub async fn restore_identity(client: &Arc<AppClient>) -> Option<String> {
    if let Ok(Some(mnemonic)) = client.get_setting(SETTING_MNEMONIC.to_string()).await {
        match client.import_identity(mnemonic).await {
            Ok(pk) => {
                tracing::info!(
                    "Identity restored from saved mnemonic: {}",
                    &pk[..16.min(pk.len())]
                );
            }
            Err(e) => {
                tracing::warn!("Failed to restore identity from mnemonic: {e}");
            }
        }
    }
    client.get_pubkey_hex().await.ok()
}

/// Save mnemonic to DB so identity persists across restarts.
pub async fn save_mnemonic(client: &AppClient, mnemonic: &str) {
    if let Err(e) = client
        .set_setting(SETTING_MNEMONIC.to_string(), mnemonic.to_string())
        .await
    {
        tracing::warn!("Failed to save mnemonic: {e}");
    }
}

/// Delete saved mnemonic from DB (used on identity reset/delete).
pub async fn delete_mnemonic(client: &AppClient) {
    if let Err(e) = client.delete_setting(SETTING_MNEMONIC.to_string()).await {
        tracing::warn!("Failed to delete mnemonic: {e}");
    }
}

// ─── Shared Business Logic ───────────────────────────────────────

/// Result of sending a message to a room (DM or group).
pub enum SendResult {
    /// DM sent successfully — event_id, relay count.
    Dm {
        event_id: String,
        relay_count: usize,
    },
    /// Signal group sent — number of events.
    Group { event_count: usize },
    /// MLS not supported.
    MlsNotSupported,
}

/// Send a text message to a room, routing to the correct API based on room type.
/// This is the single source of truth for message routing — all modes must use this.
pub async fn send_to_room(client: &AppClient, room_id: &str) -> Result<RoomType, AppError> {
    // Just resolve room type — caller handles sending with the right API
    if let Some(room) = client.get_room(room_id.to_string()).await? {
        Ok(room.room_type)
    } else {
        // Room not found in DB — assume DM (legacy behavior)
        Ok(RoomType::Dm)
    }
}

/// Send a text message to a room, handling DM vs Signal Group vs MLS routing.
pub async fn send_message(
    client: &AppClient,
    room_id: &str,
    text: &str,
) -> Result<SendResult, AppError> {
    if let Some(room) = client.get_room(room_id.to_string()).await? {
        match room.room_type {
            RoomType::SignalGroup => {
                let group_id = room.to_main_pubkey.clone();
                let result = client
                    .send_group_text(group_id, text.to_string(), None)
                    .await?;
                return Ok(SendResult::Group {
                    event_count: result.event_ids.len(),
                });
            }
            RoomType::MlsGroup | RoomType::Nip17Dm => {
                return Ok(SendResult::MlsNotSupported);
            }
            RoomType::Dm => {}
        }
    }
    // DM (or room not found — try anyway)
    let result = client
        .send_text(room_id.to_string(), text.to_string(), None, None, None)
        .await?;
    Ok(SendResult::Dm {
        event_id: result.event_id,
        relay_count: result.connected_relays.len(),
    })
}

/// Send a file message to a room, handling DM vs Signal Group vs MLS routing.
/// `files` contains pre-uploaded FilePayload items (already encrypted + uploaded to Blossom).
pub async fn send_file_message(
    client: &AppClient,
    room_id: &str,
    files: Vec<FilePayload>,
    message: Option<String>,
) -> Result<SendResult, AppError> {
    if files.is_empty() {
        return Err(AppError::InvalidArgument(
            "files list cannot be empty".into(),
        ));
    }

    if let Some(room) = client.get_room(room_id.to_string()).await? {
        match room.room_type {
            RoomType::SignalGroup => {
                let group_id = room.to_main_pubkey.clone();
                let result = client
                    .send_group_file(group_id, files, message, None)
                    .await?;
                return Ok(SendResult::Group {
                    event_count: result.event_ids.len(),
                });
            }
            RoomType::MlsGroup | RoomType::Nip17Dm => {
                return Ok(SendResult::MlsNotSupported);
            }
            RoomType::Dm => {}
        }
    }
    // DM (or room not found — try anyway)
    let result = client
        .send_file(room_id.to_string(), files, message, None)
        .await?;
    Ok(SendResult::Dm {
        event_id: result.event_id,
        relay_count: result.connected_relays.len(),
    })
}

/// Upload a local file and return the FilePayload ready for sending.
/// Reads the file, encrypts, routes upload by server type (Relay/Blossom),
/// and builds the FilePayload.
pub async fn upload_and_prepare_file(
    file_path: &Path,
    server_url: &str,
) -> Result<FilePayload, AppError> {
    let data = fs::read(file_path).map_err(|e| {
        AppError::InvalidArgument(format!("Failed to read file {}: {e}", file_path.display()))
    })?;

    let route = if keychat_app_core::is_relay_server(server_url.to_string()) {
        "relay-presigned"
    } else {
        "blossom"
    };

    let result = keychat_app_core::encrypt_and_upload_routed(data, server_url.to_string())
        .await
        .map_err(|e| {
            AppError::MediaTransfer(format!(
                "upload route={route}, server={server_url}, error={e}"
            ))
        })?;

    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let category = category_from_extension(ext);
    let mime_type = mime_from_extension(ext);

    Ok(FilePayload {
        category,
        url: result.url,
        mime_type,
        suffix: if ext.is_empty() {
            None
        } else {
            Some(ext.to_string())
        },
        size: result.size,
        key: result.key,
        iv: result.iv,
        hash: result.hash,
        source_name: file_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string()),
        audio_duration: None,
        amplitude_samples: None,
    })
}

/// Map file extension to FileCategory.
fn category_from_extension(ext: &str) -> FileCategory {
    match ext.to_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "heif" | "bmp" | "svg" => {
            FileCategory::Image
        }
        "mp4" | "mov" | "avi" | "mkv" | "webm" => FileCategory::Video,
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" => FileCategory::Audio,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => FileCategory::Document,
        "txt" | "md" | "csv" | "json" | "xml" | "yaml" | "yml" | "toml" => FileCategory::Text,
        "zip" | "tar" | "gz" | "rar" | "7z" | "bz2" => FileCategory::Archive,
        _ => FileCategory::Other,
    }
}

/// Map file extension to MIME type.
fn mime_from_extension(ext: &str) -> Option<String> {
    let mime = match ext.to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        "m4a" => "audio/mp4",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "xml" => "application/xml",
        _ => return None,
    };
    Some(mime.to_string())
}

// ─── File Message Parsing ───────────────────────────────────────

/// Parsed file item from KCMessage payload.
#[derive(Clone)]
pub struct ParsedFileItem {
    pub category: FileCategory,
    pub url: String,
    pub mime_type: Option<String>,
    pub suffix: Option<String>,
    pub size: u64,
    pub key: String,
    pub iv: String,
    pub hash: String,
    pub source_name: Option<String>,
    pub audio_duration: Option<u32>,
}

/// Parsed file message from KCMessage payloadJson.
pub struct ParsedFileMessage {
    pub message: Option<String>,
    pub items: Vec<ParsedFileItem>,
}

impl ParsedFileItem {
    /// Check if this is an image file.
    pub fn is_image(&self) -> bool {
        matches!(self.category, FileCategory::Image)
    }

    /// Check if this is a video file.
    pub fn is_video(&self) -> bool {
        matches!(self.category, FileCategory::Video)
    }

    /// Check if this is an audio/voice file.
    pub fn is_audio(&self) -> bool {
        matches!(self.category, FileCategory::Audio | FileCategory::Voice)
    }

    /// Get display name for the file.
    pub fn display_name(&self) -> String {
        self.source_name.clone().unwrap_or_else(|| {
            format!(
                "{}.{}",
                &self.hash[..12.min(self.hash.len())],
                self.suffix.as_deref().unwrap_or("bin")
            )
        })
    }

    /// Format size as human-readable string.
    pub fn size_string(&self) -> String {
        format_file_size(self.size)
    }
}

/// Parse file message from KCMessage payload JSON.
/// Returns None if the message is not a file message.
pub fn parse_file_message(payload_json: &str) -> Option<ParsedFileMessage> {
    let json: serde_json::Value = serde_json::from_str(payload_json).ok()?;

    // Accept both envelopes:
    // 1) {"kind":"files","files":{...}}
    // 2) {"files":{...}}
    // 3) direct files object {"message":...,"items":[...]}
    let files = if let Some(kind) = json.get("kind").and_then(|k| k.as_str()) {
        if kind != "files" {
            return None;
        }
        json.get("files")?
    } else {
        json.get("files").unwrap_or(&json)
    };

    // Must look like a file payload
    if files.get("items").is_none() {
        return None;
    }

    let message = files
        .get("message")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());
    let items_array = files.get("items")?.as_array()?;

    let items: Vec<ParsedFileItem> = items_array
        .iter()
        .filter_map(|item| {
            let category = match item.get("category")?.as_str()? {
                "image" => FileCategory::Image,
                "video" => FileCategory::Video,
                "voice" => FileCategory::Voice,
                "audio" => FileCategory::Audio,
                "document" => FileCategory::Document,
                "text" => FileCategory::Text,
                "archive" => FileCategory::Archive,
                _ => FileCategory::Other,
            };

            Some(ParsedFileItem {
                category,
                url: item.get("url")?.as_str()?.to_string(),
                mime_type: item
                    .get("type")
                    .or_else(|| item.get("mimeType"))
                    .or_else(|| item.get("mime_type"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string()),
                suffix: item
                    .get("suffix")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string()),
                size: item.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                key: item.get("key")?.as_str()?.to_string(),
                iv: item.get("iv")?.as_str()?.to_string(),
                hash: item.get("hash")?.as_str()?.to_string(),
                source_name: item
                    .get("sourceName")
                    .or_else(|| item.get("source_name"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string()),
                audio_duration: item
                    .get("audioDuration")
                    .or_else(|| item.get("audio_duration"))
                    .and_then(|a| a.as_u64())
                    .map(|n| n as u32),
            })
        })
        .collect();

    if items.is_empty() {
        return None;
    }

    Some(ParsedFileMessage { message, items })
}

/// Format byte size to human-readable string.
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = size as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_idx])
}

/// File info for listing files in a room.
pub struct FileInfo {
    pub msgid: String,
    pub event_id: Option<String>,
    pub sender_pubkey: String,
    pub created_at: u64,
    pub file_hash: String,
    pub source_name: String,
    pub category: FileCategory,
    pub size: u64,
    pub url: String,
    pub local_path: Option<String>,
    pub is_downloaded: bool,
}

/// Get file category icon/emoji for display.
pub fn file_category_icon(category: &FileCategory) -> &'static str {
    match category {
        FileCategory::Image => "🖼️",
        FileCategory::Video => "🎬",
        FileCategory::Voice => "🎤",
        FileCategory::Audio => "🎵",
        FileCategory::Document => "📄",
        FileCategory::Text => "📝",
        FileCategory::Archive => "📦",
        FileCategory::Other => "📎",
    }
}

/// Create identity with full persistence: save to app storage + save mnemonic.
/// Returns (pubkey_hex, npub, mnemonic).
pub async fn create_identity(
    client: &AppClient,
    display_name: &str,
) -> Result<(String, String, String), AppError> {
    let result = client.create_identity().await?;
    let npub = keychat_app_core::npub_from_hex(result.pubkey_hex.clone()).unwrap_or_default();

    // Save identity with display name to app storage
    if let Err(e) = client
        .save_app_identity(
            result.pubkey_hex.clone(),
            npub.clone(),
            display_name.to_string(),
            0,
            true,
        )
        .await
    {
        tracing::warn!("Failed to save identity name: {e}");
    }

    // Persist mnemonic for auto-restore on next startup
    save_mnemonic(client, &result.mnemonic).await;

    Ok((result.pubkey_hex, npub, result.mnemonic))
}

/// Import identity from mnemonic with full persistence.
/// Returns pubkey_hex.
pub async fn import_identity(client: &AppClient, mnemonic: &str) -> Result<String, AppError> {
    let pubkey = client.import_identity(mnemonic.to_string()).await?;
    save_mnemonic(client, mnemonic).await;

    // Restore sessions after import
    match client.restore_sessions().await {
        Ok(n) if n > 0 => tracing::info!("Restored {n} session(s) after import"),
        Err(e) => tracing::warn!("restore_sessions after import: {e}"),
        _ => {}
    }

    Ok(pubkey)
}

// ─── Shared Utilities ───────────────────────────────────────────

/// Truncate a hex key for display (first 16 chars + ellipsis).
pub fn short_key(key: &str) -> String {
    if key.len() > 16 {
        format!("{}…", &key[..16])
    } else {
        key.to_string()
    }
}

/// Format a unix timestamp as HH:MM:SS.
pub fn format_timestamp(ts: u64) -> String {
    chrono::Utc
        .timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Connect to relays and start event loop in background.
/// Shared by all modes — the single source of truth for connect + event loop.
pub fn connect_and_start(client: &Arc<AppClient>, relay_urls: Vec<String>) {
    let client_bg = Arc::clone(client);
    tokio::spawn(async move {
        tracing::info!("Connecting to {} relay(s)", relay_urls.len());
        if let Err(e) = client_bg.connect(relay_urls).await {
            tracing::warn!("Auto-connect failed: {e}");
            return;
        }
        tracing::info!("Connected to relays, starting event loop");
        if let Err(e) = client_bg.start_event_loop().await {
            tracing::error!("event loop error: {e}");
        }
    });
}

/// Restore identity, restore sessions, connect to relays, and start event loop.
/// Shared startup sequence for all modes.
/// Returns the pubkey hex and session count if identity was found.
pub async fn init_and_connect(
    client: &Arc<AppClient>,
    relay_urls: Vec<String>,
) -> Option<(String, u32)> {
    let pubkey = restore_identity(client).await?;

    let session_count = match client.restore_sessions().await {
        Ok(n) => {
            if n > 0 {
                tracing::info!("Restored {n} session(s)");
            }
            n
        }
        Err(e) => {
            tracing::warn!("restore_sessions failed: {e}");
            0
        }
    };

    connect_and_start(client, relay_urls);

    Some((pubkey, session_count))
}

// ─── Event Listener ─────────────────────────────────────────────

/// Event listener that forwards [`ClientEvent`] to a broadcast channel.
pub struct CliEventListener {
    tx: broadcast::Sender<ClientEvent>,
}

impl CliEventListener {
    pub fn new(tx: broadcast::Sender<ClientEvent>) -> Self {
        Self { tx }
    }
}

impl EventListener for CliEventListener {
    fn on_event(&self, event: ClientEvent) {
        if let Err(e) = self.tx.send(event) {
            tracing::debug!("No event subscribers: {e}");
        }
    }
}

// ─── Data Listener ──────────────────────────────────────────────

/// Data listener that forwards [`DataChange`] to a broadcast channel.
pub struct CliDataListener {
    tx: broadcast::Sender<DataChange>,
}

impl CliDataListener {
    pub fn new(tx: broadcast::Sender<DataChange>) -> Self {
        Self { tx }
    }
}

impl DataListener for CliDataListener {
    fn on_data_change(&self, change: DataChange) {
        if let Err(e) = self.tx.send(change) {
            tracing::debug!("No data subscribers: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_listener_forwards() {
        let (tx, mut rx) = broadcast::channel(16);
        let listener = CliEventListener::new(tx);

        let event = ClientEvent::EventLoopError {
            description: "test error".into(),
        };
        listener.on_event(event);

        let received = rx.try_recv().unwrap();
        match received {
            ClientEvent::EventLoopError { description } => {
                assert_eq!(description, "test error");
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[test]
    fn test_data_listener_forwards() {
        let (tx, mut rx) = broadcast::channel(16);
        let listener = CliDataListener::new(tx);

        let change = DataChange::RoomListChanged;
        listener.on_data_change(change);

        let received = rx.try_recv().unwrap();
        match received {
            DataChange::RoomListChanged => {} // expected
            _ => panic!("unexpected data change variant"),
        }
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(bytes_to_hex(&[]), "");
    }
}
