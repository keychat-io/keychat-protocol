use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::TimeZone;
use keychat_uniffi::{ClientEvent, DataChange, DataListener, EventListener, KeychatClient};
use tokio::sync::broadcast;

const KEYRING_SERVICE: &str = "keychat-cli";
const KEYRING_ACCOUNT: &str = "db-key";
const KEY_FILE_NAME: &str = "db.key";

/// Get or create the database encryption key.
///
/// Strategy:
/// 1. Try OS keyring (macOS Keychain / Linux secret-service).
/// 2. If keyring unavailable or fails, fall back to a file at `{data_dir}/db.key`.
pub fn get_or_create_db_key(data_dir: &str) -> anyhow::Result<String> {
    // Try keyring first
    match get_or_create_via_keyring() {
        Ok(key) => {
            tracing::info!("DB key loaded from OS keyring");
            return Ok(key);
        }
        Err(e) => {
            tracing::warn!("Keyring unavailable, falling back to file: {e}");
        }
    }

    // Fallback: file-based key
    get_or_create_via_file(data_dir)
}

fn get_or_create_via_keyring() -> anyhow::Result<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
    match entry.get_password() {
        Ok(key) if !key.is_empty() => Ok(key),
        Ok(_) | Err(keyring::Error::NoEntry) => {
            let key = generate_hex_key()?;
            entry.set_password(&key)?;
            tracing::info!("Generated new DB key, stored in OS keyring");
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

fn get_or_create_via_file(data_dir: &str) -> anyhow::Result<String> {
    let key_path = Path::new(data_dir).join(KEY_FILE_NAME);

    if key_path.exists() {
        let key = fs::read_to_string(&key_path)?.trim().to_string();
        if key.len() == 64 {
            tracing::info!("DB key loaded from file: {}", key_path.display());
            return Ok(key);
        }
        tracing::warn!("Invalid key in {}, regenerating", key_path.display());
    }

    let key = generate_hex_key()?;
    fs::write(&key_path, &key)?;

    // Best-effort: restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = fs::set_permissions(&key_path, perms) {
            tracing::warn!("failed to restrict db.key permissions: {e}");
        }
    }

    tracing::info!("Generated new DB key, saved to {}", key_path.display());
    Ok(key)
}

/// Generate a random 32-byte hex string (64 hex chars).
fn generate_hex_key() -> anyhow::Result<String> {
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
        compile_error!("keychat-cli requires Unix for /dev/urandom; add a rand crate for other platforms");
    }

    Ok(bytes_to_hex(&buf))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
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
pub async fn restore_identity(client: &Arc<KeychatClient>) -> Option<String> {
    if let Ok(Some(mnemonic)) = client.get_setting(SETTING_MNEMONIC.to_string()).await {
        match client.import_identity(mnemonic).await {
            Ok(pk) => {
                tracing::info!("Identity restored from saved mnemonic: {}", &pk[..16.min(pk.len())]);
            }
            Err(e) => {
                tracing::warn!("Failed to restore identity from mnemonic: {e}");
            }
        }
    }
    client.get_pubkey_hex().await.ok()
}

/// Save mnemonic to DB so identity persists across restarts.
pub async fn save_mnemonic(client: &KeychatClient, mnemonic: &str) {
    if let Err(e) = client.set_setting(SETTING_MNEMONIC.to_string(), mnemonic.to_string()).await {
        tracing::warn!("Failed to save mnemonic: {e}");
    }
}

/// Delete saved mnemonic from DB (used on identity reset/delete).
pub async fn delete_mnemonic(client: &KeychatClient) {
    if let Err(e) = client.delete_setting(SETTING_MNEMONIC.to_string()).await {
        tracing::warn!("Failed to delete mnemonic: {e}");
    }
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

/// Restore identity, restore sessions, connect to relays, and start event loop.
/// Shared startup sequence for TUI and daemon modes.
/// Returns the pubkey hex and session count if identity was found.
pub async fn init_and_connect(client: &Arc<KeychatClient>, relay_urls: Vec<String>) -> Option<(String, u32)> {
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
    fn test_get_or_create_db_key_file_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        // First call: key file should be created
        let key1 = get_or_create_via_file(data_dir).unwrap();
        let key_path = dir.path().join(KEY_FILE_NAME);
        assert!(key_path.exists(), "key file should be created");

        // Second call: same key should be returned
        let key2 = get_or_create_via_file(data_dir).unwrap();
        assert_eq!(key1, key2, "same key should be returned on second call");
    }

    #[test]
    fn test_db_key_is_valid_hex() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        let key = get_or_create_via_file(data_dir).unwrap();

        // Should be 64 hex chars (32 bytes)
        assert_eq!(key.len(), 64, "key should be 64 hex chars");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "key should contain only hex characters"
        );
    }

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
