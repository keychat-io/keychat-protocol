//! keychat-app-core — shared application layer for all UI clients.
//!
//! Contains app-level persistence (rooms, messages, contacts, settings),
//! relay send tracking, and the `OrchestratorDelegate` implementation
//! that bridges protocol events to app storage and UI notifications.

pub mod app_client;
pub mod app_storage;
pub mod delegate;
pub mod event_loop;
pub mod friend_request;
pub mod group;
pub mod messaging;
pub mod relay_tracker;
pub mod types;

pub use app_client::{
    AppClient, AppClientInner, AppError, AppResult,
    default_device_id, lock_app_storage, lock_app_storage_result,
    npub_from_hex, hex_from_npub, normalize_to_hex,
};

// Re-export commonly used free functions from libkeychat
pub use libkeychat::transport::DEFAULT_RELAYS;

/// Get the default relay URLs.
pub fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// Check if a server URL uses the relay presigned-S3 protocol.
pub fn is_relay_server(server_url: String) -> bool {
    server_url
        .strip_prefix("https://")
        .or_else(|| server_url.strip_prefix("http://"))
        .map(|rest| {
            let host = rest.split('/').next().unwrap_or("");
            host == "relay.keychat.io"
        })
        .unwrap_or(false)
}

/// Get the default Blossom media server URL.
pub fn default_blossom_server() -> String {
    "https://blossom.band".to_string()
}

/// Encrypt plaintext and upload to media server (Blossom or relay-presigned).
///
/// This is a standalone utility — does not require AppClient state.
pub async fn encrypt_and_upload_routed(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<EncryptedUploadResult, AppError> {
    // Encrypt
    let encrypted = libkeychat::encrypt_file(&plaintext);

    // Upload
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| AppError::MediaTransfer(format!("HTTP client: {e}")))?;

    let resp = client
        .put(&format!("{}/upload", server_url))
        .header("Content-Type", "application/octet-stream")
        .body(encrypted.ciphertext.clone())
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("upload failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::MediaTransfer(format!("upload HTTP {status}: {body}")));
    }

    let key_hex = hex::encode(encrypted.key);
    let iv_hex = hex::encode(encrypted.iv);
    let hash_hex = hex::encode(encrypted.hash);
    let url = format!("{}/{}", server_url, hash_hex);

    Ok(EncryptedUploadResult {
        url,
        key: key_hex,
        iv: iv_hex,
        hash: hash_hex,
        size: encrypted.ciphertext.len() as u64,
    })
}

/// Result of encrypting and uploading a file.
#[derive(Clone, Debug)]
pub struct EncryptedUploadResult {
    pub url: String,
    pub key: String,
    pub iv: String,
    pub hash: String,
    pub size: u64,
}
pub use app_storage::AppStorage;
pub use relay_tracker::{RelaySendTracker, RelayStatusUpdate};
pub use types::*;
