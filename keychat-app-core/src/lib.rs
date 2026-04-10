//! keychat-app-core — shared application layer for all UI clients.
//!
//! Contains app-level persistence (rooms, messages, contacts, settings),
//! relay send tracking, and business logic shared by all UI clients.

pub mod app_client;
pub mod app_storage;
pub mod data_store;
pub mod event_loop;
pub mod friend_request;
pub mod group;
pub mod media;
pub mod messaging;
pub mod relay_tracker;
pub mod types;

pub use app_client::{
    default_device_id, hex_from_npub, lock_app_storage, lock_app_storage_result, normalize_to_hex,
    npub_from_hex, AppClient, AppClientInner, AppError, AppResult,
};
pub use app_storage::AppStorage;
pub use relay_tracker::{RelaySendTracker, RelayStatusUpdate};
pub use types::*;

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

/// Re-export encrypt_and_upload_routed from media module.
pub use media::encrypt_and_upload_routed;
/// Re-export the result type.
pub use media::FileUploadResult as EncryptedUploadResult;
