mod address;
pub(crate) mod app_storage;
mod client;
mod data_store;
mod error;
mod event_loop;
mod friend_request;
mod group;
pub mod media;
mod messaging;
mod relay_tracker;
mod types;

pub use client::KeychatClient;
pub use error::KeychatUniError;
pub use media::{
    encrypt_and_upload, encrypt_and_upload_routed, download_and_decrypt,
    encrypt_file_data, decrypt_file_data, sign_blossom_upload_auth,
    is_relay_server, local_file_name,
    built_in_media_server, default_blossom_server, default_auto_download_limit_mb, max_file_size, max_files_per_message,
    EncryptedFileResult, FileUploadResult,
};
pub use types::*;

uniffi::setup_scaffolding!();

// ─── Standalone utility functions exposed to Swift ──────────────────────────

use nostr::nips::nip19::{FromBech32, ToBech32};

/// Convert a hex public key to npub (bech32) format.
///
/// Example: "c002c688..." → "npub1cqq..."
#[uniffi::export]
pub fn npub_from_hex(hex: String) -> Result<String, KeychatUniError> {
    let pk = libkeychat::PublicKey::from_hex(&hex).map_err(|e| KeychatUniError::Identity {
        msg: format!("invalid hex pubkey: {e}"),
    })?;
    pk.to_bech32().map_err(|e| KeychatUniError::Identity {
        msg: format!("bech32 encode failed: {e}"),
    })
}

/// Convert an npub (bech32) string to hex public key.
///
/// Example: "npub1cqq..." → "c002c688..."
#[uniffi::export]
pub fn hex_from_npub(npub: String) -> Result<String, KeychatUniError> {
    let pk = libkeychat::PublicKey::from_bech32(&npub).map_err(|e| KeychatUniError::Identity {
        msg: format!("invalid npub: {e}"),
    })?;
    Ok(pk.to_hex())
}

/// Normalize a Nostr public key: accepts both npub1... (bech32) and hex formats.
/// Returns the hex-encoded public key string.
#[uniffi::export]
pub fn normalize_to_hex(input: String) -> Result<String, KeychatUniError> {
    libkeychat::normalize_pubkey(&input)
        .map_err(|e| KeychatUniError::Identity { msg: e.to_string() })
}

/// Return the default relay URLs from libkeychat.
#[uniffi::export]
pub fn default_relays() -> Vec<String> {
    libkeychat::transport::DEFAULT_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}
