#![deny(clippy::await_holding_lock)]

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
mod mls_group;
mod relay_tracker;
mod types;

pub use client::KeychatClient;
pub use error::KeychatUniError;
pub use media::{
    built_in_media_server, decrypt_file_data, default_auto_download_limit_mb,
    default_blossom_server, download_and_decrypt, encrypt_and_upload, encrypt_and_upload_routed,
    encrypt_file_data, is_relay_server, local_file_name, max_file_size, max_files_per_message,
    sign_blossom_upload_auth, EncryptedFileResult, FileUploadResult,
};
pub use types::*;

uniffi::setup_scaffolding!();

// ─── Standalone utility functions exposed to Swift ──────────────────────────

use keychat_app_core::nostr::nips::nip19::{FromBech32, ToBech32};

/// Convert a hex public key to npub (bech32) format.
///
/// Example: "c002c688..." → "npub1cqq..."
#[uniffi::export]
pub fn npub_from_hex(hex: String) -> Result<String, KeychatUniError> {
    let pk =
        keychat_app_core::PublicKey::from_hex(&hex).map_err(|e| KeychatUniError::Identity {
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
    let pk =
        keychat_app_core::PublicKey::from_bech32(&npub).map_err(|e| KeychatUniError::Identity {
            msg: format!("invalid npub: {e}"),
        })?;
    Ok(pk.to_hex())
}

/// Normalize a Nostr public key: accepts both npub1... (bech32) and hex formats.
/// Returns the hex-encoded public key string.
#[uniffi::export]
pub fn normalize_to_hex(input: String) -> Result<String, KeychatUniError> {
    keychat_app_core::normalize_pubkey(&input)
        .map_err(|e| KeychatUniError::Identity { msg: e.to_string() })
}

/// Return the default relay URLs.
#[uniffi::export]
pub fn default_relays() -> Vec<String> {
    keychat_app_core::default_relays()
}
