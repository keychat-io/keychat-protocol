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

// ─── V1 Migration ───────────────────────────────────────

/// Migration report returned to Swift.
#[derive(uniffi::Record)]
pub struct V1MigrationResult {
    pub identities: u32,
    pub contacts: u32,
    pub rooms: u32,
    pub messages: u32,
    pub signal_sessions: u32,
    pub relays: u32,
}

/// Migrate v1 data into v1.5 encrypted databases.
///
/// Called from Swift after exporting Isar collections to JSON.
/// `isar_json`: JSON dict `{"Identity": "[...]", "Contact": "[...]", ...}`
/// `signal_db_path`: path to v1 signal_protocol.db (or empty)
/// `app_db_path`: path to new app.db
/// `app_db_key`: encryption key for app.db
/// `protocol_db_path`: path to new protocol.db
/// `protocol_db_key`: encryption key for protocol.db
#[uniffi::export]
pub fn migrate_v1_data(
    isar_json: String,
    signal_db_path: String,
    app_db_path: String,
    app_db_key: String,
    protocol_db_path: String,
    protocol_db_key: String,
) -> Result<V1MigrationResult, KeychatUniError> {
    let app_storage =
        keychat_app_core::app_storage::AppStorage::open(&app_db_path, &app_db_key)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("open app.db: {e}"),
            })?;

    let report = keychat_app_core::v1_migration::migrate_from_v1(
        &isar_json,
        &signal_db_path,
        &app_storage,
        &protocol_db_path,
        &protocol_db_key,
    )
    .map_err(|e| KeychatUniError::Storage {
        msg: format!("migration failed: {e}"),
    })?;

    Ok(V1MigrationResult {
        identities: report.identities,
        contacts: report.contacts,
        rooms: report.rooms,
        messages: report.messages,
        signal_sessions: report.signal_sessions,
        relays: report.relays,
    })
}
