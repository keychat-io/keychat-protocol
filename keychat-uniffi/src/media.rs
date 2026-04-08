//! Media utilities — thin UniFFI delegation to keychat-app-core.

use crate::error::KeychatUniError;
use crate::types::FileCategory;

// Re-export constants for backward compatibility
pub use keychat_app_core::media::{
    BUILT_IN_SERVER, DEFAULT_BLOSSOM_SERVER, DEFAULT_AUTO_DOWNLOAD_LIMIT_MB,
    MAX_FILE_SIZE, MAX_FILES_PER_MESSAGE,
};

// ─── UniFFI-exported free functions ─────────────────────────────

#[uniffi::export]
pub fn is_relay_server(server_url: String) -> bool {
    keychat_app_core::is_relay_server(server_url)
}

#[uniffi::export]
pub fn local_file_name(
    source_name: Option<String>,
    hash: String,
    suffix: Option<String>,
) -> String {
    keychat_app_core::media::local_file_name(source_name, hash, suffix)
}

#[uniffi::export]
pub fn built_in_media_server() -> String {
    BUILT_IN_SERVER.to_string()
}

#[uniffi::export]
pub fn default_blossom_server() -> String {
    DEFAULT_BLOSSOM_SERVER.to_string()
}

#[uniffi::export]
pub fn default_auto_download_limit_mb() -> u64 {
    DEFAULT_AUTO_DOWNLOAD_LIMIT_MB
}

#[uniffi::export]
pub fn max_file_size() -> u64 {
    MAX_FILE_SIZE
}

#[uniffi::export]
pub fn max_files_per_message() -> u32 {
    MAX_FILES_PER_MESSAGE
}

/// Encrypt file data with AES-256-CTR.
#[uniffi::export]
pub fn encrypt_file_data(plaintext: Vec<u8>) -> EncryptedFileResult {
    let r = keychat_app_core::media::encrypt_file_data(plaintext);
    EncryptedFileResult {
        ciphertext: r.ciphertext,
        key: r.key,
        iv: r.iv,
        hash: r.hash,
    }
}

/// Decrypt file data with AES-256-CTR.
#[uniffi::export]
pub fn decrypt_file_data(
    ciphertext: Vec<u8>,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, KeychatUniError> {
    keychat_app_core::media::decrypt_file_data(ciphertext, key, iv, hash)
        .map_err(|e| KeychatUniError::MediaCrypto { msg: e.to_string() })
}

/// Sign a Blossom upload auth event.
#[uniffi::export]
pub fn sign_blossom_upload_auth(
    _secret_hex: String,
    file_hash: String,
    _server_url: String,
) -> Result<String, KeychatUniError> {
    keychat_app_core::media::sign_blossom_upload_auth(file_hash)
        .map_err(|e| KeychatUniError::Crypto { msg: e.to_string() })
}

/// Encrypt and upload to Blossom server.
#[uniffi::export(async_runtime = "tokio")]
pub async fn encrypt_and_upload(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, KeychatUniError> {
    let r = keychat_app_core::media::encrypt_and_upload(plaintext, server_url).await
        .map_err(|e| KeychatUniError::MediaTransfer { msg: e.to_string() })?;
    Ok(FileUploadResult {
        url: r.url, key: r.key, iv: r.iv, hash: r.hash, size: r.size,
    })
}

/// Encrypt and upload, routing to relay or Blossom.
#[uniffi::export(async_runtime = "tokio")]
pub async fn encrypt_and_upload_routed(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, KeychatUniError> {
    let r = keychat_app_core::media::encrypt_and_upload_routed(plaintext, server_url).await
        .map_err(|e| KeychatUniError::MediaTransfer { msg: e.to_string() })?;
    Ok(FileUploadResult {
        url: r.url, key: r.key, iv: r.iv, hash: r.hash, size: r.size,
    })
}

/// Download and decrypt from URL.
#[uniffi::export(async_runtime = "tokio")]
pub async fn download_and_decrypt(
    url: String,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, KeychatUniError> {
    keychat_app_core::media::download_and_decrypt(url, key, iv, hash).await
        .map_err(|e| KeychatUniError::MediaTransfer { msg: e.to_string() })
}

// ─── UniFFI Record Types ────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct EncryptedFileResult {
    pub ciphertext: Vec<u8>,
    pub key: String,
    pub iv: String,
    pub hash: String,
}

#[derive(uniffi::Record)]
pub struct FileUploadResult {
    pub url: String,
    pub key: String,
    pub iv: String,
    pub hash: String,
    pub size: u64,
}

// ─── FileCategory Conversion ────────────────────────────────────

pub(crate) fn file_category_to_lib(c: &FileCategory) -> libkeychat::FileCategory {
    match c {
        FileCategory::Image => libkeychat::FileCategory::Image,
        FileCategory::Video => libkeychat::FileCategory::Video,
        FileCategory::Voice => libkeychat::FileCategory::Voice,
        FileCategory::Audio => libkeychat::FileCategory::Audio,
        FileCategory::Document => libkeychat::FileCategory::Document,
        FileCategory::Text => libkeychat::FileCategory::Text,
        FileCategory::Archive => libkeychat::FileCategory::Archive,
        FileCategory::Other => libkeychat::FileCategory::Other,
    }
}

impl From<FileCategory> for libkeychat::FileCategory {
    fn from(c: FileCategory) -> Self {
        file_category_to_lib(&c)
    }
}
