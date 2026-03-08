use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{KeychatError, Result};

/// Result of encrypting a file with AES-256-CTR.
#[derive(Clone, Debug)]
pub struct FileEncryptResult {
    /// Encrypted file bytes.
    pub ciphertext: Vec<u8>,
    /// AES key (base64-encoded, 32 bytes).
    pub key: String,
    /// AES IV (base64-encoded, 16 bytes).
    pub iv: String,
    /// SHA-256 hash of the ciphertext (base64-encoded).
    pub hash: String,
}

impl FileEncryptResult {
    /// Return ciphertext hash as lowercase hex string (for Blossom auth).
    pub fn hash_hex(&self) -> Result<String> {
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.hash)
            .map_err(KeychatError::Base64Decode)?;
        Ok(hex::encode(hash_bytes))
    }
}

/// Media file metadata sent within a Signal-encrypted message.
///
/// Compatible with Keychat app's `MsgFileInfo` format.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MsgFileInfo {
    /// URL of the encrypted file on the Blossom server.
    pub url: String,
    /// AES-256-CTR key (base64).
    pub key: String,
    /// AES-256-CTR IV (base64).
    pub iv: String,
    /// SHA-256 hash of the encrypted file (base64).
    pub hash: String,
    /// File size in bytes.
    pub size: usize,
    /// File extension (e.g. "jpg", "png", "mp4").
    pub suffix: String,
    /// Media type (e.g. "image", "video", "file").
    #[serde(rename = "type")]
    pub media_type: String,
    /// Original filename (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
}

/// Media URL format used by Keychat Signal messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUrlInfo {
    /// Base URL without query params.
    pub url: String,
    /// Media type (image/video/file/voiceNote).
    pub kctype: String,
    /// File extension.
    pub suffix: String,
    /// AES-256-CTR key (base64).
    pub key: String,
    /// AES-256-CTR IV (base64).
    pub iv: String,
    /// Encrypted file size in bytes.
    pub size: usize,
    /// SHA-256 hash of ciphertext (base64), optional.
    pub hash: Option<String>,
    /// Original filename, optional.
    pub source_name: Option<String>,
}

/// Media types matching Keychat app's `MessageMediaType`.
pub mod media_types {
    pub const IMAGE: &str = "image";
    pub const VIDEO: &str = "video";
    pub const FILE: &str = "file";
    pub const VOICE_NOTE: &str = "voiceNote";
}
