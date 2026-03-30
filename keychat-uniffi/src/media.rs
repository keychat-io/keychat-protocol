use crate::error::KeychatUniError;
use crate::types::FileCategory;

// ─── UniFFI Record for encryption result ────────────────────────

#[derive(uniffi::Record)]
pub struct EncryptedFileResult {
    pub ciphertext: Vec<u8>,
    /// AES-256 key, hex-encoded.
    pub key: String,
    /// IV / nonce, hex-encoded.
    pub iv: String,
    /// SHA-256 hash of ciphertext, hex-encoded.
    pub hash: String,
}

// ─── Standalone functions exposed to Swift ──────────────────────

/// Encrypt file data with AES-256-CTR + PKCS7 padding.
/// Returns hex-encoded key, iv, hash for use in KCFilePayload.
#[uniffi::export]
pub fn encrypt_file_data(plaintext: Vec<u8>) -> EncryptedFileResult {
    let enc = libkeychat::encrypt_file(&plaintext);
    EncryptedFileResult {
        ciphertext: enc.ciphertext,
        key: hex::encode(enc.key),
        iv: hex::encode(enc.iv),
        hash: hex::encode(enc.hash),
    }
}

/// Decrypt file data encrypted with AES-256-CTR + PKCS7.
/// key, iv, hash are hex-encoded strings (as stored in KCFilePayload).
/// Verifies SHA-256 hash before decrypting.
#[uniffi::export]
pub fn decrypt_file_data(
    ciphertext: Vec<u8>,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, KeychatUniError> {
    let key_bytes: [u8; 32] = hex::decode(&key)
        .map_err(|e| KeychatUniError::MediaCrypto {
            msg: format!("invalid hex key: {e}"),
        })?
        .try_into()
        .map_err(|_| KeychatUniError::MediaCrypto {
            msg: "key must be 32 bytes".into(),
        })?;

    let iv_bytes: [u8; 16] = hex::decode(&iv)
        .map_err(|e| KeychatUniError::MediaCrypto {
            msg: format!("invalid hex iv: {e}"),
        })?
        .try_into()
        .map_err(|_| KeychatUniError::MediaCrypto {
            msg: "iv must be 16 bytes".into(),
        })?;

    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|e| KeychatUniError::MediaCrypto {
            msg: format!("invalid hex hash: {e}"),
        })?
        .try_into()
        .map_err(|_| KeychatUniError::MediaCrypto {
            msg: "hash must be 32 bytes".into(),
        })?;

    libkeychat::decrypt_file(&ciphertext, &key_bytes, &iv_bytes, &hash_bytes)
        .map_err(|e| KeychatUniError::MediaCrypto {
            msg: e.to_string(),
        })
}

// ─── FileCategory conversion helpers ────────────────────────────

/// Convert a reference to uniffi FileCategory to libkeychat FileCategory.
/// Used by messaging.rs when building KCFilePayload from Swift input.
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

impl From<libkeychat::FileCategory> for FileCategory {
    fn from(c: libkeychat::FileCategory) -> Self {
        match c {
            libkeychat::FileCategory::Image => FileCategory::Image,
            libkeychat::FileCategory::Video => FileCategory::Video,
            libkeychat::FileCategory::Voice => FileCategory::Voice,
            libkeychat::FileCategory::Audio => FileCategory::Audio,
            libkeychat::FileCategory::Document => FileCategory::Document,
            libkeychat::FileCategory::Text => FileCategory::Text,
            libkeychat::FileCategory::Archive => FileCategory::Archive,
            libkeychat::FileCategory::Other => FileCategory::Other,
        }
    }
}
