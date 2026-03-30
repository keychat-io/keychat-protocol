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

// ─── Blossom upload authorization ───────────────────────────────

/// Sign a Blossom (BUD-01) upload authorization event (kind 24242).
///
/// Uses an ephemeral secp256k1 keypair — does not expose the user's identity.
/// Returns a base64-encoded signed Nostr event JSON, ready for the
/// `Authorization: Nostr <base64>` header.
#[uniffi::export]
pub fn sign_blossom_upload_auth(hash: String) -> Result<String, KeychatUniError> {
    use nostr::prelude::*;

    // Ephemeral keypair — no identity leak
    let keys = Keys::generate();
    let expiration = Timestamp::now() + 30 * 24 * 3600; // 30 days

    let event = EventBuilder::new(Kind::Custom(24242), &hash)
        .tag(Tag::custom(TagKind::t(), vec!["upload"]))
        .tag(Tag::custom(TagKind::Custom("x".into()), vec![hash.clone()]))
        .tag(Tag::expiration(expiration))
        .sign_with_keys(&keys)
        .map_err(|e| KeychatUniError::Crypto {
            msg: format!("Failed to sign Blossom auth event: {e}"),
        })?;

    let json = event.as_json();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    Ok(b64)
}

// ─── Blossom upload (HTTP) ───────────────────────────────────────

/// Result of a Blossom upload, with the download URL separate from crypto metadata.
#[derive(uniffi::Record)]
pub struct FileUploadResult {
    /// Download URL from the Blossom server.
    pub url: String,
    /// AES-256 key, hex-encoded.
    pub key: String,
    /// IV / nonce, hex-encoded.
    pub iv: String,
    /// SHA-256 hash of ciphertext, hex-encoded.
    pub hash: String,
    /// Size of the encrypted ciphertext in bytes.
    pub encrypted_size: u64,
}

/// Encrypt and upload a file to a Blossom server in one call.
///
/// Returns the download URL and all encryption metadata needed for KCFilePayload.
#[uniffi::export]
pub async fn encrypt_and_upload(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, KeychatUniError> {
    // 1. Encrypt
    let enc = libkeychat::encrypt_file(&plaintext);
    let key_hex = hex::encode(enc.key);
    let iv_hex = hex::encode(enc.iv);
    let hash_hex = hex::encode(enc.hash);
    let encrypted_size = enc.ciphertext.len() as u64;

    // 2. Sign Blossom auth
    let auth_b64 = sign_blossom_upload_auth(hash_hex.clone())?;
    let auth_header = format!("Nostr {auth_b64}");

    // 3. HTTP PUT upload
    let upload_url = format!("{server_url}/upload");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("HTTP client error: {e}"),
        })?;

    let resp = client
        .put(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", &auth_header)
        .body(enc.ciphertext)
        .send()
        .await
        .map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("Upload failed: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(KeychatUniError::MediaTransfer {
            msg: format!("Upload HTTP {status}: {body}"),
        });
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| KeychatUniError::MediaTransfer {
        msg: format!("Upload response parse error: {e}"),
    })?;

    let url = json["url"]
        .as_str()
        .ok_or_else(|| KeychatUniError::MediaTransfer {
            msg: "Upload response missing 'url' field".into(),
        })?
        .to_string();

    Ok(FileUploadResult {
        url,
        key: key_hex,
        iv: iv_hex,
        hash: hash_hex,
        encrypted_size,
    })
}

// ─── Blossom download (HTTP) ────────────────────────────────────

/// Download ciphertext from a URL, verify hash, decrypt, and return plaintext.
///
/// Swift saves the returned bytes to local disk.
#[uniffi::export]
pub async fn download_and_decrypt(
    url: String,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, KeychatUniError> {
    // 1. HTTP GET download
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("HTTP client error: {e}"),
        })?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| KeychatUniError::MediaTransfer {
            msg: format!("Download failed: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(KeychatUniError::MediaTransfer {
            msg: format!("Download HTTP {status} from {url}"),
        });
    }

    let ciphertext = resp.bytes().await.map_err(|e| KeychatUniError::MediaTransfer {
        msg: format!("Download read error: {e}"),
    })?;

    // 2. Decrypt (reuse existing function — handles hash verification)
    decrypt_file_data(ciphertext.to_vec(), key, iv, hash)
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
