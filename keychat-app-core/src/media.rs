
use crate::types::FileCategory;
use crate::app_client::AppError;

// ─── Constants ──────────────────────────────────────────────────

/// Built-in media server (Ecash-Presigned protocol).
pub const BUILT_IN_SERVER: &str = "https://relay.keychat.io";
/// Default Blossom server.
pub const DEFAULT_BLOSSOM_SERVER: &str = "https://blossom.band";
/// Auto-download limit in MB (default 20). 0 means "never auto-download".
pub const DEFAULT_AUTO_DOWNLOAD_LIMIT_MB: u64 = 20;
/// Max file size: 100 MB.
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
/// Max files per message.
pub const MAX_FILES_PER_MESSAGE: u32 = 10;

// ─── Utility functions ──────────────────────────────────────────

/// Check if a server URL uses the relay presigned-S3 protocol.
pub fn is_relay_server(server_url: String) -> bool {
    // Simple host check without pulling in the `url` crate
    server_url
        .strip_prefix("https://")
        .or_else(|| server_url.strip_prefix("http://"))
        .map(|rest| {
            let host = rest.split('/').next().unwrap_or("");
            host == "relay.keychat.io"
        })
        .unwrap_or(false)
}

/// Deterministic local file name for a payload.
/// Uses source_name if available, otherwise "{hash_prefix_12}.{suffix}".
pub fn local_file_name(
    source_name: Option<String>,
    _hash: String,
    suffix: Option<String>,
) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    if let Some(name) = source_name {
        // Split name from extension: "photo.jpg" -> ("photo", "jpg")
        if let Some(dot) = name.rfind('.') {
            let stem = &name[..dot];
            let ext = &name[dot + 1..];
            format!("{stem}_{ts}.{ext}")
        } else {
            // No extension in source_name, use suffix if available
            let ext = suffix.as_deref().unwrap_or("bin");
            format!("{name}_{ts}.{ext}")
        }
    } else {
        let ext = suffix.as_deref().unwrap_or("bin");
        format!("file_{ts}.{ext}")
    }
}

/// Return the built-in media server URL.
pub fn built_in_media_server() -> String {
    BUILT_IN_SERVER.to_string()
}

/// Return the default Blossom server URL.
pub fn default_blossom_server() -> String {
    DEFAULT_BLOSSOM_SERVER.to_string()
}

/// Return the default auto-download limit in MB.
pub fn default_auto_download_limit_mb() -> u64 {
    DEFAULT_AUTO_DOWNLOAD_LIMIT_MB
}

/// Return the max file size in bytes.
pub fn max_file_size() -> u64 {
    MAX_FILE_SIZE
}

/// Return the max files per message.
pub fn max_files_per_message() -> u32 {
    MAX_FILES_PER_MESSAGE
}

// ─── UniFFI Record for encryption result ────────────────────────

#[derive(Clone, Debug)]
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
pub fn decrypt_file_data(
    ciphertext: Vec<u8>,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, AppError> {
    let key_bytes: [u8; 32] = hex::decode(&key)
        .map_err(|e| AppError::MediaCrypto(format!("invalid hex key: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("key must be 32 bytes".into()))?;

    let iv_bytes: [u8; 16] = hex::decode(&iv)
        .map_err(|e| AppError::MediaCrypto(format!("invalid hex iv: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("iv must be 16 bytes".into()))?;

    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|e| AppError::MediaCrypto(format!("invalid hex hash: {e}")))?
        .try_into()
        .map_err(|_| AppError::MediaCrypto("hash must be 32 bytes".into()))?;

    libkeychat::decrypt_file(&ciphertext, &key_bytes, &iv_bytes, &hash_bytes)
        .map_err(|e| AppError::MediaCrypto(e.to_string(),
        ))
}

// ─── Blossom upload authorization ───────────────────────────────

/// Sign a Blossom (BUD-01) upload authorization event (kind 24242).
///
/// Uses an ephemeral secp256k1 keypair — does not expose the user's identity.
/// Returns a base64-encoded signed Nostr event JSON, ready for the
/// `Authorization: Nostr <base64>` header.
pub fn sign_blossom_upload_auth(hash: String) -> Result<String, AppError> {
    use nostr::prelude::*;

    // Ephemeral keypair — no identity leak
    let keys = Keys::generate();
    let expiration = Timestamp::now() + 30 * 24 * 3600; // 30 days

    let event = EventBuilder::new(Kind::Custom(24242), &hash)
        .tag(Tag::custom(TagKind::t(), vec!["upload"]))
        .tag(Tag::custom(TagKind::Custom("x".into()), vec![hash.clone()]))
        .tag(Tag::expiration(expiration))
        .sign_with_keys(&keys)
        .map_err(|e| AppError::Crypto(format!("Failed to sign Blossom auth event: {e}")))?;

    let json = event.as_json();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    Ok(b64)
}

// ─── Blossom upload (HTTP) ───────────────────────────────────────

/// Result of a Blossom upload, with the download URL separate from crypto metadata.
#[derive(Clone, Debug)]
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
pub async fn encrypt_and_upload(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, AppError> {
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
        .map_err(|e| AppError::MediaTransfer(format!("HTTP client error: {e}")))?;

    let resp = client
        .put(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", &auth_header)
        .body(enc.ciphertext)
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("Upload failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::MediaTransfer(format!("Upload HTTP {status}: {body}")));
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| AppError::MediaTransfer(format!("Upload response parse error: {e}")))?;

    let url = json["url"]
        .as_str()
        .ok_or_else(|| AppError::MediaTransfer("Upload response missing 'url' field".into()))?
        .to_string();

    Ok(FileUploadResult {
        url,
        key: key_hex,
        iv: iv_hex,
        hash: hash_hex,
        encrypted_size,
    })
}

// ─── Relay presigned-S3 upload ──────────────────────────────────

/// Encrypt and upload via relay presigned-S3 protocol.
/// 1. Encrypt locally
/// 2. POST to {server}/api/v1/object with cashu="", length, sha256(base64)
/// 3. PUT encrypted data to presigned URL with returned headers
/// 4. Return FileUploadResult with access_url
async fn upload_via_relay(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, AppError> {
    let enc = libkeychat::encrypt_file(&plaintext);
    let key_hex = hex::encode(enc.key);
    let iv_hex = hex::encode(enc.iv);
    let hash_hex = hex::encode(enc.hash);
    let encrypted_size = enc.ciphertext.len() as u64;

    // Convert hash to base64 for relay API
    let hash_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&enc.hash)
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| AppError::MediaTransfer(format!("HTTP client error: {e}")))?;

    // 1. Request presigned URL from relay
    let api_url = format!("{server_url}/api/v1/object");
    let params = serde_json::json!({
        "cashu": "",
        "length": encrypted_size,
        "sha256": hash_b64,
    });

    let resp = client
        .post(&api_url)
        .json(&params)
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("Relay params request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::MediaTransfer(format!("Relay params HTTP {status}: {body}")));
    }

    let json: serde_json::Value =
        resp.json().await.map_err(|e| AppError::MediaTransfer(format!("Relay params parse error: {e}")))?;

    let presigned_url = json["url"].as_str().ok_or_else(|| AppError::MediaTransfer("Missing 'url' in relay response".into()))?;
    let access_url = json["access_url"]
        .as_str()
        .ok_or_else(|| AppError::MediaTransfer("Missing 'access_url' in relay response".into()))?
        .to_string();
    let headers = json["headers"]
        .as_object()
        .ok_or_else(|| AppError::MediaTransfer("Missing 'headers' in relay response".into()))?;

    // 2. PUT encrypted data to presigned S3 URL
    let mut put_req = client.put(presigned_url);
    for (k, v) in headers {
        if let Some(val) = v.as_str() {
            put_req = put_req.header(k.as_str(), val);
        }
    }
    put_req = put_req.header("Content-Type", "multipart/form-data");

    let put_resp = put_req
        .body(enc.ciphertext)
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("S3 PUT failed: {e}")))?;

    if !put_resp.status().is_success() {
        let status = put_resp.status().as_u16();
        return Err(AppError::MediaTransfer(format!("S3 upload HTTP {status}")));
    }

    tracing::info!("Relay upload complete → {}…", &access_url[..access_url.len().min(60)]);

    Ok(FileUploadResult {
        url: access_url,
        key: key_hex,
        iv: iv_hex,
        hash: hash_hex,
        encrypted_size,
    })
}

// ─── Unified upload (routes to relay or Blossom) ────────────────

/// Encrypt and upload, routing to relay or Blossom based on server URL.
pub async fn encrypt_and_upload_routed(
    plaintext: Vec<u8>,
    server_url: String,
) -> Result<FileUploadResult, AppError> {
    if is_relay_server(server_url.clone()) {
        upload_via_relay(plaintext, server_url).await
    } else {
        encrypt_and_upload(plaintext, server_url).await
    }
}

// ─── Blossom download (HTTP) ────────────────────────────────────

/// Download ciphertext from a URL, verify hash, decrypt, and return plaintext.
///
/// Swift saves the returned bytes to local disk.
pub async fn download_and_decrypt(
    url: String,
    key: String,
    iv: String,
    hash: String,
) -> Result<Vec<u8>, AppError> {
    // 1. HTTP GET download
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| AppError::MediaTransfer(format!("HTTP client error: {e}")))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::MediaTransfer(format!("Download failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(AppError::MediaTransfer(format!("Download HTTP {status} from {url}")));
    }

    let ciphertext = resp.bytes().await.map_err(|e| AppError::MediaTransfer(format!("Download read error: {e}")))?;

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
