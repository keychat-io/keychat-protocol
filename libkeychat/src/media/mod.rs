//! Media encryption, upload, and message format helpers.
//!
//! Implements Keychat-compatible media flow:
//! 1. PKCS7-pad file bytes
//! 2. AES-256-CTR encrypt with random key + IV
//! 3. Upload encrypted blob to media relay (S3 relay or Blossom)
//! 4. Build media URL with query params for Signal-encrypted transmission

pub mod types;

use std::time::Duration;

use aes::cipher::{KeyIvInit, StreamCipher};
use base64::Engine;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{KeychatError, Result};
use crate::identity::{generate_random_nostr_keypair, NostrKeypair};
use crate::nostr::NostrEvent;
use types::{FileEncryptResult, MediaUrlInfo, MsgFileInfo};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const AES_BLOCK_SIZE: usize = 16;
const DEFAULT_MEDIA_SERVER: &str = "https://relay.keychat.io";

#[derive(Debug, Deserialize)]
struct S3ObjectCreateResponse {
    url: String,
    headers: std::collections::BTreeMap<String, String>,
    access_url: String,
}

#[derive(Debug, Deserialize)]
struct BlossomUploadResponse {
    url: String,
    #[allow(dead_code)]
    size: Option<usize>,
}

#[derive(Debug, Serialize)]
struct S3ObjectCreateRequest<'a> {
    cashu: &'a str,
    length: usize,
    sha256: &'a str,
}

fn pad_pkcs7(plaintext: &[u8]) -> Vec<u8> {
    let pad_len = AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
    let mut out = Vec::with_capacity(plaintext.len() + pad_len);
    out.extend_from_slice(plaintext);
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

fn unpad_pkcs7(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.is_empty() {
        return Err(KeychatError::InvalidArgument(
            "invalid PKCS7: empty input".to_owned(),
        ));
    }

    let pad_len = *padded
        .last()
        .ok_or_else(|| KeychatError::InvalidArgument("invalid PKCS7: missing tail".to_owned()))?
        as usize;

    if pad_len == 0 || pad_len > AES_BLOCK_SIZE || pad_len > padded.len() {
        return Err(KeychatError::InvalidArgument(
            "invalid PKCS7: invalid pad length".to_owned(),
        ));
    }

    let pad_start = padded.len() - pad_len;
    if !padded[pad_start..].iter().all(|b| *b as usize == pad_len) {
        return Err(KeychatError::InvalidArgument(
            "invalid PKCS7: bad pad bytes".to_owned(),
        ));
    }

    Ok(padded[..pad_start].to_vec())
}

/// Encrypt a file with AES-256-CTR.
///
/// Returns ciphertext, base64-encoded key/IV, and base64-encoded SHA-256 hash
/// of ciphertext.
pub fn encrypt_file(plaintext: &[u8]) -> Result<FileEncryptResult> {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut iv);

    let mut ciphertext = pad_pkcs7(plaintext);
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut ciphertext);

    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&ciphertext));

    Ok(FileEncryptResult {
        ciphertext,
        key: base64::engine::general_purpose::STANDARD.encode(key),
        iv: base64::engine::general_purpose::STANDARD.encode(iv),
        hash,
    })
}

/// Decrypt an AES-256-CTR encrypted file.
///
/// `key_base64` and `iv_base64` must be standard-base64 encoded.
pub fn decrypt_file(ciphertext: &[u8], key_base64: &str, iv_base64: &str) -> Result<Vec<u8>> {
    let key_vec = base64::engine::general_purpose::STANDARD.decode(key_base64)?;
    let iv_vec = base64::engine::general_purpose::STANDARD.decode(iv_base64)?;

    let key_len = key_vec.len();
    let key_bytes: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| KeychatError::InvalidLength {
            expected: 32,
            actual: key_len,
        })?;

    let iv_len = iv_vec.len();
    let iv_bytes: [u8; 16] = iv_vec.try_into().map_err(|_| KeychatError::InvalidLength {
        expected: 16,
        actual: iv_len,
    })?;

    let mut padded = ciphertext.to_vec();
    let mut cipher = Aes256Ctr::new(&key_bytes.into(), &iv_bytes.into());
    cipher.apply_keystream(&mut padded);

    unpad_pkcs7(&padded)
}

/// Build a NIP-98 authorization header for Blossom upload.
///
/// Creates a kind:24242 event signed by an ephemeral keypair,
/// containing the file hash and expiration.
pub fn build_blossom_auth(file_hash: &str, expiration_unix: u64) -> Result<String> {
    let ephemeral = generate_random_nostr_keypair();

    let event = NostrEvent::new_unsigned(
        ephemeral.public_key_hex(),
        24242,
        vec![
            vec!["t".to_owned(), "upload".to_owned()],
            vec!["x".to_owned(), file_hash.to_owned()],
            vec!["expiration".to_owned(), expiration_unix.to_string()],
        ],
        file_hash.to_owned(),
        crate::nostr::now(),
    )
    .sign(&ephemeral)?;

    let event_json = serde_json::to_string(&event)
        .map_err(|e| KeychatError::Nostr(format!("serialize auth event: {e}")))?;

    Ok(format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event_json.as_bytes())
    ))
}

/// Build a `MsgFileInfo` from upload results.
pub fn build_file_info(
    url: &str,
    encrypt_result: &FileEncryptResult,
    suffix: &str,
    media_type: &str,
) -> MsgFileInfo {
    MsgFileInfo {
        url: url.to_owned(),
        key: encrypt_result.key.clone(),
        iv: encrypt_result.iv.clone(),
        hash: encrypt_result.hash.clone(),
        size: encrypt_result.ciphertext.len(),
        suffix: suffix.to_owned(),
        media_type: media_type.to_owned(),
        source_name: None,
    }
}

/// Build Keychat media URL format with query params.
pub fn build_media_url(
    base_url: &str,
    encrypt_result: &FileEncryptResult,
    suffix: &str,
    media_type: &str,
    source_name: &str,
) -> String {
    if let Ok(mut url) = Url::parse(base_url) {
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("kctype", media_type);
            qp.append_pair("suffix", suffix);
            qp.append_pair("key", &encrypt_result.key);
            qp.append_pair("iv", &encrypt_result.iv);
            qp.append_pair("size", &encrypt_result.ciphertext.len().to_string());
            qp.append_pair("hash", &encrypt_result.hash);
            if !source_name.is_empty() {
                qp.append_pair("sourceName", source_name);
            }
        }
        return url.into();
    }

    let joiner = if base_url.contains('?') { "&" } else { "?" };
    format!(
        "{base_url}{joiner}kctype={media_type}&suffix={suffix}&key={}&iv={}&size={}&hash={}&sourceName={source_name}",
        encrypt_result.key,
        encrypt_result.iv,
        encrypt_result.ciphertext.len(),
        encrypt_result.hash,
    )
}

/// Parse Keychat media URL format from a message string.
pub fn parse_media_url(url: &str) -> Option<MediaUrlInfo> {
    let parsed = Url::parse(url).ok()?;

    let mut kctype: Option<String> = None;
    let mut suffix: Option<String> = None;
    let mut key: Option<String> = None;
    let mut iv: Option<String> = None;
    let mut size: Option<usize> = None;
    let mut hash: Option<String> = None;
    let mut source_name: Option<String> = None;

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "kctype" => kctype = Some(v.into_owned()),
            "suffix" => suffix = Some(v.into_owned()),
            "key" => key = Some(v.into_owned()),
            "iv" => iv = Some(v.into_owned()),
            "size" => size = v.parse::<usize>().ok(),
            "hash" => hash = Some(v.into_owned()),
            "sourceName" => source_name = Some(v.into_owned()),
            _ => {}
        }
    }

    let mut base = parsed;
    base.set_query(None);
    base.set_fragment(None);

    Some(MediaUrlInfo {
        url: base.to_string(),
        kctype: kctype?,
        suffix: suffix?,
        key: key?,
        iv: iv?,
        size: size?,
        hash,
        source_name,
    })
}

/// Detect if a server is Keychat S3 relay (`/api/v1/info` has `maxsize`).
pub async fn is_s3_relay(server: &str) -> bool {
    let server = server.trim_end_matches('/');
    let url = format!("{server}/api/v1/info");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };

    let value = match resp.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(_) => return false,
    };

    value.get("maxsize").is_some()
}

/// Upload encrypted bytes to Keychat S3 relay.
pub async fn upload_to_s3_relay(
    encrypted: &[u8],
    hash_base64: &str,
    server: Option<&str>,
) -> Result<String> {
    let server = server.unwrap_or(DEFAULT_MEDIA_SERVER).trim_end_matches('/');
    let client = reqwest::Client::new();

    let create_url = format!("{server}/api/v1/object");
    let create_req = S3ObjectCreateRequest {
        cashu: "",
        length: encrypted.len(),
        sha256: hash_base64,
    };

    let create_resp = client
        .post(create_url)
        .json(&create_req)
        .send()
        .await
        .map_err(|e| KeychatError::Nostr(format!("s3 create object request failed: {e}")))?
        .error_for_status()
        .map_err(|e| KeychatError::Nostr(format!("s3 create object response error: {e}")))?
        .json::<S3ObjectCreateResponse>()
        .await
        .map_err(|e| KeychatError::Nostr(format!("s3 create object parse failed: {e}")))?;

    let mut headers = HeaderMap::new();
    for (k, v) in create_resp.headers {
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
            KeychatError::InvalidArgument(format!("invalid header name '{k}': {e}"))
        })?;
        let value = HeaderValue::from_str(&v).map_err(|e| {
            KeychatError::InvalidArgument(format!("invalid header value for '{k}': {e}"))
        })?;
        headers.insert(name, value);
    }
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    client
        .put(create_resp.url)
        .headers(headers)
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(|e| KeychatError::Nostr(format!("s3 upload request failed: {e}")))?
        .error_for_status()
        .map_err(|e| KeychatError::Nostr(format!("s3 upload response error: {e}")))?;

    Ok(create_resp.access_url)
}

/// Upload encrypted bytes to Blossom server using a NIP-98 auth header.
pub async fn upload_to_blossom(
    encrypted: &[u8],
    auth_header: &str,
    server: Option<&str>,
) -> Result<String> {
    let server = server.unwrap_or(DEFAULT_MEDIA_SERVER).trim_end_matches('/');
    let upload_url = format!("{server}/upload");

    let client = reqwest::Client::new();
    let resp = client
        .put(upload_url)
        .header("Authorization", auth_header)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(|e| KeychatError::Nostr(format!("blossom upload request failed: {e}")))?
        .error_for_status()
        .map_err(|e| KeychatError::Nostr(format!("blossom upload response error: {e}")))?
        .json::<BlossomUploadResponse>()
        .await
        .map_err(|e| KeychatError::Nostr(format!("blossom upload parse failed: {e}")))?;

    Ok(resp.url)
}

/// Encrypt file bytes and upload to media server.
///
/// Returns full Keychat media URL string with query params.
pub async fn encrypt_and_upload(
    file_bytes: &[u8],
    suffix: &str,
    source_name: &str,
    _nostr_keypair: &NostrKeypair,
    server: Option<&str>,
) -> Result<String> {
    let encrypted = encrypt_file(file_bytes)?;
    let server_url = server.unwrap_or(DEFAULT_MEDIA_SERVER);

    let uploaded_url = if is_s3_relay(server_url).await {
        match upload_to_s3_relay(&encrypted.ciphertext, &encrypted.hash, Some(server_url)).await {
            Ok(url) => url,
            Err(_) => {
                let expiration = crate::nostr::now().saturating_add(3600);
                let auth = build_blossom_auth(&encrypted.hash_hex()?, expiration)?;
                upload_to_blossom(&encrypted.ciphertext, &auth, Some(server_url)).await?
            }
        }
    } else {
        let expiration = crate::nostr::now().saturating_add(3600);
        let auth = build_blossom_auth(&encrypted.hash_hex()?, expiration)?;
        upload_to_blossom(&encrypted.ciphertext, &auth, Some(server_url)).await?
    };

    Ok(build_media_url(
        &uploaded_url,
        &encrypted,
        suffix,
        types::media_types::FILE,
        source_name,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, Keychat media!";
        let result = encrypt_file(plaintext).unwrap();

        assert_ne!(&result.ciphertext, plaintext);
        assert_eq!(result.key.len(), 44); // 32 bytes base64
        assert_eq!(result.iv.len(), 24); // 16 bytes base64

        let decrypted = decrypt_file(&result.ciphertext, &result.key, &result.iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_correct_hash() {
        let plaintext = b"test data for hashing";
        let result = encrypt_file(plaintext).unwrap();

        let expected_hash =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&result.ciphertext));
        assert_eq!(result.hash, expected_hash);
    }

    #[test]
    fn different_encryptions_produce_different_output() {
        let plaintext = b"same data";
        let r1 = encrypt_file(plaintext).unwrap();
        let r2 = encrypt_file(plaintext).unwrap();

        assert_ne!(r1.key, r2.key);
        assert_ne!(r1.iv, r2.iv);
        assert_ne!(r1.ciphertext, r2.ciphertext);
    }

    #[test]
    fn decrypt_rejects_bad_padding() {
        let plaintext = b"pad me";
        let result = encrypt_file(plaintext).unwrap();
        let mut tampered = result.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let err = decrypt_file(&tampered, &result.key, &result.iv).unwrap_err();
        assert!(format!("{err}").contains("invalid PKCS7"));
    }

    #[test]
    fn blossom_auth_header_format() {
        let auth = build_blossom_auth("abc123", 1700000000).unwrap();
        assert!(auth.starts_with("Nostr "));
        let b64 = &auth["Nostr ".len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let event: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(event["kind"], 24242);
        assert_eq!(event["content"], "abc123");
    }

    #[test]
    fn msg_file_info_serialization() {
        let info = MsgFileInfo {
            url: "https://blossom.example.com/file.enc".into(),
            key: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".into(),
            iv: "MTIzNDU2Nzg5MDEyMzQ1Ng==".into(),
            hash: "3q2+7w==".into(),
            size: 1024,
            suffix: "jpg".into(),
            media_type: "image".into(),
            source_name: Some("photo.jpg".into()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: MsgFileInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, info.url);
        assert_eq!(parsed.key, info.key);
        assert_eq!(parsed.size, 1024);
        assert_eq!(parsed.source_name, Some("photo.jpg".into()));
    }

    #[test]
    fn build_file_info_helper() {
        let enc = encrypt_file(b"test").unwrap();
        let info = build_file_info("https://example.com/file", &enc, "png", "image");

        assert_eq!(info.url, "https://example.com/file");
        assert_eq!(info.suffix, "png");
        assert_eq!(info.media_type, "image");
        assert_eq!(info.size, enc.ciphertext.len());
    }

    #[test]
    fn media_url_roundtrip() {
        let enc = encrypt_file(b"test-image").unwrap();
        let url = build_media_url(
            "https://server.com/path/to/file",
            &enc,
            "jpg",
            "image",
            "photo.jpg",
        );

        let parsed = parse_media_url(&url).unwrap();
        assert_eq!(parsed.url, "https://server.com/path/to/file");
        assert_eq!(parsed.kctype, "image");
        assert_eq!(parsed.suffix, "jpg");
        assert_eq!(parsed.key, enc.key);
        assert_eq!(parsed.iv, enc.iv);
        assert_eq!(parsed.size, enc.ciphertext.len());
        assert_eq!(parsed.hash, Some(enc.hash));
        assert_eq!(parsed.source_name, Some("photo.jpg".to_owned()));
    }

    #[test]
    fn hash_hex_helper_matches_digest() {
        let enc = encrypt_file(b"hex-hash").unwrap();
        let expected = hex::encode(Sha256::digest(&enc.ciphertext));
        assert_eq!(enc.hash_hex().unwrap(), expected);
    }
}
