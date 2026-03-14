//! Media file encryption/decryption and message builders (§12).
//!
//! Implements AES-256-CTR encryption with PKCS7 padding for client-side
//! file encryption before upload, and KCMessage builders for file/voice messages.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

use crate::message::{
    FileCategory, KCFilePayload, KCFilesPayload, KCMessage, KCMessageKind,
};
use crate::Result;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ─── EncryptedFile ───────────────────────────────────────────────────────────

/// AES-256-CTR file encryption result.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Encrypted ciphertext (with PKCS7 padding).
    pub ciphertext: Vec<u8>,
    /// Random AES-256 key.
    pub key: [u8; 32],
    /// Random IV / nonce.
    pub iv: [u8; 16],
    /// SHA-256 hash of the ciphertext.
    pub hash: [u8; 32],
}

// ─── PKCS7 padding ──────────────────────────────────────────────────────────

/// Apply PKCS7 padding to `data` for the given block size (16 for AES).
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + padding_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

/// Remove PKCS7 padding. Returns an error if padding is invalid.
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(crate::KeychatError::MediaCrypto("Empty data for PKCS7 unpad".into()));
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(crate::KeychatError::MediaCrypto("Invalid PKCS7 padding".into()));
    }
    // Verify all padding bytes are correct
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(crate::KeychatError::MediaCrypto("Invalid PKCS7 padding".into()));
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

// ─── Encrypt / Decrypt ──────────────────────────────────────────────────────

/// Encrypt a file with AES-256-CTR + PKCS7 padding.
///
/// Generates a random key and IV, applies PKCS7 padding, encrypts with
/// AES-256-CTR, and computes a SHA-256 hash of the ciphertext.
pub fn encrypt_file(plaintext: &[u8]) -> EncryptedFile {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    // PKCS7 pad then encrypt
    let mut padded = pkcs7_pad(plaintext, 16);
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut padded);

    // SHA-256 of ciphertext
    let hash: [u8; 32] = Sha256::digest(&padded).into();

    EncryptedFile {
        ciphertext: padded,
        key,
        iv,
        hash,
    }
}

/// Encrypt a file with AES-256-CTR + PKCS7 padding using a specific key and IV.
///
/// Used for deterministic test vectors.
pub fn encrypt_file_with_key(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> EncryptedFile {
    let mut padded = pkcs7_pad(plaintext, 16);
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut padded);

    let hash: [u8; 32] = Sha256::digest(&padded).into();

    EncryptedFile {
        ciphertext: padded,
        key: *key,
        iv: *iv,
        hash,
    }
}

/// Decrypt a file encrypted with AES-256-CTR + PKCS7 padding.
///
/// Verifies the SHA-256 hash of the ciphertext before decrypting.
pub fn decrypt_file(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
    expected_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    // Verify hash
    let actual_hash: [u8; 32] = Sha256::digest(ciphertext).into();
    if actual_hash != *expected_hash {
        return Err(crate::KeychatError::MediaCrypto(
            "Ciphertext hash verification failed".into(),
        ));
    }

    // Decrypt
    let mut data = ciphertext.to_vec();
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut data);

    // Remove PKCS7 padding
    pkcs7_unpad(&data)
}

// ─── KCMessage Builders ─────────────────────────────────────────────────────

/// Build a KCMessage for a single file.
pub fn build_file_message(
    url: &str,
    category: FileCategory,
    mime_type: Option<&str>,
    size: u64,
    encrypted: &EncryptedFile,
) -> KCMessage {
    let file = KCFilePayload {
        category,
        url: url.to_string(),
        type_: mime_type.map(|s| s.to_string()),
        suffix: None,
        size: Some(size),
        key: Some(hex::encode(encrypted.key)),
        iv: Some(hex::encode(encrypted.iv)),
        hash: Some(hex::encode(encrypted.hash)),
        source_name: None,
        audio_duration: None,
        amplitude_samples: None,
        ecash_token: None,
    };

    KCMessage {
        v: 2,
        id: Some(crate::message::uuid_v4()),
        kind: KCMessageKind::Files,
        files: Some(KCFilesPayload {
            message: None,
            items: vec![file],
        }),
        ..KCMessage::empty()
    }
}

/// Build a KCMessage for a voice recording.
pub fn build_voice_message(
    url: &str,
    size: u64,
    duration_secs: f64,
    amplitude_samples: Vec<f64>,
    encrypted: &EncryptedFile,
) -> KCMessage {
    let file = KCFilePayload {
        category: FileCategory::Voice,
        url: url.to_string(),
        type_: Some("audio/aac".to_string()),
        suffix: None,
        size: Some(size),
        key: Some(hex::encode(encrypted.key)),
        iv: Some(hex::encode(encrypted.iv)),
        hash: Some(hex::encode(encrypted.hash)),
        source_name: None,
        audio_duration: Some(duration_secs),
        amplitude_samples: Some(amplitude_samples),
        ecash_token: None,
    };

    KCMessage {
        v: 2,
        id: Some(crate::message::uuid_v4()),
        kind: KCMessageKind::Files,
        files: Some(KCFilesPayload {
            message: None,
            items: vec![file],
        }),
        ..KCMessage::empty()
    }
}

/// Build a KCMessage for multiple files.
pub fn build_multi_file_message(files: Vec<KCFilePayload>) -> KCMessage {
    KCMessage {
        v: 2,
        id: Some(crate::message::uuid_v4()),
        kind: KCMessageKind::Files,
        files: Some(KCFilesPayload {
            message: None,
            items: files,
        }),
        ..KCMessage::empty()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_empty() {
        let plaintext = b"";
        let enc = encrypt_file(plaintext);
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_1_byte() {
        let plaintext = b"X";
        let enc = encrypt_file(plaintext);
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_1kb() {
        let plaintext = vec![0x42u8; 1024];
        let enc = encrypt_file(&plaintext);
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_1mb() {
        let plaintext = vec![0xABu8; 1024 * 1024];
        let enc = encrypt_file(&plaintext);
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn hash_verification_tampered_ciphertext() {
        let plaintext = b"Hello, Keychat!";
        let enc = encrypt_file(plaintext);
        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0xFF; // flip bits
        let result = decrypt_file(&tampered, &enc.key, &enc.iv, &enc.hash);
        assert!(result.is_err());
    }

    #[test]
    fn key_iv_uniqueness() {
        let plaintext = b"same data";
        let enc1 = encrypt_file(plaintext);
        let enc2 = encrypt_file(plaintext);
        // Key and IV should differ (random)
        assert_ne!(enc1.key, enc2.key);
        assert_ne!(enc1.iv, enc2.iv);
    }

    #[test]
    fn build_file_message_serialization() {
        let enc = encrypt_file(b"test data");
        let msg = build_file_message(
            "https://example.com/file",
            FileCategory::Document,
            Some("application/pdf"),
            1234,
            &enc,
        );
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::Files);
        let files = parsed.files.unwrap();
        assert_eq!(files.items.len(), 1);
        assert_eq!(files.items[0].category, FileCategory::Document);
        assert_eq!(files.items[0].url, "https://example.com/file");
        assert_eq!(files.items[0].type_.as_deref(), Some("application/pdf"));
        assert_eq!(files.items[0].size, Some(1234));
        assert!(files.items[0].key.is_some());
        assert!(files.items[0].iv.is_some());
        assert!(files.items[0].hash.is_some());
    }

    #[test]
    fn build_voice_message_has_audio_fields() {
        let enc = encrypt_file(b"audio data");
        let msg = build_voice_message(
            "https://example.com/voice",
            5000,
            3.5,
            vec![0.1, 0.5, 0.9, 0.3],
            &enc,
        );
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        let files = parsed.files.unwrap();
        let voice = &files.items[0];
        assert_eq!(voice.category, FileCategory::Voice);
        assert_eq!(voice.audio_duration, Some(3.5));
        assert_eq!(
            voice.amplitude_samples.as_ref().unwrap(),
            &vec![0.1, 0.5, 0.9, 0.3]
        );
    }

    #[test]
    fn encrypt_decrypt_known_test_vector() {
        // Fixed key and IV for deterministic test
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext = b"Hello, Keychat!";

        let enc = encrypt_file_with_key(plaintext, &key, &iv);

        // Verify roundtrip with known key/IV
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);

        // Encrypt again with same key/IV → same ciphertext (deterministic)
        let enc2 = encrypt_file_with_key(plaintext, &key, &iv);
        assert_eq!(enc.ciphertext, enc2.ciphertext);
        assert_eq!(enc.hash, enc2.hash);
    }

    #[test]
    fn encrypt_decrypt_large_file_10mb() {
        let plaintext = vec![0x55u8; 10 * 1024 * 1024]; // 10 MB
        let enc = encrypt_file(&plaintext);
        let dec = decrypt_file(&enc.ciphertext, &enc.key, &enc.iv, &enc.hash).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn pkcs7_padding_block_boundary() {
        // Exactly 16 bytes → should add full block of padding (16 bytes of 0x10)
        let data = vec![0xAAu8; 16];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[16..], vec![16u8; 16]);

        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn build_multi_file_message_works() {
        let files = vec![
            KCFilePayload {
                category: FileCategory::Image,
                url: "https://example.com/a".into(),
                type_: Some("image/png".into()),
                suffix: None,
                size: Some(100),
                key: None,
                iv: None,
                hash: None,
                source_name: None,
                audio_duration: None,
                amplitude_samples: None,
                ecash_token: None,
            },
            KCFilePayload {
                category: FileCategory::Document,
                url: "https://example.com/b".into(),
                type_: Some("application/pdf".into()),
                suffix: None,
                size: Some(200),
                key: None,
                iv: None,
                hash: None,
                source_name: None,
                audio_duration: None,
                amplitude_samples: None,
                ecash_token: None,
            },
        ];
        let msg = build_multi_file_message(files);
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.files.unwrap().items.len(), 2);
    }
}
