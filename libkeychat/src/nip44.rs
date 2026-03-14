//! NIP-44 encryption/decryption.
//!
//! Provides NIP-44 v2 encrypt/decrypt using the `nostr` crate's built-in implementation.
//! NIP-44 uses XChaCha20 + HMAC-SHA256 + HKDF for authenticated encryption
//! with a shared secret derived from ECDH between sender and receiver.

use crate::error::{KeychatError, Result};
use nostr::nips::nip44;
use nostr::prelude::*;

/// Encrypt plaintext using NIP-44.
///
/// Derives a shared secret from the sender's private key and receiver's public key,
/// then encrypts the plaintext using NIP-44 v2 (XChaCha20 + HMAC-SHA256).
pub fn encrypt(
    sender_secret_key: &SecretKey,
    receiver_pubkey: &PublicKey,
    plaintext: &str,
) -> Result<String> {
    nip44::encrypt(sender_secret_key, receiver_pubkey, plaintext, nip44::Version::V2)
        .map_err(|e| KeychatError::Nip44Encrypt(e.to_string()))
}

/// Decrypt NIP-44 ciphertext.
///
/// Derives the same shared secret from the receiver's private key and sender's public key,
/// then decrypts using NIP-44 v2.
pub fn decrypt(
    receiver_secret_key: &SecretKey,
    sender_pubkey: &PublicKey,
    ciphertext: &str,
) -> Result<String> {
    nip44::decrypt(receiver_secret_key, sender_pubkey, ciphertext)
        .map_err(|e| KeychatError::Nip44Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let plaintext = "Hello, Keychat!";

        let ciphertext =
            encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();

        let decrypted =
            decrypt(receiver.secret_key(), &sender.public_key(), &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_ciphertexts_same_plaintext() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let plaintext = "same message";

        let ct1 = encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();
        let ct2 = encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();

        // NIP-44 uses random nonces, so ciphertexts should differ
        assert_ne!(ct1, ct2);

        // Both should decrypt to the same plaintext
        let d1 = decrypt(receiver.secret_key(), &sender.public_key(), &ct1).unwrap();
        let d2 = decrypt(receiver.secret_key(), &sender.public_key(), &ct2).unwrap();
        assert_eq!(d1, plaintext);
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let wrong_receiver = Keys::generate();

        let ciphertext =
            encrypt(sender.secret_key(), &receiver.public_key(), "secret").unwrap();

        let result =
            decrypt(wrong_receiver.secret_key(), &sender.public_key(), &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext() {
        let sender = Keys::generate();
        let receiver = Keys::generate();

        // NIP-44 requires minimum 1 byte plaintext; empty might error
        // but non-empty short strings should work fine
        let plaintext = "x";
        let ciphertext =
            encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();
        let decrypted =
            decrypt(receiver.secret_key(), &sender.public_key(), &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unicode_plaintext() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let plaintext = "Hello 🔑💬 Keychat! 你好世界";

        let ciphertext =
            encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();
        let decrypted =
            decrypt(receiver.secret_key(), &sender.public_key(), &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
