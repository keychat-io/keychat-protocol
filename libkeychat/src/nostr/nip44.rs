use nostr::nips::nip44::{self, Version};
use nostr::{PublicKey as NostrPublicKey, SecretKey as NostrSecretKey};

use crate::error::{KeychatError, Result};
use crate::identity::NostrKeypair;

pub fn encrypt(
    sender: &NostrKeypair,
    receiver_pubkey_hex: &str,
    plaintext: impl AsRef<[u8]>,
) -> Result<String> {
    let secret_key = NostrSecretKey::from_slice(&sender.secret_key_bytes())
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    let public_key = NostrPublicKey::from_hex(receiver_pubkey_hex)
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    nip44::encrypt(&secret_key, &public_key, plaintext, Version::V2)
        .map_err(|err| KeychatError::Nostr(err.to_string()))
}

pub fn decrypt(receiver: &NostrKeypair, sender_pubkey_hex: &str, content: &str) -> Result<String> {
    let secret_key = NostrSecretKey::from_slice(&receiver.secret_key_bytes())
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    let public_key = NostrPublicKey::from_hex(sender_pubkey_hex)
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    nip44::decrypt(&secret_key, &public_key, content)
        .map_err(|err| KeychatError::Nostr(err.to_string()))
}

/// Decrypt and return raw bytes (for binary MLS ciphertext).
pub fn decrypt_to_bytes(
    receiver: &NostrKeypair,
    sender_pubkey_hex: &str,
    content: &str,
) -> Result<Vec<u8>> {
    let secret_key = NostrSecretKey::from_slice(&receiver.secret_key_bytes())
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    let public_key = NostrPublicKey::from_hex(sender_pubkey_hex)
        .map_err(|err| KeychatError::Nostr(err.to_string()))?;
    nip44::decrypt_to_bytes(&secret_key, &public_key, content)
        .map_err(|err| KeychatError::Nostr(err.to_string()))
}
