//! Identity module: BIP-39 mnemonic → Nostr secp256k1 keypair.
//!
//! Implements the Identity Layer from the Keychat Protocol v2 spec (§2).
//! A Keychat identity is a standard Nostr secp256k1 keypair derived from a BIP-39 mnemonic.
//!
//! **Security**: The mnemonic is sensitive root key material. `Identity` does NOT store it
//! after derivation. The mnemonic is returned once at generation time for the caller to
//! persist in platform-native secure storage (Keychain, Android Keystore, etc.).

use crate::error::{KeychatError, Result};
use bip39::Mnemonic;
use nostr::prelude::*;

/// A Keychat identity — holds the derived Nostr keypair only.
///
/// The BIP-39 mnemonic is **not retained** in this struct. It is returned once
/// from [`Identity::generate`] (as part of [`IdentityWithMnemonic`]) and must
/// be stored by the caller in secure storage. To reconstruct an `Identity`
/// later, use [`Identity::from_mnemonic_str`] with the mnemonic retrieved from
/// secure storage.
#[derive(Clone)]
pub struct Identity {
    /// The Nostr keypair (secp256k1), derived via NIP-06
    keys: Keys,
}

/// Returned from [`Identity::generate`] — contains both the identity and
/// the mnemonic. The caller MUST persist the mnemonic in secure storage
/// and then drop this struct.
pub struct IdentityWithMnemonic {
    /// The derived identity (no mnemonic inside).
    pub identity: Identity,
    /// The BIP-39 mnemonic — store in OS keychain, then drop.
    pub mnemonic: String,
}

/// An ephemeral keypair for one-time use (message sending).
#[derive(Clone)]
pub struct EphemeralKeypair {
    keys: Keys,
}

impl Identity {
    /// Generate a new random identity with a 12-word mnemonic.
    ///
    /// Returns `IdentityWithMnemonic` — the mnemonic is provided **once**.
    /// The caller MUST store it in platform-native secure storage (Keychain,
    /// Android Keystore, etc.) and not persist it in plaintext.
    pub fn generate() -> Result<IdentityWithMnemonic> {
        Self::generate_with_word_count(12)
    }

    /// Generate a new random identity with a specified word count (12 or 24).
    pub fn generate_with_word_count(word_count: usize) -> Result<IdentityWithMnemonic> {
        let mnemonic =
            match word_count {
                12 => Mnemonic::generate(12)
                    .map_err(|e| KeychatError::InvalidMnemonic(e.to_string()))?,
                24 => Mnemonic::generate(24)
                    .map_err(|e| KeychatError::InvalidMnemonic(e.to_string()))?,
                _ => {
                    return Err(KeychatError::InvalidMnemonic(
                        "word count must be 12 or 24".into(),
                    ))
                }
            };
        let mnemonic_str = mnemonic.to_string();
        let identity = Self::from_mnemonic(mnemonic)?;
        Ok(IdentityWithMnemonic {
            identity,
            mnemonic: mnemonic_str,
        })
    }

    /// Import an identity from an existing mnemonic phrase (retrieved from secure storage).
    ///
    /// The mnemonic is used only for derivation and is NOT stored in the returned `Identity`.
    pub fn from_mnemonic_str(phrase: &str) -> Result<Self> {
        let mnemonic: Mnemonic = phrase
            .parse()
            .map_err(|e: bip39::Error| KeychatError::InvalidMnemonic(e.to_string()))?;
        Self::from_mnemonic(mnemonic)
    }

    /// Import an identity from an existing Mnemonic.
    fn from_mnemonic(mnemonic: Mnemonic) -> Result<Self> {
        // NIP-06: derive Nostr keys from BIP-39 mnemonic via m/44'/1237'/0'/0/0
        let keys = Keys::from_mnemonic(mnemonic.to_string(), None)
            .map_err(|e| KeychatError::KeyDerivation(e.to_string()))?;
        // Mnemonic is dropped here — not stored in Identity
        Ok(Self { keys })
    }

    /// Get the Nostr Keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        self.keys.secret_key()
    }

    /// Get the public key as hex string (64 chars, lowercase).
    pub fn pubkey_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    /// Get the public key as npub (bech32).
    pub fn npub(&self) -> String {
        self.keys.public_key().to_bech32().unwrap()
    }

    /// Get the secret key as nsec (bech32).
    pub fn nsec(&self) -> String {
        self.keys.secret_key().to_bech32().unwrap()
    }

    /// Get the secret key as hex string.
    pub fn secret_hex(&self) -> String {
        self.keys.secret_key().to_secret_hex()
    }
}

/// Normalize a Nostr public key: accepts both npub1... (bech32) and hex formats.
///
/// Returns the hex-encoded public key string.
///
/// # Examples
/// ```
/// use libkeychat::normalize_pubkey;
/// // Hex passthrough
/// let hex = normalize_pubkey("c002c688982a997c93e877e140ce5c915d624157770e7ca4e7bef6c1da72d033").unwrap();
/// assert_eq!(hex, "c002c688982a997c93e877e140ce5c915d624157770e7ca4e7bef6c1da72d033");
/// ```
pub fn normalize_pubkey(input: &str) -> crate::Result<String> {
    let trimmed = input.trim();
    if trimmed.starts_with("npub1") {
        let pk = PublicKey::from_bech32(trimmed)
            .map_err(|e| crate::KeychatError::Identity(format!("invalid npub: {e}")))?;
        Ok(pk.to_hex())
    } else {
        let _ = PublicKey::from_hex(trimmed)
            .map_err(|e| crate::KeychatError::Identity(format!("invalid hex pubkey: {e}")))?;
        Ok(trimmed.to_string())
    }
}

impl EphemeralKeypair {
    /// Generate a new random ephemeral keypair.
    pub fn generate() -> Self {
        let keys = Keys::generate();
        Self { keys }
    }

    /// Get the Nostr Keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        self.keys.secret_key()
    }

    /// Get the public key as hex string.
    pub fn pubkey_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    /// Get the secret key as hex string (for persistence).
    pub fn secret_hex(&self) -> String {
        self.keys.secret_key().to_secret_hex()
    }

    /// Reconstruct from a secret key hex string.
    pub fn from_secret_hex(secret_hex: &str) -> crate::Result<Self> {
        let secret_key = SecretKey::from_hex(secret_hex)
            .map_err(|e| crate::KeychatError::Identity(format!("invalid secret hex: {e}")))?;
        let keys = Keys::new(secret_key);
        Ok(Self { keys })
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("pubkey", &self.pubkey_hex())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("pubkey", &self.pubkey_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let gen = Identity::generate().unwrap();
        assert_eq!(gen.identity.pubkey_hex().len(), 64);
        assert!(gen.identity.npub().starts_with("npub1"));
        assert!(gen.identity.nsec().starts_with("nsec1"));
        // Mnemonic is returned separately, not inside Identity
        assert!(!gen.mnemonic.is_empty());
    }

    #[test]
    fn generate_24_word() {
        let gen = Identity::generate_with_word_count(24).unwrap();
        let words: Vec<&str> = gen.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn import_mnemonic_roundtrip() {
        let gen = Identity::generate().unwrap();
        let id2 = Identity::from_mnemonic_str(&gen.mnemonic).unwrap();
        assert_eq!(gen.identity.pubkey_hex(), id2.pubkey_hex());
        assert_eq!(gen.identity.secret_hex(), id2.secret_hex());
    }

    #[test]
    fn ephemeral_keypair() {
        let ek1 = EphemeralKeypair::generate();
        let ek2 = EphemeralKeypair::generate();
        assert_ne!(ek1.pubkey_hex(), ek2.pubkey_hex());
        assert_eq!(ek1.pubkey_hex().len(), 64);
    }

    #[test]
    fn invalid_mnemonic() {
        let result = Identity::from_mnemonic_str("not a valid mnemonic phrase");
        assert!(result.is_err());
    }

    #[test]
    fn deterministic_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let id1 = Identity::from_mnemonic_str(phrase).unwrap();
        let id2 = Identity::from_mnemonic_str(phrase).unwrap();
        assert_eq!(id1.pubkey_hex(), id2.pubkey_hex());
    }

    #[test]
    fn hex_format() {
        let gen = Identity::generate().unwrap();
        let hex = gen.identity.pubkey_hex();
        assert_eq!(hex, hex.to_lowercase());
        assert!(!hex.starts_with("0x"));
    }
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[test]
    fn test_normalize_npub() {
        // Generate a keypair and test roundtrip
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().unwrap();

        assert_eq!(normalize_pubkey(&hex).unwrap(), hex);
        assert_eq!(normalize_pubkey(&npub).unwrap(), hex);
    }

    #[test]
    fn test_normalize_invalid() {
        assert!(normalize_pubkey("npub1invalid").is_err());
        assert!(normalize_pubkey("not_a_key").is_err());
    }
}
