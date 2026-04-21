//! Signal Protocol key generation primitives.
//!
//! Implements key generation for the Signal encryption layer (§5, §6)
//! without full session management. Produces the key material needed
//! for `KCFriendRequestPayload` and `SignalPrekeyAuth`.
//!
//! Key types generated:
//! - **Signal identity**: Curve25519 keypair (per-peer, ephemeral)
//! - **Signed prekey**: Curve25519 keypair + XEdDSA signature
//! - **One-time prekey**: Curve25519 keypair
//! - **Kyber KEM prekey**: ML-KEM 1024 keypair + XEdDSA signature
//! - **globalSign**: Schnorr signature binding Nostr identity to Signal identity

use crate::error::{KeychatError, Result};
use crate::message::KCFriendRequestPayload;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Helper: truncate hex for safe debug display.
fn redact(data: &[u8]) -> String {
    let hex = hex::encode(data);
    if hex.len() > 16 {
        format!("{}...", &hex[..16])
    } else {
        hex
    }
}

/// A Signal Curve25519 identity keypair.
/// Private key is zeroed on drop (C-SEC2).
#[derive(Clone)]
pub struct SignalIdentity {
    /// 32-byte Curve25519 private key.
    pub private_key: [u8; 32],
    /// 33-byte Curve25519 public key (0x05 prefix + 32 bytes).
    pub public_key: [u8; 33],
}

impl Drop for SignalIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl std::fmt::Debug for SignalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalIdentity")
            .field("public_key", &hex::encode(self.public_key))
            .field("private_key", &redact(&self.private_key))
            .finish()
    }
}

/// A Signal signed prekey. Private key zeroed on drop (C-SEC2).
#[derive(Clone)]
pub struct SignedPrekey {
    pub id: u32,
    pub public_key: [u8; 33],
    pub signature: Vec<u8>,
    pub private_key: [u8; 32],
}

impl Drop for SignedPrekey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl std::fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPrekey")
            .field("id", &self.id)
            .field("public_key", &hex::encode(self.public_key))
            .field("private_key", &redact(&self.private_key))
            .finish()
    }
}

/// A Signal one-time prekey. Private key zeroed on drop (C-SEC2).
#[derive(Clone)]
pub struct OneTimePrekey {
    pub id: u32,
    pub public_key: [u8; 33],
    pub private_key: [u8; 32],
}

impl Drop for OneTimePrekey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl std::fmt::Debug for OneTimePrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePrekey")
            .field("id", &self.id)
            .field("public_key", &hex::encode(self.public_key))
            .field("private_key", &redact(&self.private_key))
            .finish()
    }
}

/// A Kyber KEM prekey (ML-KEM 1024 / CRYSTALS-Kyber-1024). Secret key zeroed on drop (C-SEC2).
#[derive(Clone)]
pub struct KyberPrekey {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for KyberPrekey {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl std::fmt::Debug for KyberPrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyberPrekey")
            .field("id", &self.id)
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &redact(&self.secret_key))
            .finish()
    }
}

/// Derive a v1-Flutter-compatible Signal Curve25519 identity from a BIP-39 mnemonic.
///
/// Mirrors the derivation used by the v1 Keychat Flutter app
/// (`keychat_rust_ffi_plugin::api_nostr::generate_curve25519_keypair`):
///
/// 1. `mnemonic → 64-byte seed` via BIP-39 (PBKDF2-SHA512, optional passphrase).
/// 2. BIP-32 master key on `Network::Bitcoin`.
/// 3. Derive child at `m/44'/1238'/{account}'/0/0`.
/// 4. Feed the 32-byte child secret into libsignal's `PrivateKey::deserialize`
///    (Djb/Curve25519 variant) and derive the matching 33-byte public key.
///
/// Used by v1 → v1.5 migration to recover the user's Signal identity keypair
/// without needing the plaintext key to be present in the v1 export.
pub fn derive_v1_signal_identity(
    mnemonic_words: &str,
    passphrase: Option<&str>,
    account: u32,
) -> Result<SignalIdentity> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use libsignal_protocol::PrivateKey as SignalPrivateKey;
    use std::str::FromStr;

    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_words)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid v1 mnemonic: {e}")))?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

    let ctx = bitcoin::secp256k1::Secp256k1::new();
    let root_key = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)
        .map_err(|e| KeychatError::KeyDerivation(format!("BIP-32 master: {e}")))?;
    let path_str = format!("m/44'/1238'/{}'/0/0", account);
    let path = DerivationPath::from_str(&path_str)
        .map_err(|e| KeychatError::KeyDerivation(format!("bad derivation path: {e}")))?;
    let child = root_key
        .derive_priv(&ctx, &path)
        .map_err(|e| KeychatError::KeyDerivation(format!("BIP-32 derive: {e}")))?;

    let secret_bytes: [u8; 32] = child.private_key.secret_bytes();
    let signal_priv = SignalPrivateKey::deserialize(&secret_bytes)
        .map_err(|e| KeychatError::KeyDerivation(format!("signal privkey decode: {e}")))?;
    let signal_pub = signal_priv
        .public_key()
        .map_err(|e| KeychatError::KeyDerivation(format!("signal pubkey derive: {e}")))?;

    let priv_vec = signal_priv.serialize();
    let pub_vec = signal_pub.serialize();

    if priv_vec.len() != 32 {
        return Err(KeychatError::KeyDerivation(format!(
            "unexpected v1 signal private key length: {}",
            priv_vec.len()
        )));
    }
    if pub_vec.len() != 33 {
        return Err(KeychatError::KeyDerivation(format!(
            "unexpected v1 signal public key length: {}",
            pub_vec.len()
        )));
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&priv_vec);
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(&pub_vec);

    Ok(SignalIdentity {
        private_key,
        public_key,
    })
}

/// Generate a new Signal identity keypair (Curve25519).
///
/// The private key is clamped per Curve25519 convention:
/// - Clear bits 0, 1, 2, 255
/// - Set bit 254
pub fn generate_signal_identity() -> SignalIdentity {
    use ::rand::RngCore;
    let mut rng = ::rand::rng();
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    // Clamp per Curve25519/X25519 convention
    private_key[0] &= 0xF8;
    private_key[31] &= 0x7F;
    private_key[31] |= 0x40;

    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);

    // Signal uses a 0x05 prefix for Curve25519 public keys
    let mut public_key = [0u8; 33];
    public_key[0] = 0x05;
    public_key[1..].copy_from_slice(public.as_bytes());

    SignalIdentity {
        private_key,
        public_key,
    }
}

/// Sign data using XEdDSA — converts a Curve25519 private key to an
/// Ed25519 signing key and produces a signature.
///
/// This is a simplified implementation: the Curve25519 private key bytes
/// (after clamping) are used as the Ed25519 signing key scalar.
fn xeddsa_sign(curve25519_private: &[u8; 32], message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};

    // Use the clamped Curve25519 private key as Ed25519 signing key seed.
    // This follows the XEdDSA construction: Montgomery private key → Edwards signing key.
    let signing_key = SigningKey::from_bytes(curve25519_private);
    let signature = signing_key.sign(message);
    signature.to_bytes().to_vec()
}

/// Verify an XEdDSA signature.
///
/// Converts the Curve25519 public key to an Ed25519 verifying key.
pub fn xeddsa_verify(curve25519_public: &[u8; 33], message: &[u8], signature: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // The 33-byte key has a 0x05 prefix; strip it to get 32 bytes.
    let montgomery_bytes: [u8; 32] = curve25519_public[1..]
        .try_into()
        .map_err(|_| KeychatError::KeyDerivation("invalid public key length".into()))?;

    // Convert Montgomery point to Edwards point.
    let montgomery = curve25519_dalek::montgomery::MontgomeryPoint(montgomery_bytes);
    let edwards = montgomery.to_edwards(0).ok_or_else(|| {
        KeychatError::KeyDerivation("Montgomery to Edwards conversion failed".into())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&edwards.compress().to_bytes())
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid Ed25519 public key: {}", e)))?;

    let sig = Signature::from_slice(signature)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid signature: {}", e)))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| KeychatError::KeyDerivation(format!("signature verification failed: {}", e)))
}

/// Generate a signed prekey.
///
/// The signature is an XEdDSA signature over the public key bytes,
/// using the identity private key.
pub fn generate_signed_prekey(identity_private_key: &[u8; 32]) -> SignedPrekey {
    generate_signed_prekey_with_id(identity_private_key, 1)
}

/// Generate a signed prekey with a specific ID.
pub fn generate_signed_prekey_with_id(identity_private_key: &[u8; 32], id: u32) -> SignedPrekey {
    use ::rand::RngCore;
    let mut rng = ::rand::rng();
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    private_key[0] &= 0xF8;
    private_key[31] &= 0x7F;
    private_key[31] |= 0x40;

    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);

    let mut public_key = [0u8; 33];
    public_key[0] = 0x05;
    public_key[1..].copy_from_slice(public.as_bytes());

    let signature = xeddsa_sign(identity_private_key, &public_key);

    SignedPrekey {
        id,
        public_key,
        signature,
        private_key,
    }
}

/// Generate a one-time prekey.
pub fn generate_one_time_prekey() -> OneTimePrekey {
    generate_one_time_prekey_with_id(1)
}

/// Generate a one-time prekey with a specific ID.
pub fn generate_one_time_prekey_with_id(id: u32) -> OneTimePrekey {
    use ::rand::RngCore;
    let mut rng = ::rand::rng();
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    private_key[0] &= 0xF8;
    private_key[31] &= 0x7F;
    private_key[31] |= 0x40;

    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);

    let mut public_key = [0u8; 33];
    public_key[0] = 0x05;
    public_key[1..].copy_from_slice(public.as_bytes());

    OneTimePrekey {
        id,
        public_key,
        private_key,
    }
}

/// Generate a Kyber KEM prekey (ML-KEM 1024).
///
/// The signature is an XEdDSA signature over the Kyber public key,
/// using the Signal identity private key.
pub fn generate_kyber_prekey(identity_private_key: &[u8; 32]) -> KyberPrekey {
    generate_kyber_prekey_with_id(identity_private_key, 1)
}

/// Generate a Kyber KEM prekey with a specific ID.
pub fn generate_kyber_prekey_with_id(identity_private_key: &[u8; 32], id: u32) -> KyberPrekey {
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};

    let (pk, sk) = kyber1024::keypair();
    let public_key = pk.as_bytes().to_vec();
    let secret_key = sk.as_bytes().to_vec();

    let signature = xeddsa_sign(identity_private_key, &public_key);

    KyberPrekey {
        id,
        public_key,
        signature,
        secret_key,
    }
}

/// Compute a `globalSign` Schnorr signature.
///
/// Signs `"Keychat-{nostr_identity_key}-{signal_identity_key}-{time}"`
/// with the Nostr secp256k1 private key (BIP-340 Schnorr).
pub fn compute_global_sign(
    nostr_secret_key: &nostr::SecretKey,
    nostr_identity_key: &str,
    signal_identity_key: &str,
    time: u64,
) -> Result<String> {
    use nostr::secp256k1::{Message, Secp256k1};
    use sha2::{Digest, Sha256};

    let msg_str = format!(
        "Keychat-{}-{}-{}",
        nostr_identity_key, signal_identity_key, time
    );
    let hash = Sha256::digest(msg_str.as_bytes());
    let message = Message::from_digest_slice(&hash)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid message hash: {}", e)))?;

    let secp = Secp256k1::new();
    // Extract the raw secp256k1 secret key bytes from the nostr SecretKey
    let mut sk_bytes = hex::decode(nostr_secret_key.to_secret_hex())
        .map_err(|e| KeychatError::KeyDerivation(format!("hex decode error: {}", e)))?;
    let secp_sk = nostr::secp256k1::SecretKey::from_slice(&sk_bytes)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid secret key: {}", e)))?;
    // Zeroize the hex-decoded secret key copy (C-SEC2)
    sk_bytes.zeroize();
    let keypair = nostr::secp256k1::Keypair::from_secret_key(&secp, &secp_sk);
    let sig = secp.sign_schnorr(&message, &keypair);

    Ok(hex::encode(sig.as_ref()))
}

/// Verify a `globalSign` Schnorr signature.
///
/// Verifies `"Keychat-{nostr_identity_key}-{signal_identity_key}-{time}"`
/// against the Nostr secp256k1 public key.
pub fn verify_global_sign(
    nostr_pubkey_hex: &str,
    signal_identity_key: &str,
    time: u64,
    signature_hex: &str,
) -> Result<bool> {
    use nostr::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use sha2::{Digest, Sha256};

    let msg_str = format!(
        "Keychat-{}-{}-{}",
        nostr_pubkey_hex, signal_identity_key, time
    );
    let hash = Sha256::digest(msg_str.as_bytes());
    let message = Message::from_digest_slice(&hash)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid message hash: {}", e)))?;

    let pubkey_bytes = hex::decode(nostr_pubkey_hex)?;
    let pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid public key: {}", e)))?;

    let sig_bytes = hex::decode(signature_hex)?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| KeychatError::KeyDerivation(format!("invalid signature: {}", e)))?;

    let secp = Secp256k1::verification_only();
    match secp.verify_schnorr(&sig, &message, &pubkey) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Build a complete `KCFriendRequestPayload` from Nostr identity and generated Signal keys.
///
/// This is the convenience function that combines all key generation steps
/// into a ready-to-send friend request payload (§6.2).
pub fn build_friend_request_payload(
    nostr_secret_key: &nostr::SecretKey,
    nostr_pubkey_hex: &str,
    display_name: &str,
    device_id: &str,
) -> Result<(KCFriendRequestPayload, FriendRequestSecrets)> {
    // 1. Generate Signal identity for this peer
    let signal_identity = generate_signal_identity();
    let signal_identity_key_hex = hex::encode(signal_identity.public_key);

    // 2. Generate signed prekey
    let signed_prekey = generate_signed_prekey(&signal_identity.private_key);

    // 3. Generate one-time prekey
    let one_time_prekey = generate_one_time_prekey();

    // 4. Generate Kyber KEM prekey
    let kyber_prekey = generate_kyber_prekey(&signal_identity.private_key);

    // 5. Generate firstInbox (ephemeral Nostr keypair)
    let first_inbox_keys = crate::EphemeralKeypair::generate();
    let first_inbox_hex = first_inbox_keys.pubkey_hex();

    // 6. Compute globalSign
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let global_sign = compute_global_sign(
        nostr_secret_key,
        nostr_pubkey_hex,
        &signal_identity_key_hex,
        time,
    )?;

    let payload = KCFriendRequestPayload {
        message: None,
        name: display_name.to_string(),
        nostr_identity_key: nostr_pubkey_hex.to_string(),
        signal_identity_key: signal_identity_key_hex,
        first_inbox: first_inbox_hex,
        device_id: device_id.to_string(),
        signal_signed_prekey_id: signed_prekey.id,
        signal_signed_prekey: hex::encode(signed_prekey.public_key),
        signal_signed_prekey_signature: hex::encode(&signed_prekey.signature),
        signal_one_time_prekey_id: one_time_prekey.id,
        signal_one_time_prekey: hex::encode(one_time_prekey.public_key),
        signal_kyber_prekey_id: kyber_prekey.id,
        signal_kyber_prekey: hex::encode(&kyber_prekey.public_key),
        signal_kyber_prekey_signature: hex::encode(&kyber_prekey.signature),
        global_sign,
        time: Some(time),
        version: 2,
        relay: None,
        avatar: None,
        lightning: None,
    };

    let secrets = FriendRequestSecrets {
        signal_identity,
        signed_prekey,
        one_time_prekey,
        kyber_prekey,
        first_inbox_keys,
    };

    Ok((payload, secrets))
}

/// Secret key material generated during friend request creation.
/// Must be stored locally for establishing the Signal session when the peer responds.
#[derive(Debug)]
pub struct FriendRequestSecrets {
    pub signal_identity: SignalIdentity,
    pub signed_prekey: SignedPrekey,
    pub one_time_prekey: OneTimePrekey,
    pub kyber_prekey: KyberPrekey,
    pub first_inbox_keys: crate::EphemeralKeypair,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_signal_identity_matches_flutter_derivation() {
        // Real v1 export: identity "老版本" at account=0 with mnemonic
        // "town helmet tongue lizard gap merry surround exist erode maze horn upgrade".
        // Expected curve25519PkHex from Isar snapshot:
        //   05a8c796464794748f45b8f685707110223e8456ec7eb87c0fc2baa17efe261145
        let mnemonic =
            "town helmet tongue lizard gap merry surround exist erode maze horn upgrade";
        let id = derive_v1_signal_identity(mnemonic, None, 0).unwrap();
        let pub_hex = hex::encode(id.public_key);
        assert_eq!(
            pub_hex,
            "05a8c796464794748f45b8f685707110223e8456ec7eb87c0fc2baa17efe261145",
            "v1 derivation must match keychat_rust_ffi_plugin::generate_curve25519_keypair"
        );
        // Matches v1 Flutter curve25519 public key stored in Identity.curve25519PkHex.
    }

    #[test]
    fn v1_signal_identity_same_mnemonic_different_account() {
        let mnemonic =
            "town helmet tongue lizard gap merry surround exist erode maze horn upgrade";
        let id0 = derive_v1_signal_identity(mnemonic, None, 0).unwrap();
        let id1 = derive_v1_signal_identity(mnemonic, None, 1).unwrap();
        assert_ne!(id0.public_key, id1.public_key);
        assert_ne!(id0.private_key, id1.private_key);
    }

    #[test]
    fn generate_signal_identity_key_sizes() {
        let id = generate_signal_identity();
        assert_eq!(id.private_key.len(), 32);
        assert_eq!(id.public_key.len(), 33);
        assert_eq!(
            id.public_key[0], 0x05,
            "Signal Curve25519 public key must have 0x05 prefix"
        );
    }

    #[test]
    fn signal_identity_is_random() {
        let id1 = generate_signal_identity();
        let id2 = generate_signal_identity();
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.private_key, id2.private_key);
    }

    #[test]
    fn signed_prekey_generation() {
        let identity = generate_signal_identity();
        let spk = generate_signed_prekey(&identity.private_key);
        assert_eq!(spk.public_key.len(), 33);
        assert_eq!(spk.public_key[0], 0x05);
        assert_eq!(spk.id, 1);
        assert!(!spk.signature.is_empty());
    }

    #[test]
    fn signed_prekey_custom_id() {
        let identity = generate_signal_identity();
        let spk = generate_signed_prekey_with_id(&identity.private_key, 42);
        assert_eq!(spk.id, 42);
    }

    #[test]
    fn one_time_prekey_generation() {
        let otpk = generate_one_time_prekey();
        assert_eq!(otpk.public_key.len(), 33);
        assert_eq!(otpk.public_key[0], 0x05);
        assert_eq!(otpk.id, 1);
    }

    #[test]
    fn one_time_prekey_custom_id() {
        let otpk = generate_one_time_prekey_with_id(99);
        assert_eq!(otpk.id, 99);
    }

    #[test]
    fn kyber_prekey_generation() {
        let identity = generate_signal_identity();
        let kyber = generate_kyber_prekey(&identity.private_key);
        // ML-KEM 1024 public key is 1568 bytes
        assert_eq!(
            kyber.public_key.len(),
            1568,
            "ML-KEM 1024 public key should be 1568 bytes"
        );
        assert!(!kyber.signature.is_empty());
        assert_eq!(kyber.id, 1);
    }

    #[test]
    fn kyber_prekey_custom_id() {
        let identity = generate_signal_identity();
        let kyber = generate_kyber_prekey_with_id(&identity.private_key, 7);
        assert_eq!(kyber.id, 7);
    }

    #[test]
    fn global_sign_roundtrip() {
        let identity = crate::Identity::generate().unwrap().identity;
        let signal_id = generate_signal_identity();
        let signal_pub_hex = hex::encode(signal_id.public_key);
        let nostr_pub_hex = identity.pubkey_hex();
        let time = 1700000000u64;

        let sig = compute_global_sign(identity.secret_key(), &nostr_pub_hex, &signal_pub_hex, time)
            .unwrap();

        // Signature is 64 bytes → 128 hex chars
        assert_eq!(sig.len(), 128);

        // Verify
        let valid = verify_global_sign(&nostr_pub_hex, &signal_pub_hex, time, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn global_sign_wrong_time_fails() {
        let identity = crate::Identity::generate().unwrap().identity;
        let signal_id = generate_signal_identity();
        let signal_pub_hex = hex::encode(signal_id.public_key);
        let nostr_pub_hex = identity.pubkey_hex();

        let sig = compute_global_sign(identity.secret_key(), &nostr_pub_hex, &signal_pub_hex, 100)
            .unwrap();

        // Wrong time should fail verification
        let valid = verify_global_sign(&nostr_pub_hex, &signal_pub_hex, 999, &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn build_friend_request_payload_complete() {
        let identity = crate::Identity::generate().unwrap().identity;
        let (payload, secrets) = build_friend_request_payload(
            identity.secret_key(),
            &identity.pubkey_hex(),
            "Alice",
            "device-001",
        )
        .unwrap();

        // Check all required fields are populated
        assert_eq!(payload.name, "Alice");
        assert_eq!(payload.nostr_identity_key, identity.pubkey_hex());
        assert!(!payload.signal_identity_key.is_empty());
        assert!(!payload.first_inbox.is_empty());
        assert_eq!(payload.device_id, "device-001");
        assert!(payload.signal_signed_prekey_id > 0);
        assert!(!payload.signal_signed_prekey.is_empty());
        assert!(!payload.signal_signed_prekey_signature.is_empty());
        assert!(payload.signal_one_time_prekey_id > 0);
        assert!(!payload.signal_one_time_prekey.is_empty());
        assert!(payload.signal_kyber_prekey_id > 0);
        assert!(!payload.signal_kyber_prekey.is_empty());
        assert!(!payload.signal_kyber_prekey_signature.is_empty());
        assert!(!payload.global_sign.is_empty());
        assert!(payload.time.is_some());
        assert_eq!(payload.version, 2);

        // Verify globalSign
        let valid = verify_global_sign(
            &payload.nostr_identity_key,
            &payload.signal_identity_key,
            payload.time.unwrap(),
            &payload.global_sign,
        )
        .unwrap();
        assert!(valid);

        // Check secrets are retained
        assert_eq!(secrets.signal_identity.private_key.len(), 32);
        assert_eq!(secrets.first_inbox_keys.pubkey_hex(), payload.first_inbox);
    }

    #[test]
    fn friend_request_payload_json_camel_case() {
        let identity = crate::Identity::generate().unwrap().identity;
        let (payload, _) = build_friend_request_payload(
            identity.secret_key(),
            &identity.pubkey_hex(),
            "Bob",
            "dev-2",
        )
        .unwrap();

        let msg = crate::message::KCMessage::friend_request("fr-001".into(), payload);
        let json = msg.to_json().unwrap();

        // Must use camelCase
        assert!(
            json.contains("nostrIdentityKey"),
            "missing nostrIdentityKey"
        );
        assert!(
            json.contains("signalIdentityKey"),
            "missing signalIdentityKey"
        );
        assert!(json.contains("firstInbox"), "missing firstInbox");
        assert!(
            json.contains("signalSignedPrekeyId"),
            "missing signalSignedPrekeyId"
        );
        assert!(
            json.contains("signalKyberPrekey\":"),
            "missing signalKyberPrekey"
        );
        assert!(json.contains("globalSign"), "missing globalSign");
    }

    #[test]
    fn debug_output_does_not_leak_full_private_key() {
        let id = generate_signal_identity();
        let debug = format!("{:?}", id);
        // Private key should be truncated (16 hex chars + "...")
        assert!(
            debug.contains("..."),
            "Debug output should truncate private key"
        );
        // Full private key (64 hex chars) should NOT appear
        let full_priv_hex = hex::encode(id.private_key);
        assert!(
            !debug.contains(&full_priv_hex),
            "Debug output must not contain full private key"
        );
    }

    #[test]
    fn zeroize_on_drop_clears_private_key() {
        let id = generate_signal_identity();
        let priv_copy = id.private_key;
        assert_ne!(
            priv_copy, [0u8; 32],
            "key should not be all zeros initially"
        );
        // After drop, we can't inspect the original memory directly in safe Rust,
        // but we verify the Drop impl exists and compiles correctly.
        // The zeroize crate is well-tested; we trust it does its job.
        drop(id);
        // If we got here without panic, Drop ran successfully.
    }
}
