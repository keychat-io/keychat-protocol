pub mod nip04;
pub mod nip44;
pub mod nip59;

use rand::RngCore;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

use crate::error::{KeychatError, Result};
use crate::identity::{generate_random_nostr_keypair, NostrKeypair};

pub type NostrTag = Vec<String>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<NostrTag>,
    pub content: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

impl NostrEvent {
    pub fn new_unsigned(
        pubkey: String,
        kind: u16,
        tags: Vec<NostrTag>,
        content: String,
        created_at: u64,
    ) -> Self {
        Self {
            id: String::new(),
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: String::new(),
        }
    }

    pub fn sign(mut self, keypair: &NostrKeypair) -> Result<Self> {
        self.id = compute_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        self.sig = sign_digest_hex(&keypair.secret_key(), &self.id)?;
        Ok(self)
    }

    pub fn new_rumor(
        pubkey: String,
        kind: u16,
        tags: Vec<NostrTag>,
        content: String,
        created_at: u64,
    ) -> Self {
        let mut event = Self::new_unsigned(pubkey, kind, tags, content, created_at);
        event.id = compute_event_id(
            &event.pubkey,
            event.created_at,
            event.kind,
            &event.tags,
            &event.content,
        );
        event
    }

    pub fn verify_id(&self) -> Result<()> {
        let expected = compute_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if self.id != expected {
            return Err(KeychatError::InvalidSignature);
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_id()?;
        if self.sig.is_empty() {
            return Err(KeychatError::InvalidSignature);
        }

        verify_digest_hex(&self.pubkey, &self.id, &self.sig)
    }

    pub fn first_tag_value(&self, tag_name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().is_some_and(|value| value == tag_name) && tag.len() > 1)
            .and_then(|tag| tag.get(1).map(String::as_str))
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn generate_ephemeral_sender() -> NostrKeypair {
    generate_random_nostr_keypair()
}

pub fn compute_event_id(
    pubkey: &str,
    created_at: u64,
    kind: u16,
    tags: &[NostrTag],
    content: &str,
) -> String {
    let serialized = serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string();
    hex::encode(Sha256::digest(serialized.as_bytes()))
}

pub fn sign_message(secret_key: &SecretKey, message: &[u8]) -> Result<String> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    sign_digest(secret_key, &digest)
}

pub fn sign_digest(secret_key: &SecretKey, digest: &[u8; 32]) -> Result<String> {
    let message = Message::from_digest_slice(digest).map_err(KeychatError::from)?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(signature.to_string())
}

pub fn sign_digest_hex(secret_key: &SecretKey, digest_hex: &str) -> Result<String> {
    let digest = decode_hex_32(digest_hex)?;
    sign_digest(secret_key, &digest)
}

pub fn verify_message(pubkey_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify_digest(pubkey_hex, &digest, signature_hex)
}

pub fn verify_digest(pubkey_hex: &str, digest: &[u8; 32], signature_hex: &str) -> Result<()> {
    let message = Message::from_digest_slice(digest).map_err(KeychatError::from)?;
    let pubkey = XOnlyPublicKey::from_slice(&decode_hex_32(pubkey_hex)?)?;
    let signature = Signature::from_str(signature_hex).map_err(KeychatError::from)?;
    Secp256k1::new()
        .verify_schnorr(&signature, &message, &pubkey)
        .map_err(KeychatError::from)?;
    Ok(())
}

pub fn verify_digest_hex(pubkey_hex: &str, digest_hex: &str, signature_hex: &str) -> Result<()> {
    let digest = decode_hex_32(digest_hex)?;
    verify_digest(pubkey_hex, &digest, signature_hex)
}

pub fn derive_shared_secret(secret_key: &SecretKey, peer_pubkey_hex: &str) -> Result<[u8; 32]> {
    let local_public = PublicKey::from_secret_key(&Secp256k1::new(), secret_key)
        .x_only_public_key()
        .0
        .serialize();
    let local_hex = hex::encode(local_public);
    let mut pair = [local_hex, peer_pubkey_hex.to_owned()];
    pair.sort();
    let mut hasher = Sha256::new();
    hasher.update(pair[0].as_bytes());
    hasher.update(pair[1].as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn xor_stream_encrypt(
    secret_key: &SecretKey,
    peer_pubkey_hex: &str,
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let secret = derive_shared_secret(secret_key, peer_pubkey_hex)?;
    Ok(apply_keystream(&secret, nonce, plaintext))
}

pub fn random_nonce<const N: usize>() -> [u8; N] {
    let mut nonce = [0u8; N];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn apply_keystream(secret: &[u8; 32], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter = 0u64;

    while out.len() < input.len() {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(nonce);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        for byte in block {
            if out.len() == input.len() {
                break;
            }
            let idx = out.len();
            out.push(input[idx] ^ byte);
        }
        counter += 1;
    }

    out
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(KeychatError::InvalidLength {
            expected: 32,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
