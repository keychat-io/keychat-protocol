pub mod bech32;

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv as ExtendedPrivKey};
use bitcoin::Network;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::str::FromStr;

use crate::error::Result;

#[derive(Clone, Debug)]
pub struct NostrKeypair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl NostrKeypair {
    /// Create a keypair from raw secret key bytes and expected public key hex.
    pub fn from_secret_key_bytes(
        secret_bytes: &[u8; 32],
        _expected_pubkey_hex: &str,
    ) -> crate::error::Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(secret_bytes)
            .map_err(|e| crate::error::KeychatError::Nostr(e.to_string()))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn xonly_public_key(&self) -> XOnlyPublicKey {
        self.public_key.x_only_public_key().0
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.xonly_public_key().serialize()
    }

    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.secret_key.secret_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.xonly_public_key().serialize())
    }

    pub fn nsec(&self) -> Result<String> {
        bech32::encode_nsec(&self.secret_key.secret_bytes())
    }

    pub fn npub(&self) -> Result<String> {
        bech32::encode_npub(&self.xonly_public_key().serialize())
    }
}

pub trait SecretStore {
    fn store_mnemonic(&mut self, mnemonic: Mnemonic);
    fn load_mnemonic(&self) -> Option<Mnemonic>;
    fn clear(&mut self);
}

#[derive(Clone, Debug, Default)]
pub struct InMemorySecretStore {
    mnemonic: Option<Mnemonic>,
}

impl SecretStore for InMemorySecretStore {
    fn store_mnemonic(&mut self, mnemonic: Mnemonic) {
        self.mnemonic = Some(mnemonic);
    }

    fn load_mnemonic(&self) -> Option<Mnemonic> {
        self.mnemonic.clone()
    }

    fn clear(&mut self) {
        self.mnemonic = None;
    }
}

pub fn generate_mnemonic(word_count: usize) -> Result<Mnemonic> {
    Ok(Mnemonic::generate_in(Language::English, word_count)?)
}

pub fn recover_mnemonic(phrase: &str) -> Result<Mnemonic> {
    Ok(Mnemonic::parse_in(Language::English, phrase)?)
}

pub fn nostr_keypair_from_mnemonic(mnemonic: &Mnemonic) -> Result<NostrKeypair> {
    nostr_keypair_from_mnemonic_with_account(mnemonic, 0)
}

pub fn nostr_keypair_from_mnemonic_with_account(
    mnemonic: &Mnemonic,
    account: u32,
) -> Result<NostrKeypair> {
    let seed = mnemonic.to_seed("");
    let secret_key = derive_secret_key(&seed, account)?;
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);

    Ok(NostrKeypair {
        secret_key,
        public_key,
    })
}

pub fn generate_random_nostr_keypair() -> NostrKeypair {
    let secret_key = SecretKey::new(&mut OsRng);
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);

    NostrKeypair {
        secret_key,
        public_key,
    }
}

fn derive_secret_key(seed: &[u8; 64], account: u32) -> Result<SecretKey> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master_key = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
    let path = DerivationPath::from_str(&format!("m/44'/1237'/{}'/0/0", account))?;
    let derived_key = master_key.derive_priv(&secp, &path)?;

    Ok(SecretKey::from_slice(
        &derived_key.private_key.secret_bytes(),
    )?)
}

/// Decode an npub (bech32) to hex pubkey string.
pub fn decode_npub(npub: &str) -> Result<String> {
    let bytes = bech32::decode_npub(npub)?;
    Ok(hex::encode(bytes))
}
