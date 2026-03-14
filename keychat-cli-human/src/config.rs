//! Configuration persistence.
//!
//! **Security**: Mnemonic and DB encryption key are stored in the OS keychain
//! (macOS Keychain, Linux secret service) via the `keyring` crate.
//! Only non-sensitive settings are stored in config.json.

use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Service name for keychain entries.
const KEYRING_SERVICE: &str = "keychat-cli";

/// Non-sensitive configuration (stored as JSON on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Display name for this identity.
    pub name: String,
    /// Relay URLs.
    pub relays: Vec<String>,
    /// Whether to auto-accept friend requests (first becomes owner, others need approval).
    #[serde(default)]
    pub auto_accept_friends: bool,
    /// Owner's nostr pubkey (hex). First peer to add us becomes owner.
    #[serde(default)]
    pub owner: Option<String>,
    /// Public key hex — used as keychain username to scope secrets per identity.
    #[serde(default)]
    pub pubkey_hex: Option<String>,
}

impl Config {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("config.json")
    }

    pub fn load(data_dir: &Path) -> Result<Option<Self>> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(&content)?))
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = Self::path(data_dir);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

// ─── Secure keychain storage ────────────────────────────────────────────────

/// Store the mnemonic in the OS keychain.
pub fn store_mnemonic(pubkey_hex: &str, mnemonic: &str) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("mnemonic:{}", pubkey_hex))
        .context("failed to create keychain entry for mnemonic")?;
    entry.set_password(mnemonic)
        .context("failed to store mnemonic in keychain")?;
    Ok(())
}

/// Retrieve the mnemonic from the OS keychain.
pub fn load_mnemonic(pubkey_hex: &str) -> Result<String> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("mnemonic:{}", pubkey_hex))
        .context("failed to create keychain entry for mnemonic")?;
    entry.get_password()
        .context("mnemonic not found in keychain — identity may need to be re-imported")
}

/// Store the DB encryption key in the OS keychain.
pub fn store_db_key(pubkey_hex: &str, db_key: &str) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("dbkey:{}", pubkey_hex))
        .context("failed to create keychain entry for DB key")?;
    entry.set_password(db_key)
        .context("failed to store DB key in keychain")?;
    Ok(())
}

/// Retrieve the DB encryption key from the OS keychain.
pub fn load_db_key(pubkey_hex: &str) -> Result<String> {
    let entry = Entry::new(KEYRING_SERVICE, &format!("dbkey:{}", pubkey_hex))
        .context("failed to create keychain entry for DB key")?;
    entry.get_password()
        .context("DB key not found in keychain")
}

/// Generate a random DB encryption key (hex-encoded 32 bytes).
pub fn generate_db_key() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    hex::encode(key)
}

/// Check if a mnemonic exists in the keychain for this identity.
pub fn has_mnemonic(pubkey_hex: &str) -> bool {
    load_mnemonic(pubkey_hex).is_ok()
}
