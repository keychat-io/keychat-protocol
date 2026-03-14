//! # SQLCipher Persistent Storage
//!
//! Phase 8: AES-256 encrypted database for all protocol state.
//! Uses SQLCipher (via rusqlite bundled-sqlcipher) for transparent encryption.
//!
//! The encryption key is a passphrase provided by the caller — SQLCipher
//! derives the actual AES key via PBKDF2 internally.

use crate::error::{KeychatError, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Serializable version of a derived address for storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivedAddressSerialized {
    pub address: String,
    pub secret_key: String,
    pub ratchet_key: String,
}

/// Serializable version of PeerAddressState for storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerAddressStateSerialized {
    pub receiving_addresses: Vec<DerivedAddressSerialized>,
    pub sending_address: Option<String>,
    pub peer_first_inbox: Option<String>,
    pub peer_nostr_pubkey: Option<String>,
}

/// Peer mapping record (nostr pubkey ↔ signal identity).
#[derive(Debug, Clone, PartialEq)]
pub struct PeerMapping {
    pub nostr_pubkey: String,
    pub signal_id: String,
    pub name: String,
    pub created_at: i64,
}

/// SQLCipher-encrypted persistent storage for all protocol state.
pub struct SecureStorage {
    conn: Connection,
}

impl SecureStorage {
    /// Open (or create) an encrypted database at `path`.
    /// `key` is the encryption passphrase for SQLCipher.
    pub fn open(path: &str, key: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| KeychatError::Storage(format!("Failed to open database: {e}")))?;
        Self::init(conn, key)
    }

    /// Open an in-memory encrypted database (for tests).
    pub fn open_in_memory(key: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| KeychatError::Storage(format!("Failed to open in-memory db: {e}")))?;
        Self::init(conn, key)
    }

    /// Common initialization: set encryption key, pragmas, create schema.
    fn init(conn: Connection, key: &str) -> Result<Self> {
        // Escape single quotes in key for SQL safety
        let escaped_key = key.replace('\'', "''");
        conn.execute_batch(&format!(
            "PRAGMA key = '{escaped_key}'; \
             PRAGMA cipher_page_size = 4096; \
             PRAGMA journal_mode = WAL;"
        ))
        .map_err(|e| KeychatError::Storage(format!("Failed to set encryption pragmas: {e}")))?;

        // Create all tables in a single transaction
        conn.execute_batch(
            "BEGIN;

            CREATE TABLE IF NOT EXISTS signal_sessions (
                address TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                record BLOB NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (address, device_id)
            );

            CREATE TABLE IF NOT EXISTS pre_keys (
                id INTEGER PRIMARY KEY,
                record BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signed_pre_keys (
                id INTEGER PRIMARY KEY,
                record BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kyber_pre_keys (
                id INTEGER PRIMARY KEY,
                record BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS identity_keys (
                address TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                private_key BLOB,
                is_own INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS peer_addresses (
                peer_signal_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                processed_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS peer_mappings (
                nostr_pubkey TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (nostr_pubkey)
            );
            CREATE INDEX IF NOT EXISTS idx_peer_signal ON peer_mappings(signal_id);

            COMMIT;",
        )
        .map_err(|e| KeychatError::Storage(format!("Failed to create schema: {e}")))?;

        Ok(Self { conn })
    }

    // ─── Signal Session Store ─────────────────────────────

    /// Save a Signal session record.
    pub fn save_session(&self, address: &str, device_id: u32, record: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_sessions (address, device_id, record, updated_at) \
                 VALUES (?1, ?2, ?3, strftime('%s','now'))",
                rusqlite::params![address, device_id, record],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save session: {e}")))?;
        Ok(())
    }

    /// Load a Signal session record.
    pub fn load_session(&self, address: &str, device_id: u32) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM signal_sessions WHERE address = ?1 AND device_id = ?2")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![address, device_id], |row: &rusqlite::Row| row.get(0))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load session: {e}")))?;

        Ok(result)
    }

    /// List all session addresses.
    pub fn list_sessions(&self) -> Result<Vec<(String, u32)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, device_id FROM signal_sessions")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })
            .map_err(|e| KeychatError::Storage(format!("Failed to list sessions: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let pair: (String, u32) = row
                .map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?;
            results.push(pair);
        }
        Ok(results)
    }

    /// Delete a session.
    pub fn delete_session(&self, address: &str, device_id: u32) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM signal_sessions WHERE address = ?1 AND device_id = ?2",
                rusqlite::params![address, device_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete session: {e}")))?;
        Ok(())
    }

    // ─── PreKey Store ─────────────────────────────────────

    /// Save a pre-key.
    pub fn save_pre_key(&self, id: u32, record: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO pre_keys (id, record) VALUES (?1, ?2)",
                rusqlite::params![id, record],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save pre-key: {e}")))?;
        Ok(())
    }

    /// Load a pre-key.
    pub fn load_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM pre_keys WHERE id = ?1")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![id], |row: &rusqlite::Row| row.get(0))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load pre-key: {e}")))?;

        Ok(result)
    }

    /// Remove a pre-key (consumed after use).
    pub fn remove_pre_key(&self, id: u32) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM pre_keys WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to remove pre-key: {e}")))?;
        Ok(())
    }

    // ─── Signed PreKey Store ──────────────────────────────

    /// Save a signed pre-key.
    pub fn save_signed_pre_key(&self, id: u32, record: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signed_pre_keys (id, record) VALUES (?1, ?2)",
                rusqlite::params![id, record],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save signed pre-key: {e}")))?;
        Ok(())
    }

    /// Load a signed pre-key.
    pub fn load_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM signed_pre_keys WHERE id = ?1")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![id], |row: &rusqlite::Row| row.get(0))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load signed pre-key: {e}")))?;

        Ok(result)
    }

    // ─── Kyber PreKey Store ───────────────────────────────

    /// Save a Kyber pre-key.
    pub fn save_kyber_pre_key(&self, id: u32, record: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO kyber_pre_keys (id, record) VALUES (?1, ?2)",
                rusqlite::params![id, record],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save kyber pre-key: {e}")))?;
        Ok(())
    }

    /// Load a Kyber pre-key.
    pub fn load_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM kyber_pre_keys WHERE id = ?1")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![id], |row: &rusqlite::Row| row.get(0))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load kyber pre-key: {e}")))?;

        Ok(result)
    }

    /// Remove a Kyber pre-key (consumed after use).
    pub fn remove_kyber_pre_key(&self, id: u32) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM kyber_pre_keys WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to remove kyber pre-key: {e}")))?;
        Ok(())
    }

    // ─── Identity Store ───────────────────────────────────

    /// Save our own identity key pair.
    pub fn save_identity_key(
        &self,
        address: &str,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO identity_keys (address, public_key, private_key, is_own) \
                 VALUES (?1, ?2, ?3, 1)",
                rusqlite::params![address, public_key, private_key],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save identity key: {e}")))?;
        Ok(())
    }

    /// Load our identity key pair.
    pub fn load_identity_key(&self, address: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key, private_key FROM identity_keys \
                 WHERE address = ?1 AND is_own = 1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![address], |row: &rusqlite::Row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load identity key: {e}")))?;

        Ok(result)
    }

    /// Save a peer's identity key (for trust verification).
    pub fn save_peer_identity(&self, address: &str, public_key: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO identity_keys (address, public_key, private_key, is_own) \
                 VALUES (?1, ?2, NULL, 0)",
                rusqlite::params![address, public_key],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save peer identity: {e}")))?;
        Ok(())
    }

    /// Load a peer's identity key.
    pub fn load_peer_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key FROM identity_keys WHERE address = ?1 AND is_own = 0")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![address], |row: &rusqlite::Row| row.get(0))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load peer identity: {e}")))?;

        Ok(result)
    }

    // ─── Address Manager State ────────────────────────────

    /// Save a peer's address state (serialized as JSON).
    pub fn save_peer_addresses(
        &self,
        peer_signal_id: &str,
        state: &PeerAddressStateSerialized,
    ) -> Result<()> {
        let json = serde_json::to_string(state)
            .map_err(|e| KeychatError::Storage(format!("Failed to serialize state: {e}")))?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO peer_addresses (peer_signal_id, state_json, updated_at) \
                 VALUES (?1, ?2, strftime('%s','now'))",
                rusqlite::params![peer_signal_id, json],
            )
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to save peer addresses: {e}"))
            })?;
        Ok(())
    }

    /// Load all peer address states.
    pub fn load_all_peer_addresses(
        &self,
    ) -> Result<Vec<(String, PeerAddressStateSerialized)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_signal_id, state_json FROM peer_addresses")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to load peer addresses: {e}"))
            })?;

        let mut results = Vec::new();
        for row in rows {
            let (id, json) = row
                .map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?;
            let state: PeerAddressStateSerialized = serde_json::from_str(&json)
                .map_err(|e| KeychatError::Storage(format!("Failed to deserialize state: {e}")))?;
            results.push((id, state));
        }
        Ok(results)
    }

    // ─── Event Deduplication ──────────────────────────────

    /// Mark an event ID as processed.
    pub fn mark_event_processed(&self, event_id: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO processed_events (event_id, processed_at) \
                 VALUES (?1, strftime('%s','now'))",
                rusqlite::params![event_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to mark event: {e}")))?;
        Ok(())
    }

    /// Check if an event was already processed.
    pub fn is_event_processed(&self, event_id: &str) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM processed_events WHERE event_id = ?1")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let exists = stmt
            .query_row(rusqlite::params![event_id], |_| Ok(()))
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to check event: {e}")))?
            .is_some();

        Ok(exists)
    }

    /// Prune old processed events (keep only those newer than max_age_secs).
    /// Returns the number of pruned rows.
    pub fn prune_processed_events(&self, max_age_secs: u64) -> Result<u64> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM processed_events WHERE processed_at < (strftime('%s','now') - ?1)",
                rusqlite::params![max_age_secs as i64],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prune events: {e}")))?;

        Ok(deleted as u64)
    }

    // ─── Peer Mapping ─────────────────────────────────────

    /// Save peer mapping (nostr pubkey → signal identity).
    pub fn save_peer_mapping(
        &self,
        nostr_pubkey: &str,
        signal_id: &str,
        name: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO peer_mappings (nostr_pubkey, signal_id, name, created_at) \
                 VALUES (?1, ?2, ?3, strftime('%s','now'))",
                rusqlite::params![nostr_pubkey, signal_id, name],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save peer mapping: {e}")))?;
        Ok(())
    }

    /// Load peer mapping by nostr pubkey.
    pub fn load_peer_by_nostr(&self, nostr_pubkey: &str) -> Result<Option<PeerMapping>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT nostr_pubkey, signal_id, name, created_at \
                 FROM peer_mappings WHERE nostr_pubkey = ?1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![nostr_pubkey], |row: &rusqlite::Row| {
                Ok(PeerMapping {
                    nostr_pubkey: row.get(0)?,
                    signal_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load peer: {e}")))?;

        Ok(result)
    }

    /// Load peer mapping by signal identity.
    pub fn load_peer_by_signal(&self, signal_id: &str) -> Result<Option<PeerMapping>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT nostr_pubkey, signal_id, name, created_at \
                 FROM peer_mappings WHERE signal_id = ?1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![signal_id], |row: &rusqlite::Row| {
                Ok(PeerMapping {
                    nostr_pubkey: row.get(0)?,
                    signal_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load peer: {e}")))?;

        Ok(result)
    }

    /// List all peers.
    pub fn list_peers(&self) -> Result<Vec<PeerMapping>> {
        let mut stmt = self
            .conn
            .prepare("SELECT nostr_pubkey, signal_id, name, created_at FROM peer_mappings")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| {
                Ok(PeerMapping {
                    nostr_pubkey: row.get(0)?,
                    signal_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(|e| KeychatError::Storage(format!("Failed to list peers: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(
                row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?,
            );
        }
        Ok(results)
    }
}

/// Trait extension for rusqlite optional results.
trait OptionalExt<T> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_KEY: &str = "test-passphrase-for-sqlcipher-2024";

    #[test]
    fn test_open_close_reopen_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap();

        // Create and write
        {
            let store = SecureStorage::open(path_str, TEST_KEY).unwrap();
            store.save_pre_key(1, b"key-data-1").unwrap();
        }

        // Reopen with same key — data persists
        {
            let store = SecureStorage::open(path_str, TEST_KEY).unwrap();
            let loaded = store.load_pre_key(1).unwrap();
            assert_eq!(loaded, Some(b"key-data-1".to_vec()));
        }
    }

    #[test]
    fn test_wrong_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_wrong_key.db");
        let path_str = path.to_str().unwrap();

        // Create with correct key
        {
            let store = SecureStorage::open(path_str, TEST_KEY).unwrap();
            store.save_pre_key(1, b"secret").unwrap();
        }

        // Reopen with wrong key — should fail
        let result = SecureStorage::open(path_str, "wrong-key");
        assert!(result.is_err(), "Opening with wrong key should fail");
    }

    #[test]
    fn test_signal_session_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Save
        store
            .save_session("alice", 1, b"session-record-1")
            .unwrap();
        store
            .save_session("alice", 2, b"session-record-2")
            .unwrap();
        store.save_session("bob", 1, b"session-record-3").unwrap();

        // Load
        let s1 = store.load_session("alice", 1).unwrap();
        assert_eq!(s1, Some(b"session-record-1".to_vec()));

        let s2 = store.load_session("alice", 2).unwrap();
        assert_eq!(s2, Some(b"session-record-2".to_vec()));

        // List
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 3);

        // Delete
        store.delete_session("alice", 1).unwrap();
        let deleted = store.load_session("alice", 1).unwrap();
        assert!(deleted.is_none());

        // Remaining
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_prekey_lifecycle() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        store.save_pre_key(42, b"prekey-42").unwrap();
        let loaded = store.load_pre_key(42).unwrap();
        assert_eq!(loaded, Some(b"prekey-42".to_vec()));

        // Consume (remove)
        store.remove_pre_key(42).unwrap();
        let removed = store.load_pre_key(42).unwrap();
        assert!(removed.is_none());

        // Remove non-existent — no error
        store.remove_pre_key(999).unwrap();
    }

    #[test]
    fn test_signed_prekey_and_kyber() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Signed pre-key
        store.save_signed_pre_key(1, b"signed-pk-1").unwrap();
        let loaded = store.load_signed_pre_key(1).unwrap();
        assert_eq!(loaded, Some(b"signed-pk-1".to_vec()));

        // Kyber pre-key
        store.save_kyber_pre_key(100, b"kyber-pk-100").unwrap();
        let loaded = store.load_kyber_pre_key(100).unwrap();
        assert_eq!(loaded, Some(b"kyber-pk-100".to_vec()));

        // Remove kyber
        store.remove_kyber_pre_key(100).unwrap();
        assert!(store.load_kyber_pre_key(100).unwrap().is_none());
    }

    #[test]
    fn test_identity_key_persistence() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Own key pair
        let pub_key = b"own-public-key-32bytes-xxxxxxxxx";
        let priv_key = b"own-private-key-32bytes-xxxxxxxx";
        store
            .save_identity_key("self", pub_key, priv_key)
            .unwrap();
        let loaded = store.load_identity_key("self").unwrap();
        assert_eq!(loaded, Some((pub_key.to_vec(), priv_key.to_vec())));

        // Peer key
        let peer_pub = b"peer-public-key-32bytes-xxxxxxxx";
        store.save_peer_identity("alice", peer_pub).unwrap();
        let loaded_peer = store.load_peer_identity("alice").unwrap();
        assert_eq!(loaded_peer, Some(peer_pub.to_vec()));

        // Non-existent peer
        assert!(store.load_peer_identity("unknown").unwrap().is_none());
    }

    #[test]
    fn test_peer_address_state_roundtrip() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        let state = PeerAddressStateSerialized {
            receiving_addresses: vec![
                DerivedAddressSerialized {
                    address: "addr1".into(),
                    secret_key: "sk1".into(),
                    ratchet_key: "rk1".into(),
                },
                DerivedAddressSerialized {
                    address: "addr2".into(),
                    secret_key: "sk2".into(),
                    ratchet_key: "rk2".into(),
                },
            ],
            sending_address: Some("send-addr".into()),
            peer_first_inbox: Some("inbox-addr".into()),
            peer_nostr_pubkey: Some("npub1abc".into()),
        };

        store.save_peer_addresses("signal-id-alice", &state).unwrap();

        let all = store.load_all_peer_addresses().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "signal-id-alice");
        assert_eq!(all[0].1, state);
    }

    #[test]
    fn test_event_dedup() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        assert!(!store.is_event_processed("evt1").unwrap());

        store.mark_event_processed("evt1").unwrap();
        assert!(store.is_event_processed("evt1").unwrap());

        // Double-mark is fine (INSERT OR IGNORE)
        store.mark_event_processed("evt1").unwrap();
        assert!(store.is_event_processed("evt1").unwrap());

        // Different event
        assert!(!store.is_event_processed("evt2").unwrap());
    }

    #[test]
    fn test_prune_processed_events() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Insert an event with an old timestamp
        store.conn.execute(
            "INSERT INTO processed_events (event_id, processed_at) VALUES ('old-evt', 1000)",
            [],
        ).unwrap();
        store.mark_event_processed("new-evt").unwrap();

        // Prune events older than 1 day (the old one is from epoch + 1000s)
        let pruned = store.prune_processed_events(86400).unwrap();
        assert_eq!(pruned, 1);

        assert!(!store.is_event_processed("old-evt").unwrap());
        assert!(store.is_event_processed("new-evt").unwrap());
    }

    #[test]
    fn test_peer_mapping_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        store
            .save_peer_mapping("npub1alice", "signal-alice", "Alice")
            .unwrap();
        store
            .save_peer_mapping("npub1bob", "signal-bob", "Bob")
            .unwrap();

        // Lookup by nostr
        let alice = store.load_peer_by_nostr("npub1alice").unwrap().unwrap();
        assert_eq!(alice.signal_id, "signal-alice");
        assert_eq!(alice.name, "Alice");

        // Lookup by signal
        let bob = store.load_peer_by_signal("signal-bob").unwrap().unwrap();
        assert_eq!(bob.nostr_pubkey, "npub1bob");
        assert_eq!(bob.name, "Bob");

        // List all
        let all = store.list_peers().unwrap();
        assert_eq!(all.len(), 2);

        // Non-existent
        assert!(store.load_peer_by_nostr("npub1unknown").unwrap().is_none());
        assert!(store.load_peer_by_signal("signal-unknown").unwrap().is_none());
    }

    #[test]
    fn test_in_memory_mode() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // All basic operations should work
        store.save_session("test", 1, b"record").unwrap();
        store.save_pre_key(1, b"pk").unwrap();
        store.save_signed_pre_key(1, b"spk").unwrap();
        store.save_kyber_pre_key(1, b"kpk").unwrap();
        store.save_identity_key("self", b"pub", b"priv").unwrap();
        store.save_peer_identity("peer", b"pub").unwrap();
        store.mark_event_processed("evt").unwrap();
        store.save_peer_mapping("npub", "sig", "name").unwrap();

        assert!(store.load_session("test", 1).unwrap().is_some());
        assert!(store.load_pre_key(1).unwrap().is_some());
        assert!(store.load_signed_pre_key(1).unwrap().is_some());
        assert!(store.load_kyber_pre_key(1).unwrap().is_some());
        assert!(store.load_identity_key("self").unwrap().is_some());
        assert!(store.load_peer_identity("peer").unwrap().is_some());
        assert!(store.is_event_processed("evt").unwrap());
        assert!(store.load_peer_by_nostr("npub").unwrap().is_some());
    }

    #[test]
    fn test_concurrent_reads() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        for i in 0..10 {
            store
                .save_session(&format!("addr-{i}"), 1, format!("record-{i}").as_bytes())
                .unwrap();
        }

        // Multiple reads don't conflict (WAL mode)
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 10);

        for i in 0..10 {
            let s = store.load_session(&format!("addr-{i}"), 1).unwrap();
            assert!(s.is_some());
        }
    }

    #[test]
    fn test_large_dataset() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // 1000 sessions
        for i in 0..1000 {
            store
                .save_session(&format!("addr-{i}"), 1, &vec![i as u8; 256])
                .unwrap();
        }

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1000);

        // 10000 events
        for i in 0..10000 {
            store
                .mark_event_processed(&format!("event-{i}"))
                .unwrap();
        }

        // Verify random lookups
        assert!(store.is_event_processed("event-5000").unwrap());
        assert!(!store.is_event_processed("event-99999").unwrap());

        let s = store.load_session("addr-500", 1).unwrap().unwrap();
        assert_eq!(s.len(), 256);
    }

    #[test]
    fn test_update_existing_session() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        store.save_session("alice", 1, b"version-1").unwrap();
        store.save_session("alice", 1, b"version-2").unwrap();

        let loaded = store.load_session("alice", 1).unwrap();
        assert_eq!(loaded, Some(b"version-2".to_vec()));
    }
}
