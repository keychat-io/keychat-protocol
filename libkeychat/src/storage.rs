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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivedAddressSerialized {
    pub address: String,
    pub secret_key: String,
    pub ratchet_key: String,
}

impl std::fmt::Debug for DerivedAddressSerialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedAddressSerialized")
            .field("address", &self.address)
            .field(
                "secret_key",
                &format!("{}...", &self.secret_key[..16.min(self.secret_key.len())]),
            )
            .field(
                "ratchet_key",
                &format!("{}...", &self.ratchet_key[..16.min(self.ratchet_key.len())]),
            )
            .finish()
    }
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

// ─── App Data Row Types ─────────────────────────────────

/// Identity metadata row.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityRow {
    pub npub: String,
    pub nostr_pubkey_hex: String,
    pub name: String,
    pub avatar: Option<String>,
    pub idx: i32,
    pub is_default: bool,
    pub created_at: i64,
}

/// Room metadata row.
#[derive(Debug, Clone, PartialEq)]
pub struct RoomRow {
    pub id: String,
    pub to_main_pubkey: String,
    pub identity_pubkey: String,
    pub status: i32,
    pub room_type: i32,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub peer_signal_identity_key: Option<String>,
    pub last_message_content: Option<String>,
    pub last_message_at: Option<i64>,
    pub unread_count: i32,
    pub created_at: i64,
}

/// Message row.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageRow {
    pub msgid: String,
    pub event_id: Option<String>,
    pub room_id: String,
    pub identity_pubkey: String,
    pub sender_pubkey: String,
    pub content: String,
    pub is_me_send: bool,
    pub is_read: bool,
    pub status: i32,
    pub reply_to_event_id: Option<String>,
    pub reply_to_content: Option<String>,
    pub payload_json: Option<String>,
    pub nostr_event_json: Option<String>,
    pub relay_status_json: Option<String>,
    pub local_file_path: Option<String>,
    pub created_at: i64,
}

/// Contact row.
#[derive(Debug, Clone, PartialEq)]
pub struct ContactRow {
    pub id: String,
    pub pubkey: String,
    pub npubkey: String,
    pub identity_pubkey: String,
    pub signal_identity_key: Option<String>,
    pub petname: Option<String>,
    pub name: Option<String>,
    pub about: Option<String>,
    pub avatar: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
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

    /// Common initialization: set encryption key, pragmas, run migrations.
    fn init(conn: Connection, key: &str) -> Result<Self> {
        // Use pragma API to avoid SQL injection risk (C-SEC5)
        conn.pragma_update(None, "key", key)
            .map_err(|e| KeychatError::Storage(format!("Failed to set encryption key: {e}")))?;
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096; \
             PRAGMA journal_mode = WAL;",
        )
        .map_err(|e| KeychatError::Storage(format!("Failed to set pragmas: {e}")))?;

        // Run versioned migrations
        Self::run_migrations(&conn)?;

        Ok(Self { conn })
    }

    /// Execute multiple operations in a single transaction.
    /// If the closure returns Ok, the transaction is committed.
    /// If it returns Err or panics, the transaction is rolled back.
    pub fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| KeychatError::Storage(format!("begin transaction: {e}")))?;
        let result = f(&self.conn)?;
        tx.commit()
            .map_err(|e| KeychatError::Storage(format!("commit transaction: {e}")))?;
        Ok(result)
    }

    /// Schema version. Increment when adding a new migration.
    const SCHEMA_VERSION: u32 = 2;

    /// Run all pending migrations sequentially.
    fn run_migrations(conn: &Connection) -> Result<()> {
        let current: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to read user_version: {e}")))?;

        tracing::info!(
            "database schema version: {current}, target: {}",
            Self::SCHEMA_VERSION
        );

        if current < 1 {
            Self::migrate_v0_to_v1(conn)?;
        }
        if current < 2 {
            Self::migrate_v1_to_v2(conn)?;
        }

        Ok(())
    }

    /// V0 → V1: Create all base tables (initial schema).
    fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
        tracing::info!("running migration v0 → v1: create base schema");
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

            CREATE TABLE IF NOT EXISTS signal_participants (
                peer_signal_id TEXT PRIMARY KEY,
                device_id INTEGER NOT NULL,
                identity_public BLOB NOT NULL,
                identity_private BLOB NOT NULL,
                registration_id INTEGER NOT NULL,
                signed_prekey_id INTEGER NOT NULL,
                signed_prekey_record BLOB NOT NULL,
                prekey_id INTEGER NOT NULL,
                prekey_record BLOB NOT NULL,
                kyber_prekey_id INTEGER NOT NULL,
                kyber_prekey_record BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS pending_friend_requests (
                request_id TEXT PRIMARY KEY,
                device_id INTEGER NOT NULL,
                identity_public BLOB NOT NULL,
                identity_private BLOB NOT NULL,
                registration_id INTEGER NOT NULL,
                signed_prekey_id INTEGER NOT NULL,
                signed_prekey_record BLOB NOT NULL,
                prekey_id INTEGER NOT NULL,
                prekey_record BLOB NOT NULL,
                kyber_prekey_id INTEGER NOT NULL,
                kyber_prekey_record BLOB NOT NULL,
                first_inbox_secret TEXT NOT NULL,
                peer_nostr_pubkey TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS inbound_friend_requests (
                request_id TEXT PRIMARY KEY,
                sender_pubkey_hex TEXT NOT NULL,
                message_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_inbound_fr_sender ON inbound_friend_requests(sender_pubkey_hex);

            CREATE TABLE IF NOT EXISTS signal_groups (
                group_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS mls_group_ids (
                group_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS relays (
                url TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS app_identities (
                nostr_pubkey_hex TEXT PRIMARY KEY,
                npub TEXT NOT NULL,
                name TEXT NOT NULL,
                avatar TEXT,
                idx INTEGER NOT NULL DEFAULT 0,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS app_rooms (
                id TEXT PRIMARY KEY,
                to_main_pubkey TEXT NOT NULL,
                identity_pubkey TEXT NOT NULL,
                status INTEGER NOT NULL DEFAULT 0,
                type INTEGER NOT NULL DEFAULT 0,
                name TEXT,
                avatar TEXT,
                peer_signal_identity_key TEXT,
                last_message_content TEXT,
                last_message_at INTEGER,
                unread_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(to_main_pubkey, identity_pubkey)
            );
            CREATE INDEX IF NOT EXISTS idx_app_rooms_identity ON app_rooms(identity_pubkey, last_message_at);
            CREATE INDEX IF NOT EXISTS idx_app_rooms_pubkey ON app_rooms(to_main_pubkey);

            CREATE TABLE IF NOT EXISTS app_messages (
                msgid TEXT PRIMARY KEY,
                event_id TEXT UNIQUE,
                room_id TEXT NOT NULL,
                identity_pubkey TEXT NOT NULL,
                sender_pubkey TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                is_me_send INTEGER NOT NULL DEFAULT 0,
                is_read INTEGER NOT NULL DEFAULT 0,
                status INTEGER NOT NULL DEFAULT 0,
                reply_to_event_id TEXT,
                reply_to_content TEXT,
                payload_json TEXT,
                nostr_event_json TEXT,
                relay_status_json TEXT,
                local_file_path TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_app_messages_room ON app_messages(room_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_app_messages_unread ON app_messages(room_id, is_read) WHERE is_read = 0;
            CREATE INDEX IF NOT EXISTS idx_app_messages_failed ON app_messages(is_me_send, status) WHERE is_me_send = 1 AND status = 2;

            CREATE TABLE IF NOT EXISTS app_contacts (
                id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                npubkey TEXT NOT NULL,
                identity_pubkey TEXT NOT NULL,
                signal_identity_key TEXT,
                petname TEXT,
                name TEXT,
                about TEXT,
                avatar TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(pubkey, identity_pubkey)
            );
            CREATE INDEX IF NOT EXISTS idx_app_contacts_identity ON app_contacts(identity_pubkey);

            CREATE INDEX IF NOT EXISTS idx_processed_events_at ON processed_events(processed_at);

            PRAGMA user_version = 1;

            COMMIT;",
        )
        .map_err(|e| KeychatError::Storage(format!("migration v0→v1 failed: {e}")))?;

        tracing::info!("migration v0 → v1 complete");
        Ok(())
    }

    /// V1 → V2: Add peer_nostr_pubkey to pending_friend_requests, create inbound_friend_requests.
    /// This migration handles databases created before the versioning system was added.
    fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
        tracing::info!("running migration v1 → v2: friend request columns");

        // For databases that were v0 but now v1 (which already includes peer_nostr_pubkey
        // and inbound_friend_requests in the base schema), these will be no-ops.
        // For databases upgraded from the old ad-hoc system, these apply the changes.
        let _ = conn.execute_batch(
            "ALTER TABLE pending_friend_requests ADD COLUMN peer_nostr_pubkey TEXT NOT NULL DEFAULT '';"
        );
        let _ = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS inbound_friend_requests (
                request_id TEXT PRIMARY KEY,
                sender_pubkey_hex TEXT NOT NULL,
                message_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );"
        );

        conn.pragma_update(None, "user_version", 2)
            .map_err(|e| KeychatError::Storage(format!("Failed to update user_version: {e}")))?;

        tracing::info!("migration v1 → v2 complete");
        Ok(())
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
            .query_row(
                rusqlite::params![address, device_id],
                |row: &rusqlite::Row| row.get(0),
            )
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
            let pair: (String, u32) =
                row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?;
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
            .execute("DELETE FROM pre_keys WHERE id = ?1", rusqlite::params![id])
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
            .map_err(|e| KeychatError::Storage(format!("Failed to save peer addresses: {e}")))?;
        Ok(())
    }

    /// Load all peer address states.
    pub fn load_all_peer_addresses(&self) -> Result<Vec<(String, PeerAddressStateSerialized)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_signal_id, state_json FROM peer_addresses")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| KeychatError::Storage(format!("Failed to load peer addresses: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let (id, json) =
                row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?;
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
    pub fn save_peer_mapping(&self, nostr_pubkey: &str, signal_id: &str, name: &str) -> Result<()> {
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

    /// Delete a peer mapping.
    pub fn delete_peer_mapping(&self, nostr_pubkey: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM peer_mappings WHERE nostr_pubkey = ?1",
                rusqlite::params![nostr_pubkey],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete peer mapping: {e}")))?;
        Ok(())
    }

    /// Delete peer addresses.
    pub fn delete_peer_addresses(&self, peer_signal_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM peer_addresses WHERE peer_signal_id = ?1",
                rusqlite::params![peer_signal_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete peer addresses: {e}")))?;
        Ok(())
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
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    // ─── Signal Participant Key Material ────────────────────

    /// Serialized Signal pre-key material for persistence.
    /// Used to reconstruct `SignalParticipant::persistent()` on restart.
    #[allow(clippy::too_many_arguments)]
    pub fn save_signal_participant(
        &self,
        peer_signal_id: &str,
        device_id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        registration_id: u32,
        signed_prekey_id: u32,
        signed_prekey_record: &[u8],
        prekey_id: u32,
        prekey_record: &[u8],
        kyber_prekey_id: u32,
        kyber_prekey_record: &[u8],
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_participants \
                 (peer_signal_id, device_id, identity_public, identity_private, \
                  registration_id, signed_prekey_id, signed_prekey_record, \
                  prekey_id, prekey_record, kyber_prekey_id, kyber_prekey_record, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, strftime('%s','now'))",
                rusqlite::params![
                    peer_signal_id,
                    device_id,
                    identity_public,
                    identity_private,
                    registration_id,
                    signed_prekey_id,
                    signed_prekey_record,
                    prekey_id,
                    prekey_record,
                    kyber_prekey_id,
                    kyber_prekey_record,
                ],
            )
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to save signal participant: {e}"))
            })?;
        Ok(())
    }

    /// Load signal participant key material.
    /// Returns (device_id, identity_public, identity_private, registration_id,
    ///          signed_prekey_id, signed_prekey_record, prekey_id, prekey_record,
    ///          kyber_prekey_id, kyber_prekey_record).
    #[allow(clippy::type_complexity)]
    pub fn load_signal_participant(
        &self,
        peer_signal_id: &str,
    ) -> Result<
        Option<(
            u32,
            Vec<u8>,
            Vec<u8>,
            u32,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
        )>,
    > {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT device_id, identity_public, identity_private, registration_id, \
                 signed_prekey_id, signed_prekey_record, prekey_id, prekey_record, \
                 kyber_prekey_id, kyber_prekey_record \
                 FROM signal_participants WHERE peer_signal_id = ?1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![peer_signal_id], |row: &rusqlite::Row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, u32>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, u32>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })
            .optional()
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to load signal participant: {e}"))
            })?;

        Ok(result)
    }

    /// List all signal participant peer_signal_ids.
    pub fn list_signal_participants(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_signal_id FROM signal_participants")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| row.get(0))
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to list signal participants: {e}"))
            })?;

        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    /// Delete a signal participant.
    pub fn delete_signal_participant(&self, peer_signal_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM signal_participants WHERE peer_signal_id = ?1",
                rusqlite::params![peer_signal_id],
            )
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to delete signal participant: {e}"))
            })?;
        Ok(())
    }

    // ─── Pending Friend Requests ──────────────────────────

    /// Save a pending friend request's key material.
    #[allow(clippy::too_many_arguments)]
    pub fn save_pending_fr(
        &self,
        request_id: &str,
        device_id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        registration_id: u32,
        signed_prekey_id: u32,
        signed_prekey_record: &[u8],
        prekey_id: u32,
        prekey_record: &[u8],
        kyber_prekey_id: u32,
        kyber_prekey_record: &[u8],
        first_inbox_secret: &str,
        peer_nostr_pubkey: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO pending_friend_requests \
                 (request_id, device_id, identity_public, identity_private, \
                  registration_id, signed_prekey_id, signed_prekey_record, \
                  prekey_id, prekey_record, kyber_prekey_id, kyber_prekey_record, \
                  first_inbox_secret, peer_nostr_pubkey, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, strftime('%s','now'))",
                rusqlite::params![
                    request_id,
                    device_id,
                    identity_public,
                    identity_private,
                    registration_id,
                    signed_prekey_id,
                    signed_prekey_record,
                    prekey_id,
                    prekey_record,
                    kyber_prekey_id,
                    kyber_prekey_record,
                    first_inbox_secret,
                    peer_nostr_pubkey,
                ],
            )
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to save pending FR: {e}"))
            })?;
        Ok(())
    }

    /// Load a pending friend request.
    /// Returns (device_id, identity_public, identity_private, registration_id,
    ///          signed_prekey_id, signed_prekey_record, prekey_id, prekey_record,
    ///          kyber_prekey_id, kyber_prekey_record, first_inbox_secret, peer_nostr_pubkey).
    #[allow(clippy::type_complexity)]
    pub fn load_pending_fr(
        &self,
        request_id: &str,
    ) -> Result<
        Option<(
            u32,
            Vec<u8>,
            Vec<u8>,
            u32,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            String,
            String,
        )>,
    > {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT device_id, identity_public, identity_private, registration_id, \
                 signed_prekey_id, signed_prekey_record, prekey_id, prekey_record, \
                 kyber_prekey_id, kyber_prekey_record, first_inbox_secret, peer_nostr_pubkey \
                 FROM pending_friend_requests WHERE request_id = ?1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![request_id], |row: &rusqlite::Row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, u32>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, u32>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load pending FR: {e}")))?;

        Ok(result)
    }

    /// Delete a pending friend request.
    pub fn delete_pending_fr(&self, request_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM pending_friend_requests WHERE request_id = ?1",
                rusqlite::params![request_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete pending FR: {e}")))?;
        Ok(())
    }

    /// Promote a pending friend request to an active signal participant.
    /// Loads the pending FR key material, saves it as a participant, then deletes the pending FR.
    pub fn promote_pending_fr(&self, request_id: &str, peer_signal_id: &str) -> Result<()> {
        if let Some((
            device_id,
            id_pub,
            id_priv,
            reg_id,
            spk_id,
            spk_rec,
            pk_id,
            pk_rec,
            kpk_id,
            kpk_rec,
            _first_inbox,
            _peer_nostr,
        )) = self.load_pending_fr(request_id)?
        {
            self.save_signal_participant(
                peer_signal_id,
                device_id,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
                pk_id,
                &pk_rec,
                kpk_id,
                &kpk_rec,
            )?;
            self.delete_pending_fr(request_id)?;
        }
        Ok(())
    }

    /// List all pending friend request IDs.
    pub fn list_pending_frs(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT request_id FROM pending_friend_requests")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to list pending FRs: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    // ─── Signal Groups ───────────────────────────────────

    /// Save a SignalGroup (serialized as JSON).
    pub fn save_group(&self, group_id: &str, data_json: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_groups (group_id, data_json, updated_at) \
                 VALUES (?1, ?2, strftime('%s','now'))",
                rusqlite::params![group_id, data_json],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save group: {e}")))?;
        Ok(())
    }

    /// Load a SignalGroup by group_id.
    pub fn load_group(&self, group_id: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM signal_groups WHERE group_id = ?1")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![group_id], |row: &rusqlite::Row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load group: {e}")))?;

        Ok(result)
    }

    /// Load all SignalGroups.
    pub fn load_all_groups(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, data_json FROM signal_groups")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| KeychatError::Storage(format!("Failed to load groups: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    /// Delete a SignalGroup.
    pub fn delete_group(&self, group_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM signal_groups WHERE group_id = ?1",
                rusqlite::params![group_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete group: {e}")))?;
        Ok(())
    }

    // ─── MLS Group IDs ─────────────────────────────────────

    /// Track an MLS group ID for re-subscription after restart.
    pub fn save_mls_group_id(&self, group_id: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO mls_group_ids (group_id) VALUES (?1)",
                rusqlite::params![group_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save MLS group ID: {e}")))?;
        Ok(())
    }

    /// List all tracked MLS group IDs.
    pub fn list_mls_group_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id FROM mls_group_ids")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;
        let rows = stmt
            .query_map([], |row: &rusqlite::Row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to list MLS groups: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    /// Remove an MLS group ID.
    pub fn delete_mls_group_id(&self, group_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM mls_group_ids WHERE group_id = ?1",
                rusqlite::params![group_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete MLS group ID: {e}")))?;
        Ok(())
    }

    // ─── Relays ───────────────────────────────────────────────

    /// Save a relay URL.
    pub fn save_relay(&self, url: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO relays (url) VALUES (?1)",
                rusqlite::params![url],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save relay: {e}")))?;
        Ok(())
    }

    /// Delete a relay URL.
    pub fn delete_relay(&self, url: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM relays WHERE url = ?1", rusqlite::params![url])
            .map_err(|e| KeychatError::Storage(format!("Failed to delete relay: {e}")))?;
        Ok(())
    }

    /// List all saved relay URLs.
    pub fn list_relays(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT url FROM relays ORDER BY created_at")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;
        let rows = stmt
            .query_map([], |row: &rusqlite::Row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to list relays: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    // ─── Inbound Friend Requests ─────────────────────────────

    /// Save a received (inbound) friend request.
    pub fn save_inbound_fr(
        &self,
        request_id: &str,
        sender_pubkey_hex: &str,
        message_json: &str,
        payload_json: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO inbound_friend_requests \
                 (request_id, sender_pubkey_hex, message_json, payload_json, created_at) \
                 VALUES (?1, ?2, ?3, ?4, strftime('%s','now'))",
                rusqlite::params![request_id, sender_pubkey_hex, message_json, payload_json],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to save inbound FR: {e}")))?;
        Ok(())
    }

    /// Load a received (inbound) friend request.
    /// Returns (sender_pubkey_hex, message_json, payload_json).
    pub fn load_inbound_fr(&self, request_id: &str) -> Result<Option<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sender_pubkey_hex, message_json, payload_json \
                 FROM inbound_friend_requests WHERE request_id = ?1",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![request_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .optional()
            .map_err(|e| KeychatError::Storage(format!("Failed to load inbound FR: {e}")))?;

        Ok(result)
    }

    /// List all inbound friend request IDs.
    pub fn list_inbound_frs(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT request_id FROM inbound_friend_requests")
            .map_err(|e| KeychatError::Storage(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row: &rusqlite::Row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to list inbound FRs: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results
                .push(row.map_err(|e| KeychatError::Storage(format!("Failed to read row: {e}")))?);
        }
        Ok(results)
    }

    /// Delete an inbound friend request (after accept or reject).
    pub fn delete_inbound_fr(&self, request_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM inbound_friend_requests WHERE request_id = ?1",
                rusqlite::params![request_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete inbound FR: {e}")))?;
        Ok(())
    }

    /// Look up an inbound friend request's request_id by sender pubkey.
    pub fn get_inbound_fr_request_id_by_sender(&self, sender_pubkey_hex: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT request_id FROM inbound_friend_requests WHERE sender_pubkey_hex = ?1 LIMIT 1"
        ).map_err(|e| KeychatError::Storage(format!("prepare get_inbound_fr_by_sender: {e}")))?;

        let result = stmt.query_row(rusqlite::params![sender_pubkey_hex], |row| {
            row.get::<_, String>(0)
        });

        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(KeychatError::Storage(format!("get_inbound_fr_by_sender: {e}"))),
        }
    }

    // ─── App Identity CRUD ─────────────────────────────────

    /// Save or update an identity.
    pub fn save_app_identity(
        &self,
        pubkey_hex: &str,
        npub: &str,
        name: &str,
        idx: i32,
        is_default: bool,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO app_identities (nostr_pubkey_hex, npub, name, idx, is_default, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now'))
                 ON CONFLICT(nostr_pubkey_hex) DO UPDATE SET
                   npub = excluded.npub,
                   name = excluded.name,
                   idx = excluded.idx,
                   is_default = excluded.is_default",
                rusqlite::params![pubkey_hex, npub, name, idx, is_default as i32],
            )
            .map_err(|e| KeychatError::Storage(format!("save_app_identity: {e}")))?;
        Ok(())
    }

    /// Get all identities ordered by index.
    pub fn get_app_identities(&self) -> Result<Vec<IdentityRow>> {
        let mut stmt = self.conn
            .prepare("SELECT nostr_pubkey_hex, npub, name, avatar, idx, is_default, created_at FROM app_identities ORDER BY idx")
            .map_err(|e| KeychatError::Storage(format!("get_app_identities prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(IdentityRow {
                    nostr_pubkey_hex: row.get(0)?,
                    npub: row.get(1)?,
                    name: row.get(2)?,
                    avatar: row.get(3)?,
                    idx: row.get(4)?,
                    is_default: row.get::<_, i32>(5)? != 0,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| KeychatError::Storage(format!("get_app_identities query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_identities row: {e}")))?);
        }
        Ok(result)
    }

    /// Update identity fields (only non-None values are updated).
    pub fn update_app_identity(
        &self,
        pubkey_hex: &str,
        name: Option<&str>,
        avatar: Option<&str>,
        is_default: Option<bool>,
    ) -> Result<()> {
        if let Some(n) = name {
            self.conn.execute("UPDATE app_identities SET name = ?1 WHERE nostr_pubkey_hex = ?2", rusqlite::params![n, pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("update_app_identity name: {e}")))?;
        }
        if let Some(a) = avatar {
            self.conn.execute("UPDATE app_identities SET avatar = ?1 WHERE nostr_pubkey_hex = ?2", rusqlite::params![a, pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("update_app_identity avatar: {e}")))?;
        }
        if let Some(d) = is_default {
            if d {
                // Clear other defaults first
                self.conn.execute("UPDATE app_identities SET is_default = 0", [])
                    .map_err(|e| KeychatError::Storage(format!("update_app_identity clear defaults: {e}")))?;
            }
            self.conn.execute("UPDATE app_identities SET is_default = ?1 WHERE nostr_pubkey_hex = ?2", rusqlite::params![d as i32, pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("update_app_identity is_default: {e}")))?;
        }
        Ok(())
    }

    /// Delete an identity and its associated rooms, messages, and contacts.
    pub fn delete_app_identity(&self, pubkey_hex: &str) -> Result<()> {
        // Delete messages for all rooms of this identity
        self.conn.execute(
            "DELETE FROM app_messages WHERE room_id IN (SELECT id FROM app_rooms WHERE identity_pubkey = ?1)",
            rusqlite::params![pubkey_hex],
        ).map_err(|e| KeychatError::Storage(format!("delete_app_identity messages: {e}")))?;
        // Delete rooms
        self.conn.execute("DELETE FROM app_rooms WHERE identity_pubkey = ?1", rusqlite::params![pubkey_hex])
            .map_err(|e| KeychatError::Storage(format!("delete_app_identity rooms: {e}")))?;
        // Delete contacts
        self.conn.execute("DELETE FROM app_contacts WHERE identity_pubkey = ?1", rusqlite::params![pubkey_hex])
            .map_err(|e| KeychatError::Storage(format!("delete_app_identity contacts: {e}")))?;
        // Delete identity
        self.conn.execute("DELETE FROM app_identities WHERE nostr_pubkey_hex = ?1", rusqlite::params![pubkey_hex])
            .map_err(|e| KeychatError::Storage(format!("delete_app_identity: {e}")))?;
        Ok(())
    }

    // ─── App Room CRUD ───────────────────────────────────────

    /// Save a new room.
    pub fn save_app_room(
        &self,
        to_main_pubkey: &str,
        identity_pubkey: &str,
        status: i32,
        room_type: i32,
        name: Option<&str>,
        peer_signal_identity_key: Option<&str>,
    ) -> Result<String> {
        let id = format!("{}:{}", to_main_pubkey, identity_pubkey);
        self.conn
            .execute(
                "INSERT INTO app_rooms (id, to_main_pubkey, identity_pubkey, status, type, name, peer_signal_identity_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                   status = CASE WHEN excluded.status > status THEN excluded.status ELSE status END,
                   name = COALESCE(excluded.name, name),
                   peer_signal_identity_key = COALESCE(excluded.peer_signal_identity_key, peer_signal_identity_key)",
                rusqlite::params![id, to_main_pubkey, identity_pubkey, status, room_type, name, peer_signal_identity_key],
            )
            .map_err(|e| KeychatError::Storage(format!("save_app_room: {e}")))?;
        Ok(id)
    }

    /// Get all rooms for an identity, ordered by last_message_at desc.
    pub fn get_app_rooms(&self, identity_pubkey: &str) -> Result<Vec<RoomRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, to_main_pubkey, identity_pubkey, status, type, name, avatar,
                        peer_signal_identity_key, last_message_content, last_message_at,
                        unread_count, created_at
                 FROM app_rooms WHERE identity_pubkey = ?1
                 ORDER BY COALESCE(last_message_at, created_at) DESC, id ASC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_rooms prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![identity_pubkey], |row| {
                Ok(RoomRow {
                    id: row.get(0)?,
                    to_main_pubkey: row.get(1)?,
                    identity_pubkey: row.get(2)?,
                    status: row.get(3)?,
                    room_type: row.get(4)?,
                    name: row.get(5)?,
                    avatar: row.get(6)?,
                    peer_signal_identity_key: row.get(7)?,
                    last_message_content: row.get(8)?,
                    last_message_at: row.get(9)?,
                    unread_count: row.get(10)?,
                    created_at: row.get(11)?,
                })
            })
            .map_err(|e| KeychatError::Storage(format!("get_app_rooms query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_rooms row: {e}")))?);
        }
        Ok(result)
    }

    /// Get a single room by ID.
    pub fn get_app_room(&self, room_id: &str) -> Result<Option<RoomRow>> {
        self.conn
            .query_row(
                "SELECT id, to_main_pubkey, identity_pubkey, status, type, name, avatar,
                        peer_signal_identity_key, last_message_content, last_message_at,
                        unread_count, created_at
                 FROM app_rooms WHERE id = ?1",
                rusqlite::params![room_id],
                |row| {
                    Ok(RoomRow {
                        id: row.get(0)?,
                        to_main_pubkey: row.get(1)?,
                        identity_pubkey: row.get(2)?,
                        status: row.get(3)?,
                        room_type: row.get(4)?,
                        name: row.get(5)?,
                        avatar: row.get(6)?,
                        peer_signal_identity_key: row.get(7)?,
                        last_message_content: row.get(8)?,
                        last_message_at: row.get(9)?,
                        unread_count: row.get(10)?,
                        created_at: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_room: {e}")))
    }

    /// Find a room by to_main_pubkey (for incoming event lookup).
    pub fn find_app_room_by_pubkey(&self, to_main_pubkey: &str) -> Result<Option<RoomRow>> {
        self.conn
            .query_row(
                "SELECT id, to_main_pubkey, identity_pubkey, status, type, name, avatar,
                        peer_signal_identity_key, last_message_content, last_message_at,
                        unread_count, created_at
                 FROM app_rooms WHERE to_main_pubkey = ?1 LIMIT 1",
                rusqlite::params![to_main_pubkey],
                |row| {
                    Ok(RoomRow {
                        id: row.get(0)?,
                        to_main_pubkey: row.get(1)?,
                        identity_pubkey: row.get(2)?,
                        status: row.get(3)?,
                        room_type: row.get(4)?,
                        name: row.get(5)?,
                        avatar: row.get(6)?,
                        peer_signal_identity_key: row.get(7)?,
                        last_message_content: row.get(8)?,
                        last_message_at: row.get(9)?,
                        unread_count: row.get(10)?,
                        created_at: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("find_app_room_by_pubkey: {e}")))
    }

    /// Update room fields.
    pub fn update_app_room(
        &self,
        room_id: &str,
        status: Option<i32>,
        name: Option<&str>,
        last_message_content: Option<&str>,
        last_message_at: Option<i64>,
    ) -> Result<()> {
        let mut sets = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(s) = status {
            sets.push(format!("status = ?{idx}"));
            params.push(Box::new(s));
            idx += 1;
        }
        if let Some(n) = name {
            sets.push(format!("name = ?{idx}"));
            params.push(Box::new(n.to_string()));
            idx += 1;
        }
        if let Some(c) = last_message_content {
            sets.push(format!("last_message_content = ?{idx}"));
            params.push(Box::new(c.to_string()));
            idx += 1;
        }
        if let Some(t) = last_message_at {
            sets.push(format!("last_message_at = ?{idx}"));
            params.push(Box::new(t));
            idx += 1;
        }

        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE app_rooms SET {} WHERE id = ?{idx}", sets.join(", "));
        params.push(Box::new(room_id.to_string()));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        self.conn
            .execute(&sql, param_refs.as_slice())
            .map_err(|e| KeychatError::Storage(format!("update_app_room: {e}")))?;
        Ok(())
    }

    /// Increment unread count for a room.
    pub fn increment_app_room_unread(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_rooms SET unread_count = unread_count + 1 WHERE id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("increment_app_room_unread: {e}")))?;
        Ok(())
    }

    /// Clear unread count for a room.
    pub fn clear_app_room_unread(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_rooms SET unread_count = 0 WHERE id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("clear_app_room_unread: {e}")))?;
        Ok(())
    }

    /// Delete a room and its messages.
    pub fn delete_app_room(&self, room_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM app_messages WHERE room_id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("delete_app_room messages: {e}")))?;
        self.conn.execute("DELETE FROM app_rooms WHERE id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("delete_app_room: {e}")))?;
        Ok(())
    }

    // ─── App Message CRUD ────────────────────────────────────

    /// Save a new message.
    pub fn save_app_message(
        &self,
        msgid: &str,
        event_id: Option<&str>,
        room_id: &str,
        identity_pubkey: &str,
        sender_pubkey: &str,
        content: &str,
        is_me_send: bool,
        status: i32,
        created_at: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO app_messages (msgid, event_id, room_id, identity_pubkey, sender_pubkey, content, is_me_send, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![msgid, event_id, room_id, identity_pubkey, sender_pubkey, content, is_me_send as i32, status, created_at],
            )
            .map_err(|e| KeychatError::Storage(format!("save_app_message: {e}")))?;
        Ok(())
    }

    /// Get messages for a room with pagination (ordered by created_at asc).
    pub fn get_app_messages(&self, room_id: &str, limit: i32, offset: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages WHERE room_id = ?1
                 ORDER BY created_at ASC, rowid ASC LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_messages prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![room_id, limit, offset], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_messages query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_messages row: {e}")))?);
        }
        Ok(result)
    }

    /// Get the latest N messages for a room, returned in chronological order (ASC).
    pub fn get_app_messages_latest(&self, room_id: &str, limit: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages WHERE room_id = ?1
                 ORDER BY created_at DESC, rowid DESC LIMIT ?2",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_latest prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![room_id, limit], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_latest query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_messages_latest row: {e}")))?);
        }
        result.reverse(); // DESC → ASC for display
        Ok(result)
    }

    /// Get all unread messages plus `context` preceding read messages for a room.
    /// Returns messages in chronological (ASC) order.
    pub fn get_app_messages_unread_with_context(&self, room_id: &str, context: i32) -> Result<Vec<MessageRow>> {
        // Find the created_at of the oldest unread message
        let oldest_unread_ts: Option<i64> = self.conn
            .query_row(
                "SELECT MIN(created_at) FROM app_messages WHERE room_id = ?1 AND is_read = 0 AND is_me_send = 0",
                rusqlite::params![room_id],
                |row| row.get(0),
            )
            .map_err(|e| KeychatError::Storage(format!("oldest_unread_ts: {e}")))?;

        let oldest_ts = match oldest_unread_ts {
            Some(ts) => ts,
            None => {
                // No unread messages — fall back to latest page
                return self.get_app_messages_latest(room_id, context);
            }
        };

        // 1. Context messages before oldest unread (DESC, then reverse)
        let mut context_stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages
                 WHERE room_id = ?1 AND created_at < ?2
                 ORDER BY created_at DESC, rowid DESC LIMIT ?3",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_unread context prepare: {e}")))?;
        let ctx_rows = context_stmt
            .query_map(rusqlite::params![room_id, oldest_ts, context], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_unread context query: {e}")))?;
        let mut result = Vec::new();
        for r in ctx_rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("context row: {e}")))?);
        }
        result.reverse(); // DESC → ASC

        // 2. All unread and newer messages (already ASC)
        let mut unread_stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages
                 WHERE room_id = ?1 AND created_at >= ?2
                 ORDER BY created_at ASC, rowid ASC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_unread unread prepare: {e}")))?;
        let unread_rows = unread_stmt
            .query_map(rusqlite::params![room_id, oldest_ts], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_unread unread query: {e}")))?;
        for r in unread_rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("unread row: {e}")))?);
        }
        Ok(result)
    }

    /// Get older messages before or at a given timestamp for pagination.
    /// Uses `<=` to avoid missing messages with the same second-level timestamp.
    /// Caller should deduplicate by msgid.
    pub fn get_app_messages_before(&self, room_id: &str, before_ts: i64, limit: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages
                 WHERE room_id = ?1 AND created_at <= ?2
                 ORDER BY created_at DESC, rowid DESC LIMIT ?3",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_before prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![room_id, before_ts, limit], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_messages_before query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_messages_before row: {e}")))?);
        }
        result.reverse(); // DESC → ASC for display
        Ok(result)
    }

    /// Helper to map a rusqlite Row to MessageRow.
    fn map_message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRow> {
        Ok(MessageRow {
            msgid: row.get(0)?,
            event_id: row.get(1)?,
            room_id: row.get(2)?,
            identity_pubkey: row.get(3)?,
            sender_pubkey: row.get(4)?,
            content: row.get(5)?,
            is_me_send: row.get::<_, i32>(6)? != 0,
            is_read: row.get::<_, i32>(7)? != 0,
            status: row.get(8)?,
            reply_to_event_id: row.get(9)?,
            reply_to_content: row.get(10)?,
            payload_json: row.get(11)?,
            nostr_event_json: row.get(12)?,
            relay_status_json: row.get(13)?,
            local_file_path: row.get(14)?,
            created_at: row.get(15)?,
        })
    }

    /// Get message count for a room.
    pub fn get_app_message_count(&self, room_id: &str) -> Result<i32> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM app_messages WHERE room_id = ?1",
                rusqlite::params![room_id],
                |row| row.get(0),
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_message_count: {e}")))
    }

    /// Check if a message with this event_id already exists.
    pub fn is_app_message_duplicate(&self, event_id: &str) -> Result<bool> {
        let exists: bool = self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_messages WHERE event_id = ?1)",
                rusqlite::params![event_id],
                |row| row.get(0),
            )
            .map_err(|e| KeychatError::Storage(format!("is_app_message_duplicate: {e}")))?;
        Ok(exists)
    }

    /// Get a message by event_id (for reply-to resolution).
    pub fn get_app_message_by_event_id(&self, event_id: &str) -> Result<Option<MessageRow>> {
        self.conn
            .query_row(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages WHERE event_id = ?1 LIMIT 1",
                rusqlite::params![event_id],
                |row| {
                    Ok(MessageRow {
                        msgid: row.get(0)?,
                        event_id: row.get(1)?,
                        room_id: row.get(2)?,
                        identity_pubkey: row.get(3)?,
                        sender_pubkey: row.get(4)?,
                        content: row.get(5)?,
                        is_me_send: row.get::<_, i32>(6)? != 0,
                        is_read: row.get::<_, i32>(7)? != 0,
                        status: row.get(8)?,
                        reply_to_event_id: row.get(9)?,
                        reply_to_content: row.get(10)?,
                        payload_json: row.get(11)?,
                        nostr_event_json: row.get(12)?,
                        relay_status_json: row.get(13)?,
                        local_file_path: row.get(14)?,
                        created_at: row.get(15)?,
                    })
                },
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_message_by_event_id: {e}")))
    }

    /// Get a single message by its msgid (primary key).
    pub fn get_app_message_by_msgid(&self, msgid: &str) -> Result<Option<MessageRow>> {
        self.conn
            .query_row(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages WHERE msgid = ?1 LIMIT 1",
                rusqlite::params![msgid],
                |row| {
                    Ok(MessageRow {
                        msgid: row.get(0)?,
                        event_id: row.get(1)?,
                        room_id: row.get(2)?,
                        identity_pubkey: row.get(3)?,
                        sender_pubkey: row.get(4)?,
                        content: row.get(5)?,
                        is_me_send: row.get::<_, i32>(6)? != 0,
                        is_read: row.get::<_, i32>(7)? != 0,
                        status: row.get(8)?,
                        reply_to_event_id: row.get(9)?,
                        reply_to_content: row.get(10)?,
                        payload_json: row.get(11)?,
                        nostr_event_json: row.get(12)?,
                        relay_status_json: row.get(13)?,
                        local_file_path: row.get(14)?,
                        created_at: row.get(15)?,
                    })
                },
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_message_by_msgid: {e}")))
    }

    /// Update message status and relay info (single atomic UPDATE).
    pub fn update_app_message(
        &self,
        msgid: &str,
        event_id: Option<&str>,
        status: Option<i32>,
        relay_status_json: Option<&str>,
        payload_json: Option<&str>,
        nostr_event_json: Option<&str>,
        reply_to_event_id: Option<&str>,
        reply_to_content: Option<&str>,
    ) -> Result<()> {
        let mut sets = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(v) = event_id {
            sets.push(format!("event_id = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }
        if let Some(v) = status {
            sets.push(format!("status = ?{idx}"));
            params.push(Box::new(v));
            idx += 1;
        }
        if let Some(v) = relay_status_json {
            sets.push(format!("relay_status_json = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }
        if let Some(v) = payload_json {
            sets.push(format!("payload_json = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }
        if let Some(v) = nostr_event_json {
            sets.push(format!("nostr_event_json = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }
        if let Some(v) = reply_to_event_id {
            sets.push(format!("reply_to_event_id = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }
        if let Some(v) = reply_to_content {
            sets.push(format!("reply_to_content = ?{idx}"));
            params.push(Box::new(v.to_string()));
            idx += 1;
        }

        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!(
            "UPDATE app_messages SET {} WHERE msgid = ?{idx}",
            sets.join(", ")
        );
        params.push(Box::new(msgid.to_string()));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        self.conn
            .execute(&sql, param_refs.as_slice())
            .map_err(|e| KeychatError::Storage(format!("update_app_message: {e}")))?;
        Ok(())
    }

    /// Mark all messages in a room as read.
    pub fn mark_app_messages_read(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_messages SET is_read = 1 WHERE room_id = ?1 AND is_read = 0", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("mark_app_messages_read: {e}")))?;
        Ok(())
    }

    /// Get failed outgoing messages for retry.
    pub fn get_app_failed_messages(&self) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, created_at
                 FROM app_messages WHERE is_me_send = 1 AND status = 2
                 ORDER BY created_at ASC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_failed_messages prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(MessageRow {
                    msgid: row.get(0)?,
                    event_id: row.get(1)?,
                    room_id: row.get(2)?,
                    identity_pubkey: row.get(3)?,
                    sender_pubkey: row.get(4)?,
                    content: row.get(5)?,
                    is_me_send: row.get::<_, i32>(6)? != 0,
                    is_read: row.get::<_, i32>(7)? != 0,
                    status: row.get(8)?,
                    reply_to_event_id: row.get(9)?,
                    reply_to_content: row.get(10)?,
                    payload_json: row.get(11)?,
                    nostr_event_json: row.get(12)?,
                    relay_status_json: row.get(13)?,
                    local_file_path: row.get(14)?,
                    created_at: row.get(15)?,
                })
            })
            .map_err(|e| KeychatError::Storage(format!("get_app_failed_messages query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_failed_messages row: {e}")))?);
        }
        Ok(result)
    }

    /// Delete a single message.
    pub fn delete_app_message(&self, msgid: &str) -> Result<()> {
        self.conn.execute("DELETE FROM app_messages WHERE msgid = ?1", rusqlite::params![msgid])
            .map_err(|e| KeychatError::Storage(format!("delete_app_message: {e}")))?;
        Ok(())
    }

    // ─── App Contact CRUD ────────────────────────────────────

    /// Save or update a contact.
    pub fn save_app_contact(
        &self,
        pubkey: &str,
        npubkey: &str,
        identity_pubkey: &str,
        name: Option<&str>,
    ) -> Result<String> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn
            .execute(
                "INSERT INTO app_contacts (id, pubkey, npubkey, identity_pubkey, name, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                   npubkey = excluded.npubkey,
                   name = COALESCE(excluded.name, name),
                   updated_at = excluded.updated_at",
                rusqlite::params![id, pubkey, npubkey, identity_pubkey, name, now],
            )
            .map_err(|e| KeychatError::Storage(format!("save_app_contact: {e}")))?;
        Ok(id)
    }

    /// Get all contacts for an identity.
    pub fn get_app_contacts(&self, identity_pubkey: &str) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, pubkey, npubkey, identity_pubkey, signal_identity_key, petname, name, about, avatar, created_at, updated_at
                 FROM app_contacts WHERE identity_pubkey = ?1 ORDER BY updated_at DESC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_contacts prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![identity_pubkey], |row| {
                Ok(ContactRow {
                    id: row.get(0)?,
                    pubkey: row.get(1)?,
                    npubkey: row.get(2)?,
                    identity_pubkey: row.get(3)?,
                    signal_identity_key: row.get(4)?,
                    petname: row.get(5)?,
                    name: row.get(6)?,
                    about: row.get(7)?,
                    avatar: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            })
            .map_err(|e| KeychatError::Storage(format!("get_app_contacts query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_contacts row: {e}")))?);
        }
        Ok(result)
    }

    /// Get a contact by pubkey and identity.
    pub fn get_app_contact(&self, pubkey: &str, identity_pubkey: &str) -> Result<Option<ContactRow>> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.conn
            .query_row(
                "SELECT id, pubkey, npubkey, identity_pubkey, signal_identity_key, petname, name, about, avatar, created_at, updated_at
                 FROM app_contacts WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    Ok(ContactRow {
                        id: row.get(0)?,
                        pubkey: row.get(1)?,
                        npubkey: row.get(2)?,
                        identity_pubkey: row.get(3)?,
                        signal_identity_key: row.get(4)?,
                        petname: row.get(5)?,
                        name: row.get(6)?,
                        about: row.get(7)?,
                        avatar: row.get(8)?,
                        created_at: row.get(9)?,
                        updated_at: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_contact: {e}")))
    }

    /// Update contact fields.
    pub fn update_app_contact(
        &self,
        pubkey: &str,
        identity_pubkey: &str,
        petname: Option<&str>,
        name: Option<&str>,
        avatar: Option<&str>,
    ) -> Result<()> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        if let Some(p) = petname {
            self.conn.execute("UPDATE app_contacts SET petname = ?1, updated_at = strftime('%s','now') WHERE id = ?2", rusqlite::params![p, id])
                .map_err(|e| KeychatError::Storage(format!("update_app_contact petname: {e}")))?;
        }
        if let Some(n) = name {
            self.conn.execute("UPDATE app_contacts SET name = ?1, updated_at = strftime('%s','now') WHERE id = ?2", rusqlite::params![n, id])
                .map_err(|e| KeychatError::Storage(format!("update_app_contact name: {e}")))?;
        }
        if let Some(a) = avatar {
            self.conn.execute("UPDATE app_contacts SET avatar = ?1, updated_at = strftime('%s','now') WHERE id = ?2", rusqlite::params![a, id])
                .map_err(|e| KeychatError::Storage(format!("update_app_contact avatar: {e}")))?;
        }
        Ok(())
    }

    /// Delete a contact.
    pub fn delete_app_contact(&self, pubkey: &str, identity_pubkey: &str) -> Result<()> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.conn.execute("DELETE FROM app_contacts WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| KeychatError::Storage(format!("delete_app_contact: {e}")))?;
        Ok(())
    }

    /// Force a WAL checkpoint so all data is written to the main database file.
    pub fn checkpoint(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| KeychatError::Storage(format!("WAL checkpoint failed: {e}")))?;
        Ok(())
    }

    // ─── Bulk Deletion ───────────────────────────────────

    /// Delete all data for the current identity (all tables except relays).
    pub fn delete_all_data(&self) -> Result<()> {
        self.transaction(|conn| {
            conn.execute_batch(
                "DELETE FROM signal_sessions;
                 DELETE FROM pre_keys;
                 DELETE FROM signed_pre_keys;
                 DELETE FROM kyber_pre_keys;
                 DELETE FROM identity_keys;
                 DELETE FROM peer_addresses;
                 DELETE FROM processed_events;
                 DELETE FROM peer_mappings;
                 DELETE FROM signal_participants;
                 DELETE FROM pending_friend_requests;
                 DELETE FROM inbound_friend_requests;
                 DELETE FROM signal_groups;
                 DELETE FROM mls_group_ids;
                 DELETE FROM app_identities;
                 DELETE FROM app_rooms;
                 DELETE FROM app_messages;
                 DELETE FROM app_contacts;",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete all data: {e}")))?;
            Ok(())
        })
    }

    /// Delete all data for a single peer (1:1 room).
    pub fn delete_peer_data(&self, signal_id: &str, nostr_pubkey: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM signal_sessions WHERE address = ?1",
                rusqlite::params![signal_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete sessions: {e}")))?;
        self.conn
            .execute(
                "DELETE FROM signal_participants WHERE peer_signal_id = ?1",
                rusqlite::params![signal_id],
            )
            .map_err(|e| {
                KeychatError::Storage(format!("Failed to delete signal participant: {e}"))
            })?;
        self.conn
            .execute(
                "DELETE FROM peer_mappings WHERE nostr_pubkey = ?1",
                rusqlite::params![nostr_pubkey],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete peer mapping: {e}")))?;
        self.conn
            .execute(
                "DELETE FROM peer_addresses WHERE peer_signal_id = ?1",
                rusqlite::params![signal_id],
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete peer addresses: {e}")))?;
        Ok(())
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
        store.save_session("alice", 1, b"session-record-1").unwrap();
        store.save_session("alice", 2, b"session-record-2").unwrap();
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
        store.save_identity_key("self", pub_key, priv_key).unwrap();
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

        store
            .save_peer_addresses("signal-id-alice", &state)
            .unwrap();

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
        store
            .conn
            .execute(
                "INSERT INTO processed_events (event_id, processed_at) VALUES ('old-evt', 1000)",
                [],
            )
            .unwrap();
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
        assert!(store
            .load_peer_by_signal("signal-unknown")
            .unwrap()
            .is_none());
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
            store.mark_event_processed(&format!("event-{i}")).unwrap();
        }

        // Verify random lookups
        assert!(store.is_event_processed("event-5000").unwrap());
        assert!(!store.is_event_processed("event-99999").unwrap());

        let s = store.load_session("addr-500", 1).unwrap().unwrap();
        assert_eq!(s.len(), 256);
    }

    #[test]
    fn test_promote_pending_fr() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Save a pending FR
        store
            .save_pending_fr(
                "fr-test-123",
                42, // device_id
                b"id_pub",
                b"id_priv",
                1001, // reg_id
                10,   // spk_id
                b"spk_rec",
                20, // pk_id
                b"pk_rec",
                30, // kpk_id
                b"kpk_rec",
                "first_inbox_secret",
                "peer_nostr_pubkey",
            )
            .unwrap();

        // Verify it's in pending
        let frs = store.list_pending_frs().unwrap();
        assert_eq!(frs.len(), 1);
        assert!(store.list_signal_participants().unwrap().is_empty());

        // Promote it
        store
            .promote_pending_fr("fr-test-123", "peer_signal_id_hex")
            .unwrap();

        // Verify it moved
        assert!(store.list_pending_frs().unwrap().is_empty());
        let participants = store.list_signal_participants().unwrap();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0], "peer_signal_id_hex");

        // Verify data is correct
        let (device_id, id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            store
                .load_signal_participant("peer_signal_id_hex")
                .unwrap()
                .unwrap();
        assert_eq!(device_id, 42);
        assert_eq!(id_pub, b"id_pub");
        assert_eq!(id_priv, b"id_priv");
        assert_eq!(reg_id, 1001);
    }

    #[test]
    fn test_update_existing_session() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        store.save_session("alice", 1, b"version-1").unwrap();
        store.save_session("alice", 1, b"version-2").unwrap();

        let loaded = store.load_session("alice", 1).unwrap();
        assert_eq!(loaded, Some(b"version-2".to_vec()));
    }

    #[test]
    fn test_group_persistence_roundtrip() {
        use crate::group::{GroupManager, GroupMember, SignalGroup};
        use std::collections::{HashMap, HashSet};

        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Build a group
        let mut members = HashMap::new();
        members.insert(
            "signal-alice".to_string(),
            GroupMember {
                signal_id: "signal-alice".into(),
                nostr_pubkey: "npub-alice".into(),
                name: "Alice".into(),
                is_admin: true,
            },
        );
        members.insert(
            "signal-bob".to_string(),
            GroupMember {
                signal_id: "signal-bob".into(),
                nostr_pubkey: "npub-bob".into(),
                name: "Bob".into(),
                is_admin: false,
            },
        );
        let mut admins = HashSet::new();
        admins.insert("signal-alice".to_string());

        let group = SignalGroup {
            group_id: "group-123".into(),
            name: "Test Group".into(),
            members,
            my_signal_id: "signal-alice".into(),
            admins,
        };

        // Save via GroupManager
        let mut mgr = GroupManager::new();
        mgr.add_group(group);
        mgr.save_group("group-123", &store).unwrap();

        // Load into a new GroupManager
        let mut mgr2 = GroupManager::new();
        mgr2.load_all(&store).unwrap();

        assert_eq!(mgr2.group_count(), 1);
        let loaded = mgr2.get_group("group-123").unwrap();
        assert_eq!(loaded.name, "Test Group");
        assert_eq!(loaded.members.len(), 2);
        assert!(loaded.is_admin("signal-alice"));
        assert!(!loaded.is_admin("signal-bob"));
        assert_eq!(loaded.my_signal_id, "signal-alice");

        // Delete
        mgr2.remove_group_persistent("group-123", &store).unwrap();
        assert_eq!(mgr2.group_count(), 0);
        let all = store.load_all_groups().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn test_signal_participant_save_restore_roundtrip() {
        use crate::signal_session::{generate_prekey_material, SignalParticipant};

        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // 1. Generate keys and create a participant
        let keys = generate_prekey_material().unwrap();
        let original_identity = hex::encode(keys.identity_key_pair.identity_key().serialize());
        let original_reg_id = keys.registration_id;

        let participant =
            SignalParticipant::from_prekey_material("test-peer".to_string(), 1, keys).unwrap();

        // 2. Serialize and save to DB
        let serialized = crate::signal_session::serialize_prekey_material(participant.keys());
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            serialized.unwrap();

        store
            .save_signal_participant(
                "test-peer",
                1,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
                pk_id,
                &pk_rec,
                kpk_id,
                &kpk_rec,
            )
            .unwrap();

        // 3. Load from DB and reconstruct
        let (d_id, l_pub, l_priv, l_reg, l_spk_id, l_spk, l_pk_id, l_pk, l_kpk_id, l_kpk) =
            store.load_signal_participant("test-peer").unwrap().unwrap();

        assert_eq!(d_id, 1);
        assert_eq!(l_reg, original_reg_id);

        let restored_keys = crate::signal_session::reconstruct_prekey_material(
            &l_pub, &l_priv, l_reg, l_spk_id, &l_spk, l_pk_id, &l_pk, l_kpk_id, &l_kpk,
        )
        .unwrap();

        let restored =
            SignalParticipant::from_prekey_material("test-peer".to_string(), d_id, restored_keys)
                .unwrap();

        // 4. Verify identity is the same
        assert_eq!(
            restored.identity_public_key_hex(),
            original_identity,
            "restored participant must have the same identity key"
        );
        assert_eq!(
            restored.registration_id(),
            original_reg_id,
            "restored participant must have the same registration ID"
        );

        // 5. Verify the restored participant can produce a valid prekey bundle
        let bundle = restored.prekey_bundle();
        assert!(
            bundle.is_ok(),
            "restored participant must produce a valid prekey bundle"
        );
    }

    #[test]
    fn test_relay_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Empty initially
        let relays = store.list_relays().unwrap();
        assert!(relays.is_empty());

        // Save
        store.save_relay("wss://relay.example.com").unwrap();
        store.save_relay("wss://relay2.example.com").unwrap();

        let relays = store.list_relays().unwrap();
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&"wss://relay.example.com".to_string()));
        assert!(relays.contains(&"wss://relay2.example.com".to_string()));

        // Duplicate insert is ignored (INSERT OR IGNORE)
        store.save_relay("wss://relay.example.com").unwrap();
        assert_eq!(store.list_relays().unwrap().len(), 2);

        // Delete
        store.delete_relay("wss://relay.example.com").unwrap();
        let relays = store.list_relays().unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0], "wss://relay2.example.com");

        // Delete non-existent — no error
        store.delete_relay("wss://nonexistent.com").unwrap();
        assert_eq!(store.list_relays().unwrap().len(), 1);

        // Delete last
        store.delete_relay("wss://relay2.example.com").unwrap();
        assert!(store.list_relays().unwrap().is_empty());
    }

    #[test]
    fn test_delete_all_data() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Populate various tables
        store.save_session("addr1", 1, b"record").unwrap();
        store.save_pre_key(1, b"pk").unwrap();
        store.save_signed_pre_key(1, b"spk").unwrap();
        store.save_kyber_pre_key(1, b"kpk").unwrap();
        store.save_identity_key("self", b"pub", b"priv").unwrap();
        store.save_peer_identity("peer1", b"pub").unwrap();
        store
            .save_peer_mapping("npub1", "signal1", "Alice")
            .unwrap();
        store.mark_event_processed("evt1").unwrap();
        store.save_relay("wss://relay.test.com").unwrap();

        // Verify data exists
        assert!(store.load_session("addr1", 1).unwrap().is_some());
        assert_eq!(store.list_peers().unwrap().len(), 1);
        assert!(store.is_event_processed("evt1").unwrap());
        assert_eq!(store.list_relays().unwrap().len(), 1);

        // Delete all
        store.delete_all_data().unwrap();

        // Everything gone except relays
        assert!(store.load_session("addr1", 1).unwrap().is_none());
        assert!(store.list_peers().unwrap().is_empty());
        assert!(!store.is_event_processed("evt1").unwrap());
        assert_eq!(
            store.list_relays().unwrap().len(),
            1,
            "relays should be preserved"
        );
    }

    #[test]
    fn test_delete_peer_data() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Create two peers
        store
            .save_peer_mapping("npub-alice", "signal-alice", "Alice")
            .unwrap();
        store
            .save_peer_mapping("npub-bob", "signal-bob", "Bob")
            .unwrap();
        store
            .save_session("signal-alice", 1, b"session-alice")
            .unwrap();
        store.save_session("signal-bob", 1, b"session-bob").unwrap();

        assert_eq!(store.list_peers().unwrap().len(), 2);

        // Delete Alice only
        store
            .delete_peer_data("signal-alice", "npub-alice")
            .unwrap();

        // Alice gone, Bob remains
        assert_eq!(store.list_peers().unwrap().len(), 1);
        assert!(store.load_session("signal-alice", 1).unwrap().is_none());
        assert!(store.load_session("signal-bob", 1).unwrap().is_some());
        assert_eq!(store.list_peers().unwrap()[0].name, "Bob");
    }

    #[test]
    fn test_mls_group_ids_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Empty
        assert!(store.list_mls_group_ids().unwrap().is_empty());

        // Save
        store.save_mls_group_id("mls-group-1").unwrap();
        store.save_mls_group_id("mls-group-2").unwrap();
        assert_eq!(store.list_mls_group_ids().unwrap().len(), 2);

        // Duplicate ignored
        store.save_mls_group_id("mls-group-1").unwrap();
        assert_eq!(store.list_mls_group_ids().unwrap().len(), 2);

        // Delete one
        store.delete_mls_group_id("mls-group-1").unwrap();
        let ids = store.list_mls_group_ids().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "mls-group-2");

        // Delete non-existent
        store.delete_mls_group_id("no-such-group").unwrap();
        assert_eq!(store.list_mls_group_ids().unwrap().len(), 1);
    }

    #[test]
    fn test_inbound_fr_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Empty
        assert!(store.list_inbound_frs().unwrap().is_empty());

        // Save
        store
            .save_inbound_fr(
                "fr-1",
                "sender-pub-1",
                r#"{"msg":"hi"}"#,
                r#"{"payload":1}"#,
            )
            .unwrap();
        store
            .save_inbound_fr(
                "fr-2",
                "sender-pub-2",
                r#"{"msg":"yo"}"#,
                r#"{"payload":2}"#,
            )
            .unwrap();
        assert_eq!(store.list_inbound_frs().unwrap().len(), 2);

        // Load
        let (sender, msg_json, payload_json) = store.load_inbound_fr("fr-1").unwrap().unwrap();
        assert_eq!(sender, "sender-pub-1");
        assert!(msg_json.contains("hi"));
        assert!(payload_json.contains("1"));

        // Non-existent
        assert!(store.load_inbound_fr("fr-999").unwrap().is_none());

        // Delete
        store.delete_inbound_fr("fr-1").unwrap();
        assert_eq!(store.list_inbound_frs().unwrap().len(), 1);
        assert!(store.load_inbound_fr("fr-1").unwrap().is_none());

        // Delete non-existent
        store.delete_inbound_fr("fr-999").unwrap();
        assert_eq!(store.list_inbound_frs().unwrap().len(), 1);
    }

    // ─── App Data Table Tests ────────────────────────────────

    #[test]
    fn test_app_identity_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Empty
        assert!(store.get_app_identities().unwrap().is_empty());

        // Save (pubkey_hex, npub, name, idx, is_default)
        store.save_app_identity("hex1", "npub1abc", "Alice", 0, true).unwrap();
        store.save_app_identity("hex2", "npub1def", "Bob", 1, false).unwrap();

        let ids = store.get_app_identities().unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].name, "Alice");
        assert!(ids[0].is_default);
        assert_eq!(ids[1].name, "Bob");
        assert!(!ids[1].is_default);

        // Update (by pubkey_hex)
        store.update_app_identity("hex1", Some("Alice2"), None, None).unwrap();
        let ids = store.get_app_identities().unwrap();
        assert_eq!(ids[0].name, "Alice2");

        // Set default
        store.update_app_identity("hex2", None, None, Some(true)).unwrap();
        let ids = store.get_app_identities().unwrap();
        assert!(!ids[0].is_default); // Alice cleared
        assert!(ids[1].is_default);  // Bob now default

        // Delete cascading (by pubkey_hex)
        store.save_app_room("peer1", "hex1", 2, 0, Some("Room1"), None).unwrap();
        store.save_app_contact("peer1", "npub1peer", "hex1", Some("Peer")).unwrap();
        store.delete_app_identity("hex1").unwrap();
        let ids = store.get_app_identities().unwrap();
        assert_eq!(ids.len(), 1);
        assert!(store.get_app_rooms("hex1").unwrap().is_empty());
        assert!(store.get_app_contacts("hex1").unwrap().is_empty());
    }

    #[test]
    fn test_app_room_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Save rooms (identity_pubkey is now hex)
        let id1 = store.save_app_room("peer1", "hex1", 2, 0, Some("Alice"), None).unwrap();
        let id2 = store.save_app_room("group1", "hex1", 2, 1, Some("Group"), None).unwrap();
        assert_eq!(id1, "peer1:hex1");
        assert_eq!(id2, "group1:hex1");

        // Get rooms
        let rooms = store.get_app_rooms("hex1").unwrap();
        assert_eq!(rooms.len(), 2);

        // Get single room
        let room = store.get_app_room(&id1).unwrap().unwrap();
        assert_eq!(room.name, Some("Alice".to_string()));
        assert_eq!(room.status, 2);
        assert_eq!(room.room_type, 0);

        // Find by pubkey
        let found = store.find_app_room_by_pubkey("peer1").unwrap().unwrap();
        assert_eq!(found.id, id1);

        // Update
        store.update_app_room(&id1, Some(3), None, Some("Hello"), Some(1000)).unwrap();
        let room = store.get_app_room(&id1).unwrap().unwrap();
        assert_eq!(room.status, 3);
        assert_eq!(room.last_message_content, Some("Hello".to_string()));
        assert_eq!(room.last_message_at, Some(1000));

        // Unread
        store.increment_app_room_unread(&id1).unwrap();
        store.increment_app_room_unread(&id1).unwrap();
        let room = store.get_app_room(&id1).unwrap().unwrap();
        assert_eq!(room.unread_count, 2);
        store.clear_app_room_unread(&id1).unwrap();
        let room = store.get_app_room(&id1).unwrap().unwrap();
        assert_eq!(room.unread_count, 0);

        // Delete (cascade messages)
        store.save_app_message("msg1", None, &id1, "hex1", "peer1", "hi", false, 1, 1000).unwrap();
        store.delete_app_room(&id1).unwrap();
        assert!(store.get_app_room(&id1).unwrap().is_none());
        assert!(store.get_app_messages(&id1, 100, 0).unwrap().is_empty());
    }

    #[test]
    fn test_app_message_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();
        let room_id = store.save_app_room("peer1", "hex1", 2, 0, Some("Alice"), None).unwrap();

        // Save messages
        store.save_app_message("msg1", Some("ev1"), &room_id, "hex1", "peer1", "hello", false, 1, 1000).unwrap();
        store.save_app_message("msg2", Some("ev2"), &room_id, "hex1", "me", "world", true, 0, 1001).unwrap();
        store.save_app_message("msg3", None, &room_id, "hex1", "peer1", "bye", false, 1, 1002).unwrap();

        // Get messages
        let msgs = store.get_app_messages(&room_id, 100, 0).unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].content, "hello");
        assert!(!msgs[0].is_me_send);
        assert!(msgs[1].is_me_send);

        // Pagination
        let page = store.get_app_messages(&room_id, 2, 0).unwrap();
        assert_eq!(page.len(), 2);
        let page2 = store.get_app_messages(&room_id, 2, 2).unwrap();
        assert_eq!(page2.len(), 1);

        // Count
        assert_eq!(store.get_app_message_count(&room_id).unwrap(), 3);

        // Duplicate check
        assert!(store.is_app_message_duplicate("ev1").unwrap());
        assert!(!store.is_app_message_duplicate("ev999").unwrap());

        // Duplicate insert (INSERT OR IGNORE)
        store.save_app_message("msg1", Some("ev1"), &room_id, "hex1", "peer1", "changed", false, 1, 1000).unwrap();
        let msgs = store.get_app_messages(&room_id, 100, 0).unwrap();
        assert_eq!(msgs[0].content, "hello"); // unchanged

        // Get by event_id
        let msg = store.get_app_message_by_event_id("ev1").unwrap().unwrap();
        assert_eq!(msg.msgid, "msg1");
        assert!(store.get_app_message_by_event_id("ev999").unwrap().is_none());

        // Update
        store.update_app_message("msg2", None, Some(1), Some("[{\"url\":\"wss://r1\",\"status\":\"success\"}]"), None, None, None, None).unwrap();
        let msg = store.get_app_messages(&room_id, 100, 0).unwrap()[1].clone();
        assert_eq!(msg.status, 1);
        assert!(msg.relay_status_json.unwrap().contains("success"));

        // Mark read
        store.mark_app_messages_read(&room_id).unwrap();
        let msgs = store.get_app_messages(&room_id, 100, 0).unwrap();
        assert!(msgs.iter().all(|m| m.is_read));

        // Failed messages query
        store.save_app_message("msg4", Some("ev4"), &room_id, "hex1", "me", "failed msg", true, 2, 1003).unwrap();
        let failed = store.get_app_failed_messages().unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].msgid, "msg4");

        // Delete single message
        store.delete_app_message("msg1").unwrap();
        assert_eq!(store.get_app_message_count(&room_id).unwrap(), 3);
    }

    #[test]
    fn test_app_contact_crud() {
        let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

        // Save (identity_pubkey is now hex)
        let id = store.save_app_contact("pub1", "npub1pub1", "hexidentity1", Some("Alice")).unwrap();
        assert_eq!(id, "pub1:hexidentity1");

        store.save_app_contact("pub2", "npub1pub2", "hexidentity1", None).unwrap();

        // Get all
        let contacts = store.get_app_contacts("hexidentity1").unwrap();
        assert_eq!(contacts.len(), 2);

        // Get single
        let c = store.get_app_contact("pub1", "hexidentity1").unwrap().unwrap();
        assert_eq!(c.name, Some("Alice".to_string()));
        assert!(c.petname.is_none());

        // Not found
        assert!(store.get_app_contact("pub999", "hexidentity1").unwrap().is_none());

        // Update
        store.update_app_contact("pub1", "hexidentity1", Some("Ali"), None, None).unwrap();
        let c = store.get_app_contact("pub1", "hexidentity1").unwrap().unwrap();
        assert_eq!(c.petname, Some("Ali".to_string()));

        // Delete
        store.delete_app_contact("pub1", "hexidentity1").unwrap();
        assert!(store.get_app_contact("pub1", "hexidentity1").unwrap().is_none());
        assert_eq!(store.get_app_contacts("hexidentity1").unwrap().len(), 1);
    }
}
