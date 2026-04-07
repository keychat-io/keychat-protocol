//! Application-layer SQLCipher storage.
//!
//! Manages app_identities, app_rooms, app_messages, app_contacts — data that
//! belongs to the application UI, not the protocol engine.  Lives in its own
//! encrypted SQLite file so libkeychat stays protocol-only.

use libkeychat::error::{KeychatError, Result};
use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;

// ─── Row Types ───────────────────────────────────────────

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
    pub parent_room_id: Option<String>,
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
    pub local_meta: Option<String>,
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

// ─── AppStorage ──────────────────────────────────────────

/// Application-layer encrypted database (separate from protocol storage).
pub struct AppStorage {
    conn: Connection,
}

impl AppStorage {
    /// Open (or create) an encrypted app database at `path`.
    pub fn open(path: &str, key: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| KeychatError::Storage(format!("Failed to open app database: {e}")))?;
        Self::init(conn, key)
    }

    /// Open an in-memory encrypted database (for tests).
    pub fn open_in_memory(key: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| KeychatError::Storage(format!("Failed to open in-memory app db: {e}")))?;
        Self::init(conn, key)
    }

    fn init(conn: Connection, key: &str) -> Result<Self> {
        conn.pragma_update(None, "key", key)
            .map_err(|e| KeychatError::Storage(format!("Failed to set app db encryption key: {e}")))?;
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096; \
             PRAGMA journal_mode = WAL;",
        )
        .map_err(|e| KeychatError::Storage(format!("Failed to set app db pragmas: {e}")))?;

        Self::run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Execute multiple operations in a single transaction.
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

    /// Force a WAL checkpoint.
    pub fn checkpoint(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| KeychatError::Storage(format!("WAL checkpoint failed: {e}")))?;
        Ok(())
    }

    // ─── Migrations ──────────────────────────────────────

    const SCHEMA_VERSION: u32 = 3;

    fn run_migrations(conn: &Connection) -> Result<()> {
        let current: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| KeychatError::Storage(format!("Failed to read user_version: {e}")))?;

        tracing::info!(
            "app database schema version: {current}, target: {}",
            Self::SCHEMA_VERSION
        );

        if current < 1 {
            Self::migrate_v0_to_v1(conn)?;
        }
        if current < 2 {
            Self::migrate_v1_to_v2(conn)?;
        }
        if current < 3 {
            Self::migrate_v2_to_v3(conn)?;
        }
        Ok(())
    }

    fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
        tracing::info!("running app migration v0 → v1: create base schema");
        conn.execute_batch(
            "BEGIN;

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
                parent_room_id TEXT REFERENCES app_rooms(id),
                last_message_content TEXT,
                last_message_at INTEGER,
                unread_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(to_main_pubkey, identity_pubkey)
            );
            CREATE INDEX IF NOT EXISTS idx_app_rooms_identity ON app_rooms(identity_pubkey, last_message_at);
            CREATE INDEX IF NOT EXISTS idx_app_rooms_pubkey ON app_rooms(to_main_pubkey);
            CREATE INDEX IF NOT EXISTS idx_app_rooms_parent ON app_rooms(parent_room_id);

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

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_attachments (
                msgid TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                room_id TEXT NOT NULL,
                local_path TEXT,
                transfer_state INTEGER NOT NULL DEFAULT 0,
                audio_played INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (msgid, file_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_file_attachments_room ON file_attachments(room_id);

            PRAGMA user_version = 1;

            COMMIT;",
        )
        .map_err(|e| KeychatError::Storage(format!("app migration v0→v1 failed: {e}")))?;

        tracing::info!("app migration v0 → v1 complete");
        Ok(())
    }

    fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
        tracing::info!("running app migration v1 → v2: add local_meta column");
        conn.execute_batch(
            "BEGIN;
            ALTER TABLE app_messages ADD COLUMN local_meta TEXT;
            PRAGMA user_version = 2;
            COMMIT;",
        )
        .map_err(|e| KeychatError::Storage(format!("app migration v1→v2 failed: {e}")))?;

        tracing::info!("app migration v1 → v2 complete");
        Ok(())
    }

    fn migrate_v2_to_v3(conn: &Connection) -> Result<()> {
        tracing::info!("running app migration v2 → v3: add file_attachments table");
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE IF NOT EXISTS file_attachments (
                msgid TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                room_id TEXT NOT NULL,
                local_path TEXT,
                transfer_state INTEGER NOT NULL DEFAULT 0,
                audio_played INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (msgid, file_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_file_attachments_room ON file_attachments(room_id);
            PRAGMA user_version = 3;
            COMMIT;",
        )
        .map_err(|e| KeychatError::Storage(format!("app migration v2→v3 failed: {e}")))?;

        tracing::info!("app migration v2 → v3 complete");
        Ok(())
    }

    // ─── App Settings CRUD ──────────────────────────────

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT value FROM app_settings WHERE key = ?1",
        ).map_err(|e| KeychatError::Storage(format!("get_setting prepare: {e}")))?;

        let result = stmt.query_row(params![key], |row| row.get(0)).optional()
            .map_err(|e| KeychatError::Storage(format!("get_setting: {e}")))?;
        Ok(result)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        ).map_err(|e| KeychatError::Storage(format!("set_setting: {e}")))?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM app_settings WHERE key = ?1",
            params![key],
        ).map_err(|e| KeychatError::Storage(format!("delete_setting: {e}")))?;
        Ok(())
    }

    // ─── App Identity CRUD ───────────────────────────────

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

    pub fn update_app_identity(
        &self,
        pubkey_hex: &str,
        name: Option<&str>,
        avatar: Option<&str>,
        is_default: Option<bool>,
    ) -> Result<()> {
        self.transaction(|_| {
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
                    self.conn.execute("UPDATE app_identities SET is_default = 0", [])
                        .map_err(|e| KeychatError::Storage(format!("update_app_identity clear defaults: {e}")))?;
                }
                self.conn.execute("UPDATE app_identities SET is_default = ?1 WHERE nostr_pubkey_hex = ?2", rusqlite::params![d as i32, pubkey_hex])
                    .map_err(|e| KeychatError::Storage(format!("update_app_identity is_default: {e}")))?;
            }
            Ok(())
        })
    }

    pub fn delete_app_identity(&self, pubkey_hex: &str) -> Result<()> {
        self.transaction(|conn| {
            conn.execute(
                "DELETE FROM app_messages WHERE room_id IN (SELECT id FROM app_rooms WHERE identity_pubkey = ?1)",
                rusqlite::params![pubkey_hex],
            ).map_err(|e| KeychatError::Storage(format!("delete_app_identity messages: {e}")))?;
            conn.execute("DELETE FROM app_rooms WHERE identity_pubkey = ?1", rusqlite::params![pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("delete_app_identity rooms: {e}")))?;
            conn.execute("DELETE FROM app_contacts WHERE identity_pubkey = ?1", rusqlite::params![pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("delete_app_identity contacts: {e}")))?;
            conn.execute("DELETE FROM app_identities WHERE nostr_pubkey_hex = ?1", rusqlite::params![pubkey_hex])
                .map_err(|e| KeychatError::Storage(format!("delete_app_identity: {e}")))?;
            Ok(())
        })
    }

    // ─── App Room CRUD ───────────────────────────────────

    pub fn save_app_room(
        &self,
        to_main_pubkey: &str,
        identity_pubkey: &str,
        status: i32,
        room_type: i32,
        name: Option<&str>,
        peer_signal_identity_key: Option<&str>,
        parent_room_id: Option<&str>,
    ) -> Result<String> {
        let id = format!("{}:{}", to_main_pubkey, identity_pubkey);
        self.conn
            .execute(
                "INSERT INTO app_rooms (id, to_main_pubkey, identity_pubkey, status, type, name, peer_signal_identity_key, parent_room_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                   status = CASE
                     WHEN status = 1 THEN status
                     WHEN excluded.status > status THEN excluded.status
                     ELSE status
                   END,
                   name = COALESCE(excluded.name, name),
                   peer_signal_identity_key = COALESCE(excluded.peer_signal_identity_key, peer_signal_identity_key),
                   parent_room_id = COALESCE(excluded.parent_room_id, parent_room_id)",
                rusqlite::params![id, to_main_pubkey, identity_pubkey, status, room_type, name, peer_signal_identity_key, parent_room_id],
            )
            .map_err(|e| KeychatError::Storage(format!("save_app_room: {e}")))?;
        Ok(id)
    }

    pub fn get_app_rooms(&self, identity_pubkey: &str) -> Result<Vec<RoomRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, to_main_pubkey, identity_pubkey, status, type, name, avatar,
                        peer_signal_identity_key, parent_room_id, last_message_content,
                        last_message_at, unread_count, created_at
                 FROM app_rooms WHERE identity_pubkey = ?1
                 ORDER BY COALESCE(last_message_at, created_at) DESC, id ASC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_rooms prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![identity_pubkey], Self::map_room_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_rooms query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_rooms row: {e}")))?);
        }
        Ok(result)
    }

    fn map_room_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RoomRow> {
        Ok(RoomRow {
            id: row.get(0)?,
            to_main_pubkey: row.get(1)?,
            identity_pubkey: row.get(2)?,
            status: row.get(3)?,
            room_type: row.get(4)?,
            name: row.get(5)?,
            avatar: row.get(6)?,
            peer_signal_identity_key: row.get(7)?,
            parent_room_id: row.get(8)?,
            last_message_content: row.get(9)?,
            last_message_at: row.get(10)?,
            unread_count: row.get(11)?,
            created_at: row.get(12)?,
        })
    }

    pub fn get_app_room(&self, room_id: &str) -> Result<Option<RoomRow>> {
        self.conn
            .query_row(
                "SELECT id, to_main_pubkey, identity_pubkey, status, type, name, avatar,
                        peer_signal_identity_key, parent_room_id, last_message_content,
                        last_message_at, unread_count, created_at
                 FROM app_rooms WHERE id = ?1",
                rusqlite::params![room_id],
                Self::map_room_row,
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_room: {e}")))
    }


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
        let rows = self.conn
            .execute(&sql, param_refs.as_slice())
            .map_err(|e| KeychatError::Storage(format!("update_app_room: {e}")))?;
        if rows == 0 {
            tracing::warn!("update_app_room: no rows affected for room_id={}", room_id);
        }
        Ok(())
    }

    pub fn increment_app_room_unread(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_rooms SET unread_count = unread_count + 1 WHERE id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("increment_app_room_unread: {e}")))?;
        Ok(())
    }

    pub fn clear_app_room_unread(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_rooms SET unread_count = 0 WHERE id = ?1", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("clear_app_room_unread: {e}")))?;
        Ok(())
    }

    pub fn delete_app_room(&self, room_id: &str) -> Result<()> {
        self.transaction(|conn| {
            conn.execute(
                "DELETE FROM app_messages WHERE room_id IN (SELECT id FROM app_rooms WHERE parent_room_id = ?1)",
                rusqlite::params![room_id],
            ).map_err(|e| KeychatError::Storage(format!("delete_app_room child messages: {e}")))?;
            conn.execute("DELETE FROM app_rooms WHERE parent_room_id = ?1", rusqlite::params![room_id])
                .map_err(|e| KeychatError::Storage(format!("delete_app_room children: {e}")))?;
            conn.execute("DELETE FROM app_messages WHERE room_id = ?1", rusqlite::params![room_id])
                .map_err(|e| KeychatError::Storage(format!("delete_app_room messages: {e}")))?;
            conn.execute("DELETE FROM app_rooms WHERE id = ?1", rusqlite::params![room_id])
                .map_err(|e| KeychatError::Storage(format!("delete_app_room: {e}")))?;
            Ok(())
        })
    }

    // ─── App Message CRUD ────────────────────────────────

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

    pub fn get_app_messages(&self, room_id: &str, limit: i32, offset: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
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

    pub fn get_app_messages_latest(&self, room_id: &str, limit: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
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
        result.reverse();
        Ok(result)
    }

    pub fn get_app_messages_unread_with_context(&self, room_id: &str, context: i32) -> Result<Vec<MessageRow>> {
        let oldest_unread_ts: Option<i64> = self.conn
            .query_row(
                "SELECT MIN(created_at) FROM app_messages WHERE room_id = ?1 AND is_read = 0 AND is_me_send = 0",
                rusqlite::params![room_id],
                |row| row.get(0),
            )
            .map_err(|e| KeychatError::Storage(format!("oldest_unread_ts: {e}")))?;

        let oldest_ts = match oldest_unread_ts {
            Some(ts) => ts,
            None => return self.get_app_messages_latest(room_id, context),
        };

        let mut context_stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
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
        result.reverse();

        let mut unread_stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
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

    pub fn get_app_messages_before(&self, room_id: &str, before_ts: i64, limit: i32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
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
        result.reverse();
        Ok(result)
    }

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
            local_meta: row.get(15)?,
            created_at: row.get(16)?,
        })
    }

    pub fn get_app_message_count(&self, room_id: &str) -> Result<i32> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM app_messages WHERE room_id = ?1",
                rusqlite::params![room_id],
                |row| row.get(0),
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_message_count: {e}")))
    }

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

    pub fn get_app_message_by_event_id(&self, event_id: &str) -> Result<Option<MessageRow>> {
        self.conn
            .query_row(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
                 FROM app_messages WHERE event_id = ?1 LIMIT 1",
                rusqlite::params![event_id],
                Self::map_message_row,
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_message_by_event_id: {e}")))
    }

    pub fn get_app_message_by_msgid(&self, msgid: &str) -> Result<Option<MessageRow>> {
        self.conn
            .query_row(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
                 FROM app_messages WHERE msgid = ?1 LIMIT 1",
                rusqlite::params![msgid],
                Self::map_message_row,
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_message_by_msgid: {e}")))
    }

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

    pub fn mark_app_messages_read(&self, room_id: &str) -> Result<()> {
        self.conn
            .execute("UPDATE app_messages SET is_read = 1 WHERE room_id = ?1 AND is_read = 0", rusqlite::params![room_id])
            .map_err(|e| KeychatError::Storage(format!("mark_app_messages_read: {e}")))?;
        Ok(())
    }

    pub fn update_local_meta(&self, msgid: &str, local_meta: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE app_messages SET local_meta = ?1 WHERE msgid = ?2",
                rusqlite::params![local_meta, msgid],
            )
            .map_err(|e| KeychatError::Storage(format!("update_local_meta: {e}")))?;
        Ok(())
    }

    pub fn get_app_failed_messages(&self) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT msgid, event_id, room_id, identity_pubkey, sender_pubkey, content,
                        is_me_send, is_read, status, reply_to_event_id, reply_to_content,
                        payload_json, nostr_event_json, relay_status_json, local_file_path, local_meta, created_at
                 FROM app_messages WHERE is_me_send = 1 AND status = 2
                 ORDER BY created_at ASC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_failed_messages prepare: {e}")))?;
        let rows = stmt
            .query_map([], Self::map_message_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_failed_messages query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_failed_messages row: {e}")))?);
        }
        Ok(result)
    }

    pub fn delete_app_message(&self, msgid: &str) -> Result<()> {
        self.conn.execute("DELETE FROM app_messages WHERE msgid = ?1", rusqlite::params![msgid])
            .map_err(|e| KeychatError::Storage(format!("delete_app_message: {e}")))?;
        Ok(())
    }

    // ─── App Contact CRUD ────────────────────────────────

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

    fn map_contact_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRow> {
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
    }

    pub fn get_app_contacts(&self, identity_pubkey: &str) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, pubkey, npubkey, identity_pubkey, signal_identity_key, petname, name, about, avatar, created_at, updated_at
                 FROM app_contacts WHERE identity_pubkey = ?1 ORDER BY updated_at DESC",
            )
            .map_err(|e| KeychatError::Storage(format!("get_app_contacts prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![identity_pubkey], Self::map_contact_row)
            .map_err(|e| KeychatError::Storage(format!("get_app_contacts query: {e}")))?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| KeychatError::Storage(format!("get_app_contacts row: {e}")))?);
        }
        Ok(result)
    }

    pub fn get_app_contact(&self, pubkey: &str, identity_pubkey: &str) -> Result<Option<ContactRow>> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.conn
            .query_row(
                "SELECT id, pubkey, npubkey, identity_pubkey, signal_identity_key, petname, name, about, avatar, created_at, updated_at
                 FROM app_contacts WHERE id = ?1",
                rusqlite::params![id],
                Self::map_contact_row,
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_app_contact: {e}")))
    }

    pub fn update_app_contact(
        &self,
        pubkey: &str,
        identity_pubkey: &str,
        petname: Option<&str>,
        name: Option<&str>,
        avatar: Option<&str>,
    ) -> Result<()> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.transaction(|_| {
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
        })
    }

    /// Update contact name without wrapping in a transaction.
    /// Safe to call inside an existing transaction.
    pub fn update_contact_name(&self, pubkey: &str, identity_pubkey: &str, name: &str) -> Result<()> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.conn
            .execute(
                "UPDATE app_contacts SET name = ?1, updated_at = strftime('%s','now') WHERE id = ?2",
                rusqlite::params![name, id],
            )
            .map_err(|e| KeychatError::Storage(format!("update_contact_name: {e}")))?;
        Ok(())
    }

    pub fn delete_app_contact(&self, pubkey: &str, identity_pubkey: &str) -> Result<()> {
        let id = format!("{}:{}", pubkey, identity_pubkey);
        self.conn.execute("DELETE FROM app_contacts WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| KeychatError::Storage(format!("delete_app_contact: {e}")))?;
        Ok(())
    }

    // ─── Composite Operations ─────────────────────────────

    /// Persist an incoming message atomically: ensure room exists, save message,
    /// update room's last message, increment unread count.
    /// Returns the msgid on success.
    pub fn persist_incoming_message(
        &self,
        room_peer: &str,
        identity_pubkey: &str,
        room_status: i32,
        room_type: i32,
        room_name: Option<&str>,
        signal_id: Option<&str>,
        msgid: &str,
        event_id: &str,
        sender_pubkey: &str,
        content: &str,
        display_content: &str,
        status: i32,
        created_at: i64,
    ) -> Result<String> {
        self.transaction(|_| {
            let room_id = self.save_app_room(
                room_peer, identity_pubkey, room_status, room_type,
                room_name, signal_id, None,
            )?;
            self.save_app_message(
                msgid, Some(event_id), &room_id, identity_pubkey,
                sender_pubkey, content, false, status, created_at,
            )?;
            self.update_app_room(&room_id, None, None, Some(display_content), Some(created_at))?;
            self.increment_app_room_unread(&room_id)?;
            Ok(room_id)
        })
    }

    // ─── Bulk Deletion ───────────────────────────────────

    /// Delete all application data including settings.
    pub fn delete_all_data(&self) -> Result<()> {
        self.transaction(|conn| {
            conn.execute_batch(
                "DELETE FROM file_attachments;
                 DELETE FROM app_messages;
                 DELETE FROM app_rooms;
                 DELETE FROM app_contacts;
                 DELETE FROM app_identities;
                 DELETE FROM app_settings;",
            )
            .map_err(|e| KeychatError::Storage(format!("Failed to delete all app data: {e}")))?;
            Ok(())
        })
    }

    // ─── File Attachments CRUD ──────────────────────────

    /// Insert or update a file attachment record.
    /// transfer_state: 0=pending, 1=downloading, 2=downloaded, 3=failed
    pub fn upsert_attachment(
        &self,
        msgid: &str,
        file_hash: &str,
        room_id: &str,
        local_path: Option<&str>,
        transfer_state: i32,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO file_attachments (msgid, file_hash, room_id, local_path, transfer_state)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(msgid, file_hash) DO UPDATE SET
                   local_path = ?4, transfer_state = ?5",
                params![msgid, file_hash, room_id, local_path, transfer_state],
            )
            .map_err(|e| KeychatError::Storage(format!("upsert_attachment: {e}")))?;
        Ok(())
    }

    /// Get the local_path of a downloaded attachment.
    pub fn get_attachment_local_path(
        &self,
        msgid: &str,
        file_hash: &str,
    ) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT local_path FROM file_attachments
                 WHERE msgid = ?1 AND file_hash = ?2 AND transfer_state = 2",
                params![msgid, file_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| KeychatError::Storage(format!("get_attachment_local_path: {e}")))
    }

    /// Mark a voice attachment as played.
    pub fn set_audio_played(&self, msgid: &str, file_hash: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE file_attachments SET audio_played = 1
                 WHERE msgid = ?1 AND file_hash = ?2",
                params![msgid, file_hash],
            )
            .map_err(|e| KeychatError::Storage(format!("set_audio_played: {e}")))?;
        Ok(())
    }

    /// Check if a voice attachment has been played.
    pub fn is_audio_played(&self, msgid: &str, file_hash: &str) -> bool {
        self.conn
            .query_row(
                "SELECT audio_played FROM file_attachments
                 WHERE msgid = ?1 AND file_hash = ?2",
                params![msgid, file_hash],
                |row| row.get::<_, i32>(0),
            )
            .map(|v| v != 0)
            .unwrap_or(false)
    }
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_storage() -> AppStorage {
        AppStorage::open_in_memory("test-key").unwrap()
    }

    #[test]
    fn test_identity_crud() {
        let s = test_storage();
        s.save_app_identity("hex1", "npub1", "Alice", 0, true).unwrap();
        let ids = s.get_app_identities().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].name, "Alice");
        assert_eq!(ids[0].npub, "npub1");
        assert!(ids[0].is_default);

        s.update_app_identity("hex1", Some("Bob"), None, None).unwrap();
        let ids = s.get_app_identities().unwrap();
        assert_eq!(ids[0].name, "Bob");

        s.delete_app_identity("hex1").unwrap();
        assert!(s.get_app_identities().unwrap().is_empty());
    }

    #[test]
    fn test_room_crud() {
        let s = test_storage();
        let id = s.save_app_room("peer1", "id1", 1, 0, Some("Room"), None, None).unwrap();
        assert_eq!(id, "peer1:id1");

        let rooms = s.get_app_rooms("id1").unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].name, Some("Room".into()));

        let room = s.get_app_room(&id).unwrap().unwrap();
        assert_eq!(room.status, 1);

        s.update_app_room(&id, Some(2), None, Some("Hello"), None).unwrap();
        let room = s.get_app_room(&id).unwrap().unwrap();
        assert_eq!(room.status, 2);
        assert_eq!(room.last_message_content, Some("Hello".into()));

        s.increment_app_room_unread(&id).unwrap();
        let room = s.get_app_room(&id).unwrap().unwrap();
        assert_eq!(room.unread_count, 1);

        s.clear_app_room_unread(&id).unwrap();
        let room = s.get_app_room(&id).unwrap().unwrap();
        assert_eq!(room.unread_count, 0);

        s.delete_app_room(&id).unwrap();
        assert!(s.get_app_room(&id).unwrap().is_none());
    }

    #[test]
    fn test_room_cascade_delete() {
        let s = test_storage();
        let parent_id = s.save_app_room("agent1", "id1", 1, 0, Some("Agent"), None, None).unwrap();
        let child_id = s.save_app_room("topic1", "id1", 1, 1, Some("Topic"), None, Some(&parent_id)).unwrap();
        s.save_app_message("m1", None, &parent_id, "id1", "peer", "hello", false, 0, 1000).unwrap();
        s.save_app_message("m2", None, &child_id, "id1", "peer", "world", false, 0, 1001).unwrap();

        s.delete_app_room(&parent_id).unwrap();

        assert!(s.get_app_room(&parent_id).unwrap().is_none());
        assert!(s.get_app_room(&child_id).unwrap().is_none());
        assert_eq!(s.get_app_message_count(&parent_id).unwrap(), 0);
        assert_eq!(s.get_app_message_count(&child_id).unwrap(), 0);
    }

    #[test]
    fn test_message_crud() {
        let s = test_storage();
        s.save_app_room("peer1", "id1", 1, 0, None, None, None).unwrap();
        s.save_app_message("m1", Some("e1"), "peer1:id1", "id1", "peer1", "hello", false, 0, 1000).unwrap();

        let msgs = s.get_app_messages("peer1:id1", 50, 0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "hello");

        assert!(s.is_app_message_duplicate("e1").unwrap());
        assert!(!s.is_app_message_duplicate("e2").unwrap());

        s.update_app_message("m1", None, Some(1), None, None, None, None, None).unwrap();
        let msg = s.get_app_message_by_msgid("m1").unwrap().unwrap();
        assert_eq!(msg.status, 1);

        s.mark_app_messages_read("peer1:id1").unwrap();
        let msg = s.get_app_message_by_msgid("m1").unwrap().unwrap();
        assert!(msg.is_read);

        s.delete_app_message("m1").unwrap();
        assert!(s.get_app_message_by_msgid("m1").unwrap().is_none());
    }

    #[test]
    fn test_contact_crud() {
        let s = test_storage();
        let id = s.save_app_contact("pub1", "npub1", "id1", Some("Alice")).unwrap();
        assert_eq!(id, "pub1:id1");

        let contacts = s.get_app_contacts("id1").unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, Some("Alice".into()));

        s.update_app_contact("pub1", "id1", Some("Ali"), None, None).unwrap();
        let c = s.get_app_contact("pub1", "id1").unwrap().unwrap();
        assert_eq!(c.petname, Some("Ali".into()));

        s.delete_app_contact("pub1", "id1").unwrap();
        assert!(s.get_app_contact("pub1", "id1").unwrap().is_none());
    }

    #[test]
    fn test_file_attachment_crud() {
        let s = test_storage();

        // Insert attachment
        s.upsert_attachment("msg1", "hash1", "room1", Some("room1/file_123.jpg"), 2).unwrap();
        let path = s.get_attachment_local_path("msg1", "hash1").unwrap();
        assert_eq!(path, Some("room1/file_123.jpg".to_string()));

        // Non-existent attachment
        let path = s.get_attachment_local_path("msg1", "hash_missing").unwrap();
        assert_eq!(path, None);

        // Pending state — not returned by get_attachment_local_path
        s.upsert_attachment("msg2", "hash2", "room1", None, 0).unwrap();
        let path = s.get_attachment_local_path("msg2", "hash2").unwrap();
        assert_eq!(path, None);

        // Multi-file: same msgid, different hashes
        s.upsert_attachment("msg3", "hashA", "room1", Some("room1/a.jpg"), 2).unwrap();
        s.upsert_attachment("msg3", "hashB", "room1", Some("room1/b.png"), 2).unwrap();
        assert_eq!(s.get_attachment_local_path("msg3", "hashA").unwrap(), Some("room1/a.jpg".to_string()));
        assert_eq!(s.get_attachment_local_path("msg3", "hashB").unwrap(), Some("room1/b.png".to_string()));

        // Audio played
        assert!(!s.is_audio_played("msg1", "hash1"));
        s.set_audio_played("msg1", "hash1").unwrap();
        assert!(s.is_audio_played("msg1", "hash1"));

        // Upsert updates existing
        s.upsert_attachment("msg1", "hash1", "room1", Some("room1/file_456.jpg"), 2).unwrap();
        let path = s.get_attachment_local_path("msg1", "hash1").unwrap();
        assert_eq!(path, Some("room1/file_456.jpg".to_string()));
    }
}
