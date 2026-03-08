use std::path::PathBuf;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::storage::{DataStore, StoredPeer, StoredSignalIdentity, StoredSignalSession};

#[derive(Debug)]
pub struct SqliteStore {
    path: PathBuf,
}

impl SqliteStore {
    pub fn open(path: &str) -> Result<Self> {
        let store = Self {
            path: PathBuf::from(path),
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        self.connection()?.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS signal_sessions (
                peer_id TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                record BLOB NOT NULL,
                PRIMARY KEY (peer_id, device_id)
            );
            CREATE TABLE IF NOT EXISTS signal_prekeys (
                key_id TEXT PRIMARY KEY,
                record BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS signal_signed_prekeys (
                key_id TEXT PRIMARY KEY,
                record BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS signal_identity_keys (
                key_id TEXT PRIMARY KEY,
                registration_id INTEGER NOT NULL,
                record BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peers (
                peer_id TEXT PRIMARY KEY,
                nostr_pubkey TEXT NOT NULL,
                signal_pubkey TEXT NOT NULL,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receiving_addresses (
                address TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS client_state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection> {
        Ok(Connection::open(&self.path)?)
    }
}

impl SqliteStore {
    /// Save a blob to the client_state key-value store.
    pub fn save_state(&self, key: &str, value: &[u8]) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO client_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            params![key, value],
        )?;
        Ok(())
    }

    /// Load a blob from the client_state key-value store.
    pub fn load_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.connection()?
            .query_row(
                "SELECT value FROM client_state WHERE key = ?1;",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// List all peer IDs that have stored Signal sessions.
    pub fn list_peers(&self) -> Result<Vec<StoredPeer>> {
        let conn = self.connection()?;
        let mut stmt =
            conn.prepare("SELECT peer_id, nostr_pubkey, signal_pubkey, name FROM peers;")?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredPeer {
                peer_id: row.get(0)?,
                nostr_pubkey: row.get(1)?,
                signal_pubkey: row.get(2)?,
                name: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

impl DataStore for SqliteStore {
    fn upsert_signal_session(&mut self, session: StoredSignalSession) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO signal_sessions (peer_id, device_id, record) VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id, device_id) DO UPDATE SET record = excluded.record;",
            params![session.peer_id, session.device_id, session.record],
        )?;
        Ok(())
    }

    fn load_signal_sessions(&self, peer_id: &str) -> Result<Vec<StoredSignalSession>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT peer_id, device_id, record FROM signal_sessions WHERE peer_id = ?1 ORDER BY device_id;",
        )?;
        let rows = stmt.query_map(params![peer_id], |row| {
            Ok(StoredSignalSession {
                peer_id: row.get(0)?,
                device_id: row.get(1)?,
                record: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO signal_prekeys (key_id, record) VALUES (?1, ?2)
             ON CONFLICT(key_id) DO UPDATE SET record = excluded.record;",
            params![key_id, record],
        )?;
        Ok(())
    }

    fn load_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        self.connection()?
            .query_row(
                "SELECT record FROM signal_prekeys WHERE key_id = ?1;",
                params![key_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn upsert_signed_prekey(&mut self, key_id: &str, record: Vec<u8>) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO signal_signed_prekeys (key_id, record) VALUES (?1, ?2)
             ON CONFLICT(key_id) DO UPDATE SET record = excluded.record;",
            params![key_id, record],
        )?;
        Ok(())
    }

    fn load_signed_prekey(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        self.connection()?
            .query_row(
                "SELECT record FROM signal_signed_prekeys WHERE key_id = ?1;",
                params![key_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn upsert_identity_key(&mut self, identity: StoredSignalIdentity) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO signal_identity_keys (key_id, registration_id, record) VALUES (?1, ?2, ?3)
             ON CONFLICT(key_id) DO UPDATE SET registration_id = excluded.registration_id, record = excluded.record;",
            params![identity.key_id, identity.registration_id, identity.record],
        )?;
        Ok(())
    }

    fn load_identity_key(&self, key_id: &str) -> Result<Option<StoredSignalIdentity>> {
        self.connection()?
            .query_row(
                "SELECT key_id, registration_id, record FROM signal_identity_keys WHERE key_id = ?1;",
                params![key_id],
                |row| {
                    Ok(StoredSignalIdentity {
                        key_id: row.get(0)?,
                        registration_id: row.get(1)?,
                        record: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn upsert_peer(&mut self, peer: StoredPeer) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO peers (peer_id, nostr_pubkey, signal_pubkey, name) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_id) DO UPDATE SET nostr_pubkey = excluded.nostr_pubkey, signal_pubkey = excluded.signal_pubkey, name = excluded.name;",
            params![peer.peer_id, peer.nostr_pubkey, peer.signal_pubkey, peer.name],
        )?;
        Ok(())
    }

    fn load_peer(&self, peer_id: &str) -> Result<Option<StoredPeer>> {
        self.connection()?
            .query_row(
                "SELECT peer_id, nostr_pubkey, signal_pubkey, name FROM peers WHERE peer_id = ?1;",
                params![peer_id],
                |row| {
                    Ok(StoredPeer {
                        peer_id: row.get(0)?,
                        nostr_pubkey: row.get(1)?,
                        signal_pubkey: row.get(2)?,
                        name: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn map_receiving_address(&mut self, address: &str, peer_id: &str) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO receiving_addresses (address, peer_id) VALUES (?1, ?2)
             ON CONFLICT(address) DO UPDATE SET peer_id = excluded.peer_id;",
            params![address, peer_id],
        )?;
        Ok(())
    }

    fn resolve_receiving_address(&self, address: &str) -> Result<Option<String>> {
        self.connection()?
            .query_row(
                "SELECT peer_id FROM receiving_addresses WHERE address = ?1;",
                params![address],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn mark_processed_event(&mut self, event_id: &str) -> Result<()> {
        self.connection()?.execute(
            "INSERT OR IGNORE INTO processed_events (event_id) VALUES (?1);",
            params![event_id],
        )?;
        Ok(())
    }

    fn has_processed_event(&self, event_id: &str) -> Result<bool> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM processed_events WHERE event_id = ?1;",
                params![event_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}
