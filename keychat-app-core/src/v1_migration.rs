//! V1 → V1.5 data migration.
//!
//! Reads v1 Keychat data (Isar JSON exports + Signal SQLite) and imports
//! into the new encrypted databases (protocol.db + app.db).
//!
//! Called from Swift via UniFFI. The Swift side reads the Isar MDBX files
//! using the libisar C API and passes the exported JSON here.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::params;
use rusqlite::Connection;
use serde::Deserialize;

use crate::app_storage::AppStorage;
use crate::v1_compat::{V1RoomMember, parse_v1_room_member};
use libkeychat::error::{KeychatError, Result};

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─── V1 Isar JSON Structures ────────────────────────────

#[derive(Debug, Deserialize)]
struct V1Identity {
    #[serde(default)]
    id: i64,
    name: Option<String>,
    npub: Option<String>,
    secp256k1PKHex: Option<String>,
    curve25519PkHex: Option<String>,
    isDefault: Option<bool>,
    index: Option<i64>,
    createdAt: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct V1Contact {
    #[serde(default)]
    id: i64,
    pubkey: Option<String>,
    npubkey: Option<String>,
    identityId: Option<i64>,
    curve25519PkHex: Option<String>,
    petname: Option<String>,
    name: Option<String>,
    about: Option<String>,
    createdAt: Option<i64>,
    updatedAt: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct V1Room {
    #[serde(default)]
    id: i64,
    toMainPubkey: Option<String>,
    identityId: Option<i64>,
    npub: Option<String>,
    status: Option<i64>,
    #[serde(rename = "type")]
    room_type: Option<i64>,
    name: Option<String>,
    encryptMode: Option<i64>,
    onetimekey: Option<String>,
    signalIdPubkey: Option<String>,
    curve25519PkHex: Option<String>,
    createdAt: Option<i64>,
    avatar: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V1Message {
    #[serde(default)]
    id: i64,
    msgid: Option<String>,
    identityId: Option<i64>,
    roomId: Option<i64>,
    idPubkey: Option<String>,
    from: Option<String>,
    to: Option<String>,
    content: Option<String>,
    realMessage: Option<String>,
    createdAt: Option<i64>,
    isMeSend: Option<bool>,
    isRead: Option<bool>,
    sent: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct V1Relay {
    #[serde(default)]
    id: i64,
    url: Option<String>,
}

// ─── Migration Entry Point ──────────────────────────────

/// Main migration function called from Swift via UniFFI.
///
/// `isar_json`: JSON dictionary keyed by collection name, values are JSON arrays.
/// `signal_db_path`: Path to v1's unencrypted signal_protocol.db (or empty string).
/// `app_storage`: Reference to the new encrypted app database.
/// `protocol_db_path`: Path to the new encrypted protocol.db.
/// `protocol_db_key`: Encryption key for protocol.db.
pub fn migrate_from_v1(
    isar_json: &str,
    signal_db_path: &str,
    app_storage: &AppStorage,
    protocol_db_path: &str,
    protocol_db_key: &str,
) -> Result<MigrationReport> {
    let collections: HashMap<String, String> =
        serde_json::from_str(isar_json).map_err(|e| {
            KeychatError::Storage(format!("Failed to parse migration JSON: {e}"))
        })?;

    let mut report = MigrationReport::default();

    // Build identity_id → pubkey mapping (needed for Room/Contact/Message migration)
    let mut identity_map: HashMap<i64, String> = HashMap::new();

    // Pre-parse all collections outside the transaction
    let identities: Vec<V1Identity> = collections
        .get("Identity")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let contacts: Vec<V1Contact> = collections
        .get("Contact")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let rooms: Vec<V1Room> = collections
        .get("Room")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let messages: Vec<V1Message> = collections
        .get("Message")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let relays: Vec<V1Relay> = collections
        .get("Relay")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let room_members: Vec<V1RoomMember> = collections
        .get("RoomMember")
        .and_then(|j| serde_json::from_str::<Vec<serde_json::Value>>(j).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(parse_v1_room_member)
        .collect();

    // ─── Build identity map first ────────────────────────
    for v1 in &identities {
        if let Some(pk) = &v1.secp256k1PKHex {
            if !pk.is_empty() {
                identity_map.insert(v1.id, pk.clone());
            }
        }
    }

    // ─── Single transaction for ALL app.db writes ────────
    // This is 100x faster than individual autocommit inserts.
    let mut room_id_map: HashMap<i64, String> = HashMap::new();

    app_storage.transaction(|conn| {
        // ─── 1. Identities ───────────────────────────────
        {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO app_identities (nostr_pubkey_hex, npub, name, idx, is_default, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now'))
                 ON CONFLICT(nostr_pubkey_hex) DO UPDATE SET
                   npub = excluded.npub, name = excluded.name,
                   idx = excluded.idx, is_default = excluded.is_default",
            ).map_err(|e| KeychatError::Storage(format!("prepare identity: {e}")))?;

            for v1 in &identities {
                let pubkey_hex = match &v1.secp256k1PKHex {
                    Some(pk) if !pk.is_empty() => pk,
                    _ => continue,
                };
                let npub = match &v1.npub {
                    Some(n) if !n.is_empty() => n,
                    _ => continue,
                };
                let name = v1.name.as_deref().unwrap_or("Keychat User");
                let idx = v1.index.unwrap_or(0) as i32;
                let is_default = v1.isDefault.unwrap_or(false);

                if stmt.execute(params![pubkey_hex, npub, name, idx, is_default as i32]).is_ok() {
                    report.identities += 1;
                }
            }
        }

        // ─── 2. Contacts ──────────────────────────────────
        {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO app_contacts (id, pubkey, npubkey, identity_pubkey, signal_identity_key, petname, name, about, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                   name = COALESCE(excluded.name, name),
                   petname = COALESCE(excluded.petname, petname),
                   about = COALESCE(excluded.about, about),
                   signal_identity_key = COALESCE(excluded.signal_identity_key, signal_identity_key)",
            ).map_err(|e| KeychatError::Storage(format!("prepare contact: {e}")))?;

            for v1 in &contacts {
                let pubkey = match &v1.pubkey {
                    Some(pk) if !pk.is_empty() => pk,
                    _ => continue,
                };
                let identity_pubkey = match v1.identityId.and_then(|id| identity_map.get(&id)) {
                    Some(pk) => pk,
                    None => continue,
                };
                let id = format!("{}:{}", pubkey, identity_pubkey);
                let npubkey = v1.npubkey.as_deref().unwrap_or("");
                let now = now_ts();

                if stmt.execute(params![
                    id, pubkey, npubkey, identity_pubkey,
                    v1.curve25519PkHex, v1.petname, v1.name, v1.about, now
                ]).is_ok() {
                    report.contacts += 1;
                }
            }
        }

        // ─── 3. Rooms ────────────────────────────────────
        {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO app_rooms (id, to_main_pubkey, identity_pubkey, status, type, name, peer_signal_identity_key, peer_version, session_type, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 'x3dh', strftime('%s','now'))
                 ON CONFLICT(id) DO NOTHING",
            ).map_err(|e| KeychatError::Storage(format!("prepare room: {e}")))?;

            for v1 in &rooms {
                let to_main_pubkey = match &v1.toMainPubkey {
                    Some(pk) if !pk.is_empty() => pk,
                    _ => continue,
                };
                let identity_pubkey = match v1.identityId.and_then(|id| identity_map.get(&id)) {
                    Some(pk) => pk,
                    None => continue,
                };
                let room_id = format!("{}:{}", to_main_pubkey, identity_pubkey);
                // MLS groups: incompatible crypto state, archive with correct type
                let (status, room_type) = if v1.encryptMode == Some(3) {
                    (3_i32, 2_i32) // RoomStatus::Archived, RoomType::MlsGroup
                } else {
                    (v1.status.unwrap_or(0) as i32, v1.room_type.unwrap_or(0) as i32)
                };

                if stmt.execute(params![
                    room_id, to_main_pubkey, identity_pubkey,
                    status, room_type, v1.name, v1.curve25519PkHex
                ]).is_ok() {
                    room_id_map.insert(v1.id, room_id);
                    report.rooms += 1;
                }
            }
        }

        // ─── 4. Messages ─────────────────────────────────
        {
            let mut stmt = conn.prepare_cached(
                "INSERT OR IGNORE INTO app_messages (msgid, room_id, identity_pubkey, sender_pubkey, content, is_me_send, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            ).map_err(|e| KeychatError::Storage(format!("prepare message: {e}")))?;

            for v1 in &messages {
                let room_id = match v1.roomId.and_then(|id| room_id_map.get(&id)) {
                    Some(rid) => rid.as_str(),
                    None => continue,
                };
                let identity_pubkey = match v1.identityId.and_then(|id| identity_map.get(&id)) {
                    Some(pk) => pk.as_str(),
                    None => continue,
                };

                let content = v1.realMessage.as_deref()
                    .or(v1.content.as_deref())
                    .unwrap_or("");
                let msgid = v1.msgid.as_deref().map(|s| s.to_string())
                    .unwrap_or_else(|| format!("v1-{}", v1.id));
                let is_me_send = v1.isMeSend.unwrap_or(false);
                let sender_pubkey = if is_me_send {
                    identity_pubkey.to_string()
                } else {
                    v1.from.clone().unwrap_or_default()
                };
                let status = match v1.sent.unwrap_or(1) {
                    0 => 0, 1 | 2 => 1, 3 => 2, _ => 1,
                };
                let created_at = v1.createdAt.unwrap_or(0);

                if stmt.execute(params![
                    msgid, room_id, identity_pubkey, sender_pubkey,
                    content, is_me_send as i32, status, created_at
                ]).is_ok() {
                    report.messages += 1;
                }
            }
        }

        // ─── Update room last_message ────────────────────
        conn.execute_batch(
            "UPDATE app_rooms SET
                last_message_content = (
                    SELECT content FROM app_messages
                    WHERE app_messages.room_id = app_rooms.id
                    ORDER BY created_at DESC LIMIT 1
                ),
                last_message_at = (
                    SELECT created_at FROM app_messages
                    WHERE app_messages.room_id = app_rooms.id
                    ORDER BY created_at DESC LIMIT 1
                ),
                unread_count = (
                    SELECT COUNT(*) FROM app_messages
                    WHERE app_messages.room_id = app_rooms.id AND is_read = 0
                )",
        ).map_err(|e| KeychatError::Storage(format!("update room last messages: {e}")))?;

        Ok(())
    })?; // end transaction

    // ─── 5. Migrate Room Members ─────────────────────────
    if !room_members.is_empty() {
        report.room_members = migrate_v1_room_members(app_storage, &room_members, &room_id_map);
    }

    // ─── 6. Migrate Signal Sessions ──────────────────────
    if !signal_db_path.is_empty() && Path::new(signal_db_path).exists() {
        match migrate_signal_sessions(signal_db_path, protocol_db_path, protocol_db_key) {
            Ok(count) => report.signal_sessions = count,
            Err(e) => tracing::error!("Migration: Signal session migration failed: {e}"),
        }
    }

    // ─── 7. Migrate Relays ───────────────────────────────
    if let Ok(conn) = open_protocol_db(protocol_db_path, protocol_db_key) {
        for v1 in &relays {
            if let Some(url) = &v1.url {
                if !url.is_empty() {
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO relays (url) VALUES (?1)",
                        params![url],
                    );
                    report.relays += 1;
                }
            }
        }
    }

    tracing::info!(
        "Migration complete: {} identities, {} contacts, {} rooms, {} messages, {} room members, {} signal sessions, {} relays",
        report.identities, report.contacts, report.rooms, report.messages,
        report.room_members, report.signal_sessions, report.relays
    );

    Ok(report)
}

// ─── Signal Session Migration ───────────────────────────

fn migrate_signal_sessions(
    v1_signal_path: &str,
    protocol_db_path: &str,
    protocol_db_key: &str,
) -> Result<u32> {
    let v1_conn = Connection::open(v1_signal_path).map_err(|e| {
        KeychatError::Storage(format!("Failed to open v1 signal DB: {e}"))
    })?;

    let protocol_conn = open_protocol_db(protocol_db_path, protocol_db_key)?;
    let mut count = 0u32;
    let now = now_ts();

    // Migrate session records: v1 stores as hex TEXT, v1.5 stores as BLOB
    {
        let mut stmt = v1_conn
            .prepare("SELECT address, device, record FROM session")
            .map_err(|e| KeychatError::Storage(format!("v1 sessions query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| KeychatError::Storage(format!("v1 sessions read: {e}")))?;

        for row in rows.flatten() {
            let (address, device_id, record_hex) = row;
            if let Ok(record_bytes) = hex::decode(&record_hex) {
                let _ = protocol_conn.execute(
                    "INSERT OR REPLACE INTO signal_sessions (address, device_id, record, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    params![address, device_id, record_bytes, now],
                );
                count += 1;
            }
        }
    }

    // Migrate pre_keys
    {
        let mut stmt = v1_conn
            .prepare("SELECT keyId, record FROM pre_key WHERE used = 0")
            .map_err(|e| KeychatError::Storage(format!("v1 pre_key query: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| KeychatError::Storage(format!("v1 pre_key read: {e}")))?;

        for row in rows.flatten() {
            let (key_id, record_hex) = row;
            if let Ok(record_bytes) = hex::decode(&record_hex) {
                let _ = protocol_conn.execute(
                    "INSERT OR REPLACE INTO pre_keys (id, record) VALUES (?1, ?2)",
                    params![key_id, record_bytes],
                );
            }
        }
    }

    // Migrate signed_pre_keys
    {
        let mut stmt = v1_conn
            .prepare("SELECT keyId, record FROM signed_key")
            .map_err(|e| KeychatError::Storage(format!("v1 signed_key query: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| KeychatError::Storage(format!("v1 signed_key read: {e}")))?;

        for row in rows.flatten() {
            let (key_id, record_hex) = row;
            if let Ok(record_bytes) = hex::decode(&record_hex) {
                let _ = protocol_conn.execute(
                    "INSERT OR REPLACE INTO signed_pre_keys (id, record) VALUES (?1, ?2)",
                    params![key_id, record_bytes],
                );
            }
        }
    }

    // Migrate identity keys
    {
        let mut stmt = v1_conn
            .prepare("SELECT address, publicKey, privateKey FROM identity")
            .map_err(|e| KeychatError::Storage(format!("v1 identity query: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| KeychatError::Storage(format!("v1 identity read: {e}")))?;

        for row in rows.flatten() {
            let (address, pub_hex, pri_hex) = row;
            let pub_bytes = hex::decode(&pub_hex).unwrap_or_default();
            let pri_bytes = pri_hex.and_then(|h| hex::decode(&h).ok());
            let is_own = pri_bytes.is_some();
            let _ = protocol_conn.execute(
                "INSERT OR REPLACE INTO identity_keys (address, public_key, private_key, is_own) VALUES (?1, ?2, ?3, ?4)",
                params![address, pub_bytes, pri_bytes, is_own as i32],
            );
        }
    }

    tracing::info!("Migrated {count} Signal sessions from v1");
    Ok(count)
}

// ─── Room Member Migration ─────────────────────────────

/// Migrate v1 room members into app_room_members.
///
/// Skips members with status == 3 (removed).
/// Maps old Isar room_id (i64) to new app_rooms id (String) via `room_id_map`.
fn migrate_v1_room_members(
    app_storage: &AppStorage,
    members: &[V1RoomMember],
    room_id_map: &HashMap<i64, String>,
) -> u32 {
    let mut count = 0u32;
    for m in members {
        // Skip removed members
        if m.status == 3 {
            continue;
        }
        let new_room_id = match room_id_map.get(&m.room_id) {
            Some(id) => id.as_str(),
            None => continue,
        };
        if app_storage
            .save_room_member(
                new_room_id,
                &m.id_pubkey,
                m.name.as_deref(),
                m.is_admin,
                m.status,
            )
            .is_ok()
        {
            count += 1;
        }
    }
    count
}

// ─── Helpers ────────────────────────────────────────────

fn open_protocol_db(path: &str, key: &str) -> Result<Connection> {
    let conn = Connection::open(path)
        .map_err(|e| KeychatError::Storage(format!("open protocol DB: {e}")))?;
    conn.execute_batch(&format!("PRAGMA key = '{key}';"))
        .map_err(|e| KeychatError::Storage(format!("set protocol DB key: {e}")))?;
    Ok(conn)
}

// ─── Report ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct MigrationReport {
    pub identities: u32,
    pub contacts: u32,
    pub rooms: u32,
    pub messages: u32,
    pub room_members: u32,
    pub signal_sessions: u32,
    pub relays: u32,
}
