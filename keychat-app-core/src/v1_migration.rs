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
use crate::v1_compat::{parse_v1_room_member, V1RoomMember};
use libkeychat::error::{KeychatError, Result};
use libkeychat::{
    derive_address_with_secret, derive_v1_signal_identity, DerivedAddressSerialized,
    PeerAddressStateSerialized, SignalIdentity,
};

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

/// v1 Flutter `ContactReceiveKey` Isar row — per-peer list of x-only pubkeys
/// the v1 app has subscribed to as rolling receive addresses for this peer.
///
/// These values are v1's *cache* of what the signal Double-Ratchet is producing
/// as our `aliceAddresses` — they are x-only secp256k1 pubkeys, ready to use in
/// the v1.5 subscription filter verbatim with no further computation.
///
/// Populated by `ContactService.addReceiveKey` on the send side of
/// `SignalChatService.sendMessage` whenever the libsignal encrypt step opens
/// a new DH epoch. If the v1 user only ever received messages (never sent) on
/// a given room, `receiveKeys` may be empty — in that case the migration falls
/// back to deriving from the signal DB's `session.aliceAddresses` via the
/// byte-for-byte identical `derive_address_with_secret` path (see
/// `migrate_signal_sessions`).
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct V1ContactReceiveKey {
    #[serde(default)]
    identityId: Option<i64>,
    /// Peer's main Nostr pubkey (hex). Matches `Room.toMainPubkey` /
    /// `Contact.pubkey` — this is how we join a CRK row to a signal session.
    pubkey: Option<String>,
    #[serde(default)]
    receiveKeys: Vec<String>,
}

// ─── Migration Entry Point ──────────────────────────────

/// Main migration function called from Swift via UniFFI.
///
/// `isar_json`: JSON dictionary keyed by collection name, values are JSON arrays.
/// `signal_db_path`: Path to v1's unencrypted signal_protocol.db (or empty string).
/// `app_storage`: Reference to the new encrypted app database.
/// `protocol_db_path`: Path to the new encrypted protocol.db.
/// `protocol_db_key`: Encryption key for protocol.db.
/// `mnemonic`: Optional BIP-39 mnemonic for the current installation. When
/// provided, we derive the v1 user's Curve25519 identity for each account index
/// and populate `peer_mappings` + `signal_participants` for every migrated
/// Signal session — without this, libkeychat's orchestrator restore cannot
/// resume the session (see `orchestrator.rs::restore_persistent`).
pub fn migrate_from_v1(
    isar_json: &str,
    signal_db_path: &str,
    app_storage: &AppStorage,
    protocol_db_path: &str,
    protocol_db_key: &str,
    mnemonic: Option<&str>,
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
    let contact_receive_keys: Vec<V1ContactReceiveKey> = collections
        .get("ContactReceiveKey")
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();

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
        // Build room index keyed by `curve25519PkHex` (= v1 session.address) so
        // signal-session migration can look up the corresponding Nostr peer
        // (Contact.pubkey via Room.toMainPubkey) and identity account index.
        let mut session_addr_to_room_info: HashMap<String, SessionRoomContext> = HashMap::new();
        for room in &rooms {
            let addr = match &room.curve25519PkHex {
                Some(a) if !a.is_empty() => a.clone(),
                _ => continue,
            };
            let to_main = match &room.toMainPubkey {
                Some(t) if !t.is_empty() => t.clone(),
                _ => continue,
            };
            let identity_pubkey = match room.identityId.and_then(|id| identity_map.get(&id)) {
                Some(pk) => pk.clone(),
                None => continue,
            };
            // Find matching contact (pubkey, name).
            let contact_name = contacts
                .iter()
                .find(|c| c.pubkey.as_deref() == Some(to_main.as_str()))
                .and_then(|c| c.petname.clone().or_else(|| c.name.clone()))
                .unwrap_or_else(|| to_main[..16.min(to_main.len())].to_string());

            // Identity index (account) for the derivation `m/44'/1238'/{idx}'/0/0`.
            let account = identities
                .iter()
                .find(|v1| v1.secp256k1PKHex.as_deref() == Some(identity_pubkey.as_str()))
                .and_then(|v1| v1.index)
                .unwrap_or(0) as u32;

            session_addr_to_room_info.insert(
                addr,
                SessionRoomContext {
                    peer_nostr_pubkey: to_main,
                    contact_name,
                    account,
                    identity_pubkey: identity_pubkey.clone(),
                },
            );
        }

        // Build a direct lookup of v1's pre-computed receive-address pubkeys,
        // keyed by `(identity_pubkey, peer_main_pubkey)`. When a v1 session
        // has a matching entry with a non-empty list, the migration will
        // populate `receiving_addresses[].address` verbatim from these values
        // instead of re-deriving from `session.aliceAddresses`. This honours
        // the "直接使用" criterion (parallel to how signal session records are
        // lifted as opaque bytes): the subscription filter uses exactly the
        // pubkeys v1 was actually listening on.
        let mut crk_receive_keys: HashMap<(String, String), Vec<String>> = HashMap::new();
        for crk in &contact_receive_keys {
            let peer_main = match &crk.pubkey {
                Some(pk) if !pk.is_empty() => pk.clone(),
                _ => continue,
            };
            let identity_pubkey = match crk.identityId.and_then(|id| identity_map.get(&id)) {
                Some(pk) => pk.clone(),
                None => continue,
            };
            let keys: Vec<String> = crk
                .receiveKeys
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect();
            if keys.is_empty() {
                continue;
            }
            crk_receive_keys.insert((identity_pubkey, peer_main), keys);
        }
        tracing::info!(
            "Migration: loaded {} v1 ContactReceiveKey row(s) with non-empty receiveKeys \
             (direct-copy source for receiving_addresses)",
            crk_receive_keys.len()
        );

        // Pre-derive Signal identities per account index so we don't re-derive
        // for each session. Only done when a mnemonic is supplied.
        let mut identity_by_account: HashMap<u32, SignalIdentity> = HashMap::new();
        if let Some(words) = mnemonic {
            for account in session_addr_to_room_info
                .values()
                .map(|c| c.account)
                .collect::<std::collections::BTreeSet<_>>()
            {
                match derive_v1_signal_identity(words, None, account) {
                    Ok(id) => {
                        identity_by_account.insert(account, id);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Migration: failed to derive v1 signal identity (account={account}): {e}"
                        );
                    }
                }
            }
        } else {
            tracing::warn!(
                "Migration: no mnemonic provided — Signal sessions will be copied but \
                 peer_mappings + signal_participants will NOT be populated, so restored \
                 sessions will not be usable."
            );
        }

        // Build identity_pubkey → account map so migrate_signal_sessions can
        // resolve `(identity_pubkey, peer_main)` CRK lookups back to an
        // account index when emitting per-session logs.
        let _ = &crk_receive_keys; // borrow-checker anchor; moved into call below

        match migrate_signal_sessions(
            signal_db_path,
            protocol_db_path,
            protocol_db_key,
            &session_addr_to_room_info,
            &identity_by_account,
            &crk_receive_keys,
        ) {
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

/// Extra room-level context needed to fully restore an orchestrator-visible
/// session: the peer's Nostr pubkey (from `Room.toMainPubkey`), the display
/// name (from the matching Contact), the v1 identity's account index (for the
/// Curve25519 BIP-32 derivation), and the v1 identity's own Nostr pubkey
/// (needed to join against `ContactReceiveKey`, which is keyed by identityId).
struct SessionRoomContext {
    peer_nostr_pubkey: String,
    contact_name: String,
    account: u32,
    identity_pubkey: String,
}

/// Migrate v1 Signal sessions → v1.5 protocol.db.
///
/// `crk_receive_keys` maps `(identity_pubkey, peer_main_pubkey)` to v1's
/// pre-computed receive-address pubkeys from Isar `ContactReceiveKey.receiveKeys`.
/// When non-empty for a given session, the migration uses these values
/// verbatim for `receiving_addresses[].address` instead of deriving from
/// `session.aliceAddresses` — honours the "直接使用" criterion (parallel to
/// how signal session bytes are lifted as opaque blobs).
fn migrate_signal_sessions(
    v1_signal_path: &str,
    protocol_db_path: &str,
    protocol_db_key: &str,
    session_to_room: &HashMap<String, SessionRoomContext>,
    identity_by_account: &HashMap<u32, SignalIdentity>,
    crk_receive_keys: &HashMap<(String, String), Vec<String>>,
) -> Result<u32> {
    let v1_conn = Connection::open(v1_signal_path).map_err(|e| {
        KeychatError::Storage(format!("Failed to open v1 signal DB: {e}"))
    })?;

    let protocol_conn = open_protocol_db(protocol_db_path, protocol_db_key)?;
    let mut count = 0u32;
    let now = now_ts();

    // Pick any valid v1 signed_key record to use as a placeholder for
    // `signal_participants.signed_prekey_record`. The orchestrator restore path
    // does not consume this field for active sessions (it's `_spk_rec` in
    // `orchestrator::restore_persistent`), but the column is NOT NULL and must
    // decode as a libsignal `SignedPreKeyRecord` if anything ever touches it.
    let (placeholder_spk_id, placeholder_spk_rec): (u32, Vec<u8>) = {
        let mut stmt = v1_conn
            .prepare("SELECT keyId, record FROM signed_key ORDER BY keyId LIMIT 1")
            .map_err(|e| KeychatError::Storage(format!("v1 signed_key placeholder query: {e}")))?;
        stmt.query_row([], |row| {
            let id: i64 = row.get(0)?;
            let hex_str: String = row.get(1)?;
            Ok((id as u32, hex::decode(&hex_str).unwrap_or_default()))
        })
        .unwrap_or((0, Vec::new()))
    };

    // Migrate session records: v1 stores as hex TEXT, v1.5 stores as BLOB.
    // For each session we also write peer_mappings + signal_participants rows
    // (if mnemonic derivation succeeded) so the orchestrator can restore
    // the session on the next `initialise()` call.
    {
        // v1 session schema (signal_procotol.db):
        //   address         = peer's Signal curve25519 identity (hex, starts with "05")
        //   device          = Signal device id (almost always 1)
        //   record          = libsignal SessionRecord blob (hex)
        //   bobAddress      = peer's current receive address, format "{hash}-{pub}"
        //   aliceAddresses  = OUR rolling receive addresses (comma-separated),
        //                     each entry format "{private}-{public}" matching
        //                     libkeychat's ratchet_key derivation input.
        let mut stmt = v1_conn
            .prepare(
                "SELECT address, device, record, \
                        COALESCE(bobAddress,''), COALESCE(aliceAddresses,'') \
                 FROM session",
            )
            .map_err(|e| KeychatError::Storage(format!("v1 sessions query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| KeychatError::Storage(format!("v1 sessions read: {e}")))?;

        for row in rows.flatten() {
            let (address, device_id, record_hex, bob_address_raw, alice_addresses_raw) = row;
            let record_bytes = match hex::decode(&record_hex) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Migration: skipping session {address}: record hex decode: {e}");
                    continue;
                }
            };

            // 1. signal_sessions row (libsignal SessionRecord blob).
            if let Err(e) = protocol_conn.execute(
                "INSERT OR REPLACE INTO signal_sessions (address, device_id, record, updated_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![address, device_id, record_bytes, now],
            ) {
                tracing::warn!("Migration: signal_sessions insert failed for {address}: {e}");
                continue;
            }

            // 2. peer_mappings + signal_participants — only when we have a room
            //    match AND a derived Signal identity for that identity's account.
            let ctx = match session_to_room.get(&address) {
                Some(c) => c,
                None => {
                    tracing::warn!(
                        "Migration: session {address} has no matching v1 Room \
                         (curve25519PkHex); skipping peer/participant rows."
                    );
                    count += 1;
                    continue;
                }
            };
            let signal_identity = match identity_by_account.get(&ctx.account) {
                Some(id) => id,
                None => {
                    tracing::warn!(
                        "Migration: session {address} account={} has no derived v1 identity \
                         (mnemonic missing or derive failed); session restored in signal_sessions \
                         but orchestrator will not see it.",
                        ctx.account
                    );
                    count += 1;
                    continue;
                }
            };

            // peer_mappings: Nostr ↔ Signal for the orchestrator's reverse indexes.
            if let Err(e) = protocol_conn.execute(
                "INSERT OR REPLACE INTO peer_mappings \
                 (nostr_pubkey, signal_id, name, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![ctx.peer_nostr_pubkey, address, ctx.contact_name, now],
            ) {
                tracing::warn!("Migration: peer_mappings insert failed for {address}: {e}");
            }

            // signal_participants: our per-peer Signal identity (derived from v1 mnemonic).
            // device_id, identity_public/private, reg_id come from the v1 session + mnemonic.
            let reg_id: u32 = 0; // v1 Flutter always uses reg_id=0 for initialised store.
            if let Err(e) = protocol_conn.execute(
                "INSERT OR REPLACE INTO signal_participants \
                 (peer_signal_id, device_id, identity_public, identity_private, \
                  registration_id, signed_prekey_id, signed_prekey_record, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    address,
                    device_id,
                    signal_identity.public_key.to_vec(),
                    signal_identity.private_key.to_vec(),
                    reg_id,
                    placeholder_spk_id,
                    placeholder_spk_rec.clone(),
                    now,
                ],
            ) {
                tracing::warn!("Migration: signal_participants insert failed for {address}: {e}");
            }

            // peer_addresses: restore the full AddressManager state so the
            // orchestrator's `receiving_addr_to_peer` reverse index is rebuilt
            // (required for decrypting incoming messages) AND the next outbound
            // uses the peer's last known receive address (not just a Priority-3
            // Nostr-pubkey fallback).
            //
            // receiving_addresses  ← PRIMARY: v1 Isar `ContactReceiveKey.receiveKeys`
            //                        copied verbatim into `address` — this is
            //                        the pre-computed x-only pubkey list v1
            //                        itself was actively subscribing to.
            //                        `secret_key` + `ratchet_key` are then
            //                        filled by matching each CRK pubkey against
            //                        the derived output of a `session.aliceAddresses`
            //                        entry (needed for NIP-44 giftwrap decrypt
            //                        and for the orchestrator's internal state).
            //                        FALLBACK: when CRK is empty (common on v1
            //                        installs that only received, never sent),
            //                        derive all three fields from
            //                        `session.aliceAddresses` via the
            //                        byte-for-byte identical ECDH path v1 Flutter
            //                        would have computed at send-time
            //                        (`generate_seed_from_ratchetkey_pair`
            //                        ⇔ `derive_address_with_secret`).
            // sending_address      ← v1 `session.bobAddress` re-derived via the
            //                        same ECDH path. v1 does not store bobAddress
            //                        as a pre-computed pubkey; every send runs
            //                        `generate_seed_from_ratchetkey_pair` on
            //                        `{priv}-{pub}`, so we necessarily mirror
            //                        that at migration time.
            // peer_nostr_pubkey    ← fallback kept for Priority-3 resolution.

            // Derive every aliceAddresses entry once so we can:
            //   (a) match CRK pubkeys to their `(secret_key, ratchet_key)`, and
            //   (b) use the full list as the fallback when CRK is empty.
            let alice_derived: Vec<(String, DerivedAddressSerialized)> = alice_addresses_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(|entry| match derive_address_with_secret(entry) {
                    Ok(d) => Some((
                        entry.to_string(),
                        DerivedAddressSerialized {
                            address: d.address,
                            secret_key: d.secret_key,
                            ratchet_key: d.ratchet_key,
                        },
                    )),
                    Err(e) => {
                        tracing::warn!(
                            "Migration: skipping malformed v1 aliceAddresses entry \
                             for {address}: {e}"
                        );
                        None
                    }
                })
                .collect();

            let crk_hit = crk_receive_keys
                .get(&(ctx.identity_pubkey.clone(), ctx.peer_nostr_pubkey.clone()));
            let receiving_addresses: Vec<DerivedAddressSerialized> = match crk_hit {
                Some(pubkeys) if !pubkeys.is_empty() => {
                    // DIRECT-COPY PATH: use v1's pre-computed pubkey list verbatim.
                    let mut out = Vec::with_capacity(pubkeys.len());
                    for pk in pubkeys {
                        // Best-effort match to an aliceAddresses-derived entry so
                        // we can populate secret_key + ratchet_key. If no match,
                        // still emit an address-only row — the subscription filter
                        // works on `address` alone, and a missing secret just means
                        // the orchestrator won't decrypt NIP-44 giftwrap at this
                        // pubkey (giftwrap addresses rotate: this is an acceptable
                        // loss for legacy CRK entries whose ratchet pair has since
                        // been pruned from the session record).
                        if let Some((_, der)) = alice_derived
                            .iter()
                            .find(|(_, d)| d.address.eq_ignore_ascii_case(pk))
                        {
                            out.push(der.clone());
                        } else {
                            tracing::debug!(
                                "Migration: CRK pubkey {pk} for peer {} has no \
                                 matching aliceAddresses entry in session {address}; \
                                 storing address-only (no secret_key/ratchet_key).",
                                ctx.peer_nostr_pubkey
                            );
                            out.push(DerivedAddressSerialized {
                                address: pk.clone(),
                                secret_key: String::new(),
                                ratchet_key: String::new(),
                            });
                        }
                    }
                    tracing::info!(
                        "Migration: peer_addresses.receiving_addresses for {address} \
                         populated via DIRECT-COPY from v1 ContactReceiveKey \
                         ({} entries)",
                        out.len()
                    );
                    out
                }
                _ => {
                    // FALLBACK: derive from aliceAddresses (byte-identical to what
                    // v1 Flutter would compute on-demand via
                    // generate_seed_from_ratchetkey_pair).
                    let out: Vec<_> = alice_derived
                        .iter()
                        .map(|(_, d)| d.clone())
                        .collect();
                    tracing::info!(
                        "Migration: peer_addresses.receiving_addresses for {address} \
                         populated via FALLBACK derivation from session.aliceAddresses \
                         ({} entries) — no v1 ContactReceiveKey row found for \
                         (identity={}, peer={})",
                        out.len(),
                        ctx.identity_pubkey,
                        ctx.peer_nostr_pubkey
                    );
                    out
                }
            };

            // v1's `session.bobAddress` is `"{priv}-{pub}"`, not `"{address}-{pub}"`.
            // Re-derive to produce the actual x-only pubkey we tag sends with.
            let sending_address = if bob_address_raw.trim().is_empty() {
                None
            } else {
                match derive_address_with_secret(bob_address_raw.trim()) {
                    Ok(d) => Some(d.address),
                    Err(e) => {
                        tracing::warn!(
                            "Migration: skipping malformed v1 bobAddress for {address}: {e}"
                        );
                        None
                    }
                }
            };

            let addr_state = PeerAddressStateSerialized {
                receiving_addresses,
                sending_address,
                peer_first_inbox: None,
                peer_nostr_pubkey: Some(ctx.peer_nostr_pubkey.clone()),
            };

            let recv_count = addr_state.receiving_addresses.len();
            let addr_state_json = match serde_json::to_string(&addr_state) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "Migration: peer_addresses serialize failed for {address}: {e}; \
                         falling back to empty state"
                    );
                    format!(
                        "{{\"receiving_addresses\":[],\
                           \"sending_address\":null,\
                           \"peer_first_inbox\":null,\
                           \"peer_nostr_pubkey\":\"{}\"}}",
                        ctx.peer_nostr_pubkey
                    )
                }
            };
            if let Err(e) = protocol_conn.execute(
                "INSERT OR REPLACE INTO peer_addresses \
                 (peer_signal_id, state_json, updated_at) \
                 VALUES (?1, ?2, ?3)",
                params![address, addr_state_json, now],
            ) {
                tracing::warn!("Migration: peer_addresses insert failed for {address}: {e}");
            } else {
                tracing::info!(
                    "Migration: peer_addresses restored for {address}: \
                     receiving_addresses={}, sending_address={}",
                    recv_count,
                    addr_state.sending_address.is_some()
                );
            }

            count += 1;
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
