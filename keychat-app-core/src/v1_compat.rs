//! v1 protocol compatibility layer.
//!
//! Provides transparent interoperability between v1 and v2 Keychat clients.
//! This module is designed to be **fully removable** once all users upgrade to v2.
//!
//! ## What it does
//!
//! 1. **clientv tag** — Every outgoing Nostr event gets `["clientv", "2"]` tag.
//!    Incoming events with this tag mark the peer as v2 (Room.peer_version = 2).
//!
//! 2. **kind:4 transport** — v1 Signal messages use kind:4 + NIP-04.
//!    v2 uses kind:1059. This layer handles both directions.
//!
//! 3. **Message format conversion** — v1 JSON `{"c":"signal","type":100,"msg":"..."}`
//!    ↔ v2 JSON `{"v":2,"kind":"text","text":{"content":"..."}}`.
//!
//! 4. **Friend Request field mapping** — v1 field names (pubkey, curve25519PkHex,
//!    onetimekey) ↔ v2 field names (nostrIdentityKey, signalIdentityKey, firstInbox).

use libkeychat::message::{KCMessage, KCMessageKind, KCTextPayload};
use libkeychat::error::{KeychatError, Result};
use serde::{Deserialize, Serialize};

// ─── clientv tag ────────────────────────────────────────────────────────────

/// Tag name for client protocol version.
pub const CLIENTV_TAG: &str = "clientv";

/// Current client version value.
pub const CLIENTV_VALUE: &str = "2";

/// Check whether a Nostr event carries `["clientv", "2"]` or higher.
pub fn is_v2_event(event: &nostr::Event) -> bool {
    for tag in event.tags.iter() {
        let items: Vec<&str> = tag.as_slice().iter().map(|s| s.as_str()).collect();
        if items.len() >= 2 && items[0] == CLIENTV_TAG {
            if let Ok(v) = items[1].parse::<u32>() {
                return v >= 2;
            }
        }
    }
    false
}

/// Build a clientv tag for inclusion in outgoing events.
pub fn clientv_tag() -> nostr::Tag {
    nostr::Tag::custom(
        nostr::TagKind::custom(CLIENTV_TAG),
        [CLIENTV_VALUE],
    )
}

// ─── v1 message format ─────────────────────────────────────────────────────

/// v1 message envelope.
///
/// ```json
/// {"c": "signal", "type": 100, "msg": "hello", "name": null, "data": null}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1Message {
    /// Category: "signal", "nip04", "group", "mls", "kdfGroup"
    pub c: String,
    /// Message type number (see V1MessageType constants)
    #[serde(rename = "type")]
    pub msg_type: u32,
    /// Message content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// Auxiliary data (prekey bundle for FR, reply info for DM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Extra data field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// v1 message type constants (from keychat-app constants.dart).
pub mod v1_types {
    pub const DM: u32 = 100;
    pub const ADD_CONTACT_FROM_ALICE: u32 = 101; // friend request
    pub const ADD_CONTACT_FROM_BOB: u32 = 102;   // friend approve
    pub const DELETE_HISTORY: u32 = 103;
    pub const REJECT: u32 = 104;                 // friend reject

    // Signal group operations
    pub const GROUP_INVITE: u32 = 11;
    pub const GROUP_SHARED_KEY: u32 = 12;
    pub const GROUP_HI: u32 = 14;
    pub const GROUP_CHANGE_NICKNAME: u32 = 15;
    pub const GROUP_SELF_LEAVE: u32 = 16;
    pub const GROUP_DISSOLVE: u32 = 17;
    pub const GROUP_SYNC_MEMBERS: u32 = 18;
    pub const GROUP_CHANGE_ROOM_NAME: u32 = 20;
    pub const GROUP_SEND_TO_ALL: u32 = 30;
    pub const GROUP_REMOVE_MEMBER: u32 = 31;
    pub const GROUP_REMOVE_SINGLE_MEMBER: u32 = 32;
    pub const GROUP_SELF_LEAVE_CONFIRM: u32 = 33;

    // Signal session
    pub const SIGNAL_INVITE: u32 = 41;
    pub const SIGNAL_INVITE_REPLY: u32 = 42;
    pub const SIGNAL_RELAY_SYNC_INVITE: u32 = 45;
    pub const SIGNAL_SEND_PROFILE: u32 = 48;

    // WebRTC
    pub const WEBRTC_VIDEO_CALL: u32 = 2001;
    pub const WEBRTC_AUDIO_CALL: u32 = 2002;
    pub const WEBRTC_SIGNALING: u32 = 2003;
    pub const WEBRTC_CANCEL: u32 = 2004;
    pub const WEBRTC_REJECT: u32 = 2005;
    pub const WEBRTC_END: u32 = 2006;
}

// ─── Message format conversion ─────────────────────────────────────────────

/// Parse a decrypted plaintext message, auto-detecting v1 or v2 format.
///
/// This is called after Signal decryption, before application logic.
pub fn parse_decrypted_message(plaintext: &str) -> Result<KCMessage> {
    // Try v2 first
    if let Ok(msg) = serde_json::from_str::<KCMessage>(plaintext) {
        if msg.v >= 2 {
            return Ok(msg);
        }
    }

    // Try v1
    if let Ok(v1) = serde_json::from_str::<V1Message>(plaintext) {
        return v1_to_v2(&v1);
    }

    // Fallback: treat as plain text
    Ok(KCMessage::text(plaintext.to_string()))
}

/// Convert a v1 message to v2 internal representation.
pub fn v1_to_v2(v1: &V1Message) -> Result<KCMessage> {
    match v1.msg_type {
        v1_types::DM => {
            Ok(KCMessage::text(v1.msg.clone().unwrap_or_default()))
        }
        v1_types::ADD_CONTACT_FROM_ALICE => {
            // FR payload is in the `name` field as JSON string
            // We pass it through as-is; the FR handler will parse v1 field names
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::FriendRequest;
            // Store the raw v1 FR payload in extra for downstream processing
            if let Some(name_data) = &v1.name {
                msg.extra.insert("v1_fr_payload".to_string(), 
                    serde_json::Value::String(name_data.clone()));
            }
            Ok(msg)
        }
        v1_types::ADD_CONTACT_FROM_BOB => {
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::FriendApprove;
            Ok(msg)
        }
        v1_types::REJECT => {
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::FriendReject;
            Ok(msg)
        }
        v1_types::GROUP_INVITE => {
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::SignalGroupInvite;
            if let Some(data) = &v1.data {
                msg.extra.insert("v1_group_data".to_string(),
                    serde_json::Value::String(data.clone()));
            }
            Ok(msg)
        }
        v1_types::GROUP_SELF_LEAVE => {
            let mut msg = KCMessage::text(String::new());
            msg.kind = KCMessageKind::SignalGroupSelfLeave;
            Ok(msg)
        }
        v1_types::GROUP_DISSOLVE => {
            let mut msg = KCMessage::text(String::new());
            msg.kind = KCMessageKind::SignalGroupDissolve;
            Ok(msg)
        }
        v1_types::GROUP_REMOVE_MEMBER | v1_types::GROUP_REMOVE_SINGLE_MEMBER => {
            let mut msg = KCMessage::text(String::new());
            msg.kind = KCMessageKind::SignalGroupMemberRemoved;
            Ok(msg)
        }
        v1_types::GROUP_CHANGE_ROOM_NAME => {
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::SignalGroupNameChanged;
            Ok(msg)
        }
        v1_types::GROUP_CHANGE_NICKNAME => {
            let mut msg = KCMessage::text(v1.msg.clone().unwrap_or_default());
            msg.kind = KCMessageKind::SignalGroupNicknameChanged;
            Ok(msg)
        }
        v1_types::GROUP_SEND_TO_ALL => {
            // Group text message — treat as text
            Ok(KCMessage::text(v1.msg.clone().unwrap_or_default()))
        }
        v1_types::SIGNAL_SEND_PROFILE => {
            let mut msg = KCMessage::text(String::new());
            msg.kind = KCMessageKind::ProfileSync;
            if let Some(data) = &v1.msg {
                msg.extra.insert("v1_profile_data".to_string(),
                    serde_json::Value::String(data.clone()));
            }
            Ok(msg)
        }
        v1_types::DELETE_HISTORY => {
            let mut msg = KCMessage::text(String::new());
            msg.kind = KCMessageKind::MessageDelete;
            Ok(msg)
        }
        _ => {
            // Unknown v1 type — preserve as text with metadata
            let content = v1.msg.clone().unwrap_or_else(|| 
                format!("[v1 message type {}]", v1.msg_type)
            );
            let mut msg = KCMessage::text(content);
            msg.extra.insert("v1_type".to_string(), 
                serde_json::Value::Number(v1.msg_type.into()));
            Ok(msg)
        }
    }
}

/// Convert a v2 KCMessage to v1 format for sending to v1 peers.
pub fn v2_to_v1(msg: &KCMessage) -> Result<String> {
    let v1 = match &msg.kind {
        KCMessageKind::Text => {
            let content = msg.text.as_ref()
                .map(|t| t.content.clone())
                .unwrap_or_default();
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::DM,
                msg: Some(content),
                name: None,
                data: None,
            }
        }
        KCMessageKind::FriendRequest => {
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::ADD_CONTACT_FROM_ALICE,
                msg: msg.text.as_ref().map(|t| t.content.clone()),
                name: None, // FR payload handled separately by the send path
                data: None,
            }
        }
        KCMessageKind::FriendApprove => {
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::ADD_CONTACT_FROM_BOB,
                msg: None,
                name: None,
                data: None,
            }
        }
        KCMessageKind::FriendReject => {
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::REJECT,
                msg: None,
                name: None,
                data: None,
            }
        }
        KCMessageKind::SignalGroupInvite => {
            V1Message {
                c: "group".to_string(),
                msg_type: v1_types::GROUP_INVITE,
                msg: msg.text.as_ref().map(|t| t.content.clone()),
                name: None,
                data: None,
            }
        }
        KCMessageKind::SignalGroupSelfLeave => {
            V1Message {
                c: "group".to_string(),
                msg_type: v1_types::GROUP_SELF_LEAVE,
                msg: None, name: None, data: None,
            }
        }
        KCMessageKind::SignalGroupDissolve => {
            V1Message {
                c: "group".to_string(),
                msg_type: v1_types::GROUP_DISSOLVE,
                msg: None, name: None, data: None,
            }
        }
        KCMessageKind::SignalGroupMemberRemoved => {
            V1Message {
                c: "group".to_string(),
                msg_type: v1_types::GROUP_REMOVE_MEMBER,
                msg: msg.text.as_ref().map(|t| t.content.clone()),
                name: None, data: None,
            }
        }
        KCMessageKind::SignalGroupNameChanged => {
            V1Message {
                c: "group".to_string(),
                msg_type: v1_types::GROUP_CHANGE_ROOM_NAME,
                msg: msg.text.as_ref().map(|t| t.content.clone()),
                name: None, data: None,
            }
        }
        KCMessageKind::ProfileSync => {
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::SIGNAL_SEND_PROFILE,
                msg: msg.text.as_ref().map(|t| t.content.clone()),
                name: None, data: None,
            }
        }
        _ => {
            // For v2-only kinds, send as text with fallback
            let content = msg.fallback.clone()
                .or_else(|| msg.text.as_ref().map(|t| t.content.clone()))
                .unwrap_or_else(|| "[Message requires newer Keychat version]".to_string());
            V1Message {
                c: "signal".to_string(),
                msg_type: v1_types::DM,
                msg: Some(content),
                name: None,
                data: None,
            }
        }
    };

    serde_json::to_string(&v1)
        .map_err(|e| KeychatError::Serialization(e))
}

// ─── Friend Request field mapping ───────────────────────────────────────────

/// v1 Friend Request payload (QRUserModel in v1 app).
///
/// Embedded in the `name` field of a v1 KeychatMessage with type 101.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct V1FriendRequestPayload {
    pub name: Option<String>,
    pub pubkey: String,
    #[serde(alias = "curve25519PkHex")]
    pub curve25519_pk_hex: String,
    pub onetimekey: String,
    #[serde(default)]
    pub time: u64,
    #[serde(default)]
    pub relay: String,
    #[serde(default)]
    pub lightning: String,
    #[serde(default)]
    pub avatar: String,
    #[serde(default)]
    pub global_sign: String,
    // Signal prekey fields (from userInfo in v1)
    #[serde(alias = "prekeyId")]
    pub prekey_id: Option<u32>,
    #[serde(alias = "prekeyPubkey")]
    pub prekey_pubkey: Option<String>,
    #[serde(alias = "signedPrekeyId")]
    pub signed_prekey_id: Option<u32>,
    #[serde(alias = "signedPrekeyPubkey")]
    pub signed_prekey_pubkey: Option<String>,
    #[serde(alias = "signedPrekeySignature")]
    pub signed_prekey_signature: Option<String>,
}

/// Convert v1 FR payload field names to v2 field names.
///
/// Returns a JSON object with v2 field names that can be used by
/// libkeychat's friend_request module.
pub fn v1_fr_to_v2_fields(v1: &V1FriendRequestPayload) -> serde_json::Value {
    serde_json::json!({
        "nostrIdentityKey": v1.pubkey,
        "signalIdentityKey": v1.curve25519_pk_hex,
        "firstInbox": v1.onetimekey,
        "signalOneTimePrekeyId": v1.prekey_id,
        "signalOneTimePrekey": v1.prekey_pubkey,
        "signalSignedPrekeyId": v1.signed_prekey_id,
        "signalSignedPrekey": v1.signed_prekey_pubkey,
        "signalSignedPrekeySignature": v1.signed_prekey_signature,
        "name": v1.name,
        "time": v1.time,
        "globalSign": v1.global_sign,
        "relay": v1.relay,
        "avatar": v1.avatar,
        "lightning": v1.lightning,
        // No Kyber fields — v1 doesn't have them → X3DH fallback
    })
}

/// Convert v2 FR payload to v1 field names for sending to v1 peers.
pub fn v2_fr_to_v1_fields(v2_json: &serde_json::Value) -> V1FriendRequestPayload {
    V1FriendRequestPayload {
        name: v2_json.get("name").and_then(|v| v.as_str()).map(String::from),
        pubkey: v2_json.get("nostrIdentityKey")
            .and_then(|v| v.as_str()).unwrap_or("").to_string(),
        curve25519_pk_hex: v2_json.get("signalIdentityKey")
            .and_then(|v| v.as_str()).unwrap_or("").to_string(),
        onetimekey: v2_json.get("firstInbox")
            .and_then(|v| v.as_str()).unwrap_or("").to_string(),
        time: v2_json.get("time").and_then(|v| v.as_u64()).unwrap_or(0),
        relay: v2_json.get("relay").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        lightning: v2_json.get("lightning").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        avatar: v2_json.get("avatar").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        global_sign: v2_json.get("globalSign").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        prekey_id: v2_json.get("signalOneTimePrekeyId").and_then(|v| v.as_u64()).map(|v| v as u32),
        prekey_pubkey: v2_json.get("signalOneTimePrekey").and_then(|v| v.as_str()).map(String::from),
        signed_prekey_id: v2_json.get("signalSignedPrekeyId").and_then(|v| v.as_u64()).map(|v| v as u32),
        signed_prekey_pubkey: v2_json.get("signalSignedPrekey").and_then(|v| v.as_str()).map(String::from),
        signed_prekey_signature: v2_json.get("signalSignedPrekeySignature").and_then(|v| v.as_str()).map(String::from),
    }
}

// ─── Peer version routing ───────────────────────────────────────────────────

/// Determines the message format and transport kind for a given peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerProtocol {
    /// v1: kind:4 + NIP-04 + v1 JSON format
    V1,
    /// v2: kind:1059 + v2 JSON format
    V2,
}

impl PeerProtocol {
    pub fn from_peer_version(peer_version: Option<u32>) -> Self {
        match peer_version {
            Some(v) if v >= 2 => PeerProtocol::V2,
            _ => PeerProtocol::V1,
        }
    }

    pub fn nostr_kind(&self) -> nostr::Kind {
        match self {
            PeerProtocol::V1 => nostr::Kind::from(4),
            PeerProtocol::V2 => nostr::Kind::from(1059),
        }
    }
}

/// Serialize a KCMessage for the appropriate peer protocol.
pub fn serialize_for_peer(msg: &KCMessage, protocol: PeerProtocol) -> Result<String> {
    match protocol {
        PeerProtocol::V2 => {
            serde_json::to_string(msg)
                .map_err(|e| KeychatError::Serialization(e))
        }
        PeerProtocol::V1 => {
            v2_to_v1(msg)
        }
    }
}

// ─── V1 RoomMember (Isar export) ────────────────────────────────────────────

/// Represents a room member record from the v1 Isar database.
///
/// Used during migration to import group membership data.
#[derive(Debug, Clone)]
pub struct V1RoomMember {
    /// Nostr secp256k1 public key hex of the member.
    pub id_pubkey: String,
    /// Isar room id (integer, mapped to new string id via room_id_map).
    pub room_id: i64,
    pub name: Option<String>,
    pub is_admin: bool,
    /// 0 = inviting, 1 = invited, 2 = blocked, 3 = removed.
    pub status: i32,
    pub created_at: Option<i64>,
}

/// Parse a single `V1RoomMember` from a JSON value (Isar export row).
///
/// Returns `None` if required fields are missing or empty.
pub fn parse_v1_room_member(json: &serde_json::Value) -> Option<V1RoomMember> {
    let id_pubkey = json.get("idPubkey")?.as_str()?.to_string();
    if id_pubkey.is_empty() {
        return None;
    }
    let room_id = json.get("roomId")?.as_i64()?;
    let name = json.get("name").and_then(|v| v.as_str()).map(String::from);
    let is_admin = json.get("isAdmin").and_then(|v| v.as_bool()).unwrap_or(false);
    let status = json.get("status").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let created_at = json.get("createdAt").and_then(|v| v.as_i64());

    Some(V1RoomMember {
        id_pubkey,
        room_id,
        name,
        is_admin,
        status,
        created_at,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1_text_message() {
        let v1_json = r#"{"c":"signal","type":100,"msg":"hello world"}"#;
        let msg = parse_decrypted_message(v1_json).unwrap();
        assert_eq!(msg.kind, KCMessageKind::Text);
        assert_eq!(msg.text.unwrap().content, "hello world");
    }

    #[test]
    fn parse_v2_text_message() {
        let v2_json = r#"{"v":2,"kind":"text","text":{"content":"hello v2"}}"#;
        let msg = parse_decrypted_message(v2_json).unwrap();
        assert_eq!(msg.v, 2);
        assert_eq!(msg.kind, KCMessageKind::Text);
        assert_eq!(msg.text.unwrap().content, "hello v2");
    }

    #[test]
    fn v1_dm_roundtrip() {
        let v1_json = r#"{"c":"signal","type":100,"msg":"test"}"#;
        let msg = parse_decrypted_message(v1_json).unwrap();
        let back = v2_to_v1(&msg).unwrap();
        let v1_back: V1Message = serde_json::from_str(&back).unwrap();
        assert_eq!(v1_back.msg_type, 100);
        assert_eq!(v1_back.msg.unwrap(), "test");
        assert_eq!(v1_back.c, "signal");
    }

    #[test]
    fn v1_friend_request_detected() {
        let v1_json = r#"{"c":"signal","type":101,"msg":"Hi, let's chat","name":"{\"pubkey\":\"abc\",\"curve25519PkHex\":\"def\"}"}"#;
        let msg = parse_decrypted_message(v1_json).unwrap();
        assert_eq!(msg.kind, KCMessageKind::FriendRequest);
    }

    #[test]
    fn unknown_v1_type_fallback() {
        let v1_json = r#"{"c":"signal","type":9999,"msg":"future feature"}"#;
        let msg = parse_decrypted_message(v1_json).unwrap();
        assert_eq!(msg.kind, KCMessageKind::Text);
        assert_eq!(msg.text.unwrap().content, "future feature");
    }

    #[test]
    fn peer_protocol_routing() {
        assert_eq!(PeerProtocol::from_peer_version(None), PeerProtocol::V1);
        assert_eq!(PeerProtocol::from_peer_version(Some(1)), PeerProtocol::V1);
        assert_eq!(PeerProtocol::from_peer_version(Some(2)), PeerProtocol::V2);
        assert_eq!(PeerProtocol::from_peer_version(Some(3)), PeerProtocol::V2);
    }

    #[test]
    fn v1_fr_field_mapping() {
        let v1_fr = V1FriendRequestPayload {
            name: Some("Alice".into()),
            pubkey: "nostr_pub_hex".into(),
            curve25519_pk_hex: "signal_pub_hex".into(),
            onetimekey: "first_inbox_hex".into(),
            time: 1700000000,
            relay: "".into(),
            lightning: "".into(),
            avatar: "".into(),
            global_sign: "sig_hex".into(),
            prekey_id: Some(1),
            prekey_pubkey: Some("prekey_hex".into()),
            signed_prekey_id: Some(1),
            signed_prekey_pubkey: Some("spk_hex".into()),
            signed_prekey_signature: Some("spk_sig_hex".into()),
        };
        let v2 = v1_fr_to_v2_fields(&v1_fr);
        assert_eq!(v2["nostrIdentityKey"], "nostr_pub_hex");
        assert_eq!(v2["signalIdentityKey"], "signal_pub_hex");
        assert_eq!(v2["firstInbox"], "first_inbox_hex");
        assert!(v2.get("signalKyberPrekeyId").is_none());
    }

    #[test]
    fn parse_room_member_valid() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"idPubkey":"abc123","roomId":42,"name":"Alice","isAdmin":true,"status":1,"createdAt":1700000000}"#,
        ).unwrap();
        let m = parse_v1_room_member(&json).unwrap();
        assert_eq!(m.id_pubkey, "abc123");
        assert_eq!(m.room_id, 42);
        assert_eq!(m.name.as_deref(), Some("Alice"));
        assert!(m.is_admin);
        assert_eq!(m.status, 1);
        assert_eq!(m.created_at, Some(1700000000));
    }

    #[test]
    fn parse_room_member_missing_pubkey() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"roomId":42,"status":1}"#,
        ).unwrap();
        assert!(parse_v1_room_member(&json).is_none());
    }

    #[test]
    fn parse_room_member_empty_pubkey() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"idPubkey":"","roomId":42}"#,
        ).unwrap();
        assert!(parse_v1_room_member(&json).is_none());
    }
}
