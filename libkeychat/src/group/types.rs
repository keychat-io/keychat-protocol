use serde::{Deserialize, Serialize};

/// Signal-based small group type.
/// Currently only `SendAll` is supported (fan-out encryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupType {
    /// Each message is encrypted per-member using their Signal session.
    SendAll,
}

/// A member of a Signal-based small group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's Nostr secp256k1 pubkey hex.
    pub pubkey: String,
    /// Display name.
    pub name: String,
    /// Whether this member is the group admin.
    pub is_admin: bool,
}

/// Group profile — the payload sent in invite messages.
/// Matches Keychat app's `RoomProfile` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupProfile {
    /// Group's Nostr pubkey (random, serves as group ID).
    pub pubkey: String,
    /// Group display name.
    pub name: String,
    /// List of member pubkeys (may include names as values).
    pub users: Vec<serde_json::Value>,
    /// Group type identifier.
    pub group_type: GroupTypeWire,
    /// Last update timestamp (milliseconds since epoch).
    pub updated_at: i64,
    /// Group relay URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_relay: Option<String>,
    /// Permanent group identifier. Keychat app uses this as the unique room key.
    /// Wire name is `oldToRoomPubKey` for Keychat app compatibility.
    #[serde(rename = "oldToRoomPubKey", skip_serializing_if = "Option::is_none")]
    pub small_group_id: Option<String>,
}

impl GroupProfile {
    /// Add a member to the group profile.
    pub fn add_member(&mut self, id_pubkey: &str, name: &str, is_admin: bool) {
        self.users.push(serde_json::json!({
            "idPubkey": id_pubkey,
            "name": name,
            "isAdmin": is_admin,
        }));
    }
}

/// Wire format for group type (matches Keychat app enum serialization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupTypeWire {
    #[serde(rename = "sendAll")]
    SendAll,
    #[serde(rename = "mls")]
    Mls,
    #[serde(rename = "shareKey")]
    ShareKey,
    #[serde(rename = "kdf")]
    Kdf,
    #[serde(rename = "common")]
    Common,
}

/// KeychatMessage subtypes for group operations.
/// Matches `KeyChatEventKinds` constants from Keychat app.
pub mod event_kinds {
    /// Group invite (type 11).
    pub const GROUP_INVITE: i32 = 11;
    /// Change nickname (type 15).
    pub const GROUP_CHANGE_NICKNAME: i32 = 15;
    /// Dissolve group (type 17).
    pub const GROUP_DISSOLVE: i32 = 17;
    /// Change room name (type 20).
    pub const GROUP_CHANGE_ROOM_NAME: i32 = 20;
    /// Send message to all members (type 30).
    pub const GROUP_SEND_TO_ALL: i32 = 30;
    /// Remove a member (type 31).
    pub const GROUP_REMOVE_MEMBER: i32 = 31;
}

/// A group message (inner content of KeychatMessage with c="group").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    /// The Nostr pubkey of the sender.
    pub sender: String,
    /// The plaintext content.
    pub content: String,
    /// The group pubkey this message belongs to.
    pub group_pubkey: String,
    /// Message subtype (event kind).
    pub subtype: i32,
    /// Optional extra data (e.g., new name for rename).
    pub ext: Option<String>,
}

/// Result of creating a group.
pub struct CreateGroupResult {
    /// The group profile (to be sent as invite).
    pub profile: GroupProfile,
    /// The group's secret key (hex) — only admin keeps this.
    pub group_secret_key: String,
}

/// Processed inbound group event.
#[derive(Debug, Clone)]
pub enum GroupEvent {
    /// Regular chat message.
    Message {
        sender: String,
        content: String,
        group_pubkey: String,
    },
    /// Group invite received.
    Invite {
        profile: GroupProfile,
        inviter: String,
    },
    /// Member removed.
    MemberRemoved {
        member_pubkey: String,
        by: String,
        group_pubkey: String,
    },
    /// Group dissolved by admin.
    Dissolved { by: String, group_pubkey: String },
    /// Room name changed.
    RoomNameChanged {
        new_name: String,
        by: String,
        group_pubkey: String,
    },
    /// Nickname changed.
    NicknameChanged {
        new_name: String,
        by: String,
        group_pubkey: String,
    },
}
