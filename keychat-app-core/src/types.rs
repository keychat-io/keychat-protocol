//! App-layer types shared by all UI clients (Swift, Kotlin, CLI).
//!
//! These are plain Rust types without UniFFI annotations.
//! The `keychat-uniffi` crate re-exports them with `#[uniffi::Enum]`/`#[uniffi::Record]`.

/// Build a composite room ID from peer pubkey and identity pubkey.
pub fn make_room_id(peer_pubkey: &str, identity_pubkey: &str) -> String {
    format!("{}:{}", peer_pubkey, identity_pubkey)
}

// ─── Status Enums ───────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoomStatus {
    Requesting,  // 0
    Enabled,     // 1
    Approving,   // 2
    Rejected,    // -1
}

impl RoomStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => RoomStatus::Requesting,
            1 => RoomStatus::Enabled,
            2 => RoomStatus::Approving,
            -1 => RoomStatus::Rejected,
            _ => RoomStatus::Requesting,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            RoomStatus::Requesting => 0,
            RoomStatus::Enabled => 1,
            RoomStatus::Approving => 2,
            RoomStatus::Rejected => -1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoomType {
    Dm,           // 0 — Signal-encrypted 1:1 DM
    SignalGroup,  // 1
    MlsGroup,    // 2
    Nip17Dm,     // 3 — Standard NIP-17 DM (no Signal session, NIP-44 only)
}

impl RoomType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => RoomType::Dm,
            1 => RoomType::SignalGroup,
            2 => RoomType::MlsGroup,
            3 => RoomType::Nip17Dm,
            _ => RoomType::Dm,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            RoomType::Dm => 0,
            RoomType::SignalGroup => 1,
            RoomType::MlsGroup => 2,
            RoomType::Nip17Dm => 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageStatus {
    Sending,   // 0
    Success,   // 1
    Failed,    // 2
}

impl MessageStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => MessageStatus::Sending,
            1 => MessageStatus::Success,
            2 => MessageStatus::Failed,
            _ => MessageStatus::Sending,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            MessageStatus::Sending => 0,
            MessageStatus::Success => 1,
            MessageStatus::Failed => 2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

// ─── App Data Query Types ────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct IdentityInfo {
    pub npub: String,
    pub nostr_pubkey_hex: String,
    pub name: String,
    pub avatar: Option<String>,
    pub idx: i32,
    pub is_default: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct RoomInfo {
    pub id: String,
    pub to_main_pubkey: String,
    pub identity_pubkey: String,
    pub status: RoomStatus,
    pub room_type: RoomType,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub peer_signal_identity_key: Option<String>,
    pub parent_room_id: Option<String>,
    pub last_message_content: Option<String>,
    pub last_message_at: Option<i64>,
    pub unread_count: i32,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct MessageInfo {
    pub msgid: String,
    pub event_id: Option<String>,
    pub room_id: String,
    pub identity_pubkey: String,
    pub sender_pubkey: String,
    pub content: String,
    pub is_me_send: bool,
    pub is_read: bool,
    pub status: MessageStatus,
    pub reply_to_event_id: Option<String>,
    pub reply_to_content: Option<String>,
    pub payload_json: Option<String>,
    pub nostr_event_json: Option<String>,
    pub relay_status_json: Option<String>,
    pub local_file_path: Option<String>,
    pub local_meta: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct ContactInfoFull {
    pub pubkey: String,
    pub npubkey: String,
    pub identity_pubkey: String,
    pub petname: Option<String>,
    pub name: Option<String>,
    pub avatar: Option<String>,
}

// ─── Data Change Notifications ──────────────────────────────────

#[derive(Clone, Debug)]
pub enum DataChange {
    RoomUpdated { room_id: String },
    RoomDeleted { room_id: String },
    RoomListChanged,
    MessageAdded { room_id: String, msgid: String },
    MessageUpdated { room_id: String, msgid: String },
    ContactUpdated { pubkey: String },
    ContactListChanged,
    IdentityListChanged,
    ConnectionStatusChanged { status: ConnectionStatus, message: Option<String> },
}

/// Listener for data change notifications (implemented by UI layer).
pub trait DataListener: Send + Sync {
    fn on_data_change(&self, change: DataChange);
}
