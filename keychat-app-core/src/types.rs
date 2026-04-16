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
    Requesting, // 0
    Enabled,    // 1
    Approving,  // 2
    Rejected,   // -1
    Archived,   // 3
}

impl RoomStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => RoomStatus::Requesting,
            1 => RoomStatus::Enabled,
            2 => RoomStatus::Approving,
            3 => RoomStatus::Archived,
            -1 => RoomStatus::Rejected,
            _ => RoomStatus::Requesting,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            RoomStatus::Requesting => 0,
            RoomStatus::Enabled => 1,
            RoomStatus::Approving => 2,
            RoomStatus::Archived => 3,
            RoomStatus::Rejected => -1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberStatus {
    Inviting,     // 0
    Invited,      // 1 — normal/active
    Blocked,      // 2
    Removed,      // 3
    InviteFailed, // 4 — KeyPackage fetch or send failed; eligible for retry
}

impl MemberStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => MemberStatus::Inviting,
            1 => MemberStatus::Invited,
            2 => MemberStatus::Blocked,
            3 => MemberStatus::Removed,
            4 => MemberStatus::InviteFailed,
            _ => MemberStatus::Inviting,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            MemberStatus::Inviting => 0,
            MemberStatus::Invited => 1,
            MemberStatus::Blocked => 2,
            MemberStatus::Removed => 3,
            MemberStatus::InviteFailed => 4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoomType {
    Dm,          // 0 — Signal-encrypted 1:1 DM
    SignalGroup, // 1
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
    Sending, // 0
    Success, // 1
    Failed,  // 2
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
// Note: Timestamps use i64 (from SQLite). The UniFFI layer converts to u64 for Swift/Kotlin.

#[derive(Clone, Debug)]
pub struct IdentityInfo {
    pub npub: String,
    pub nostr_pubkey_hex: String,
    pub name: String,
    pub avatar: Option<String>,
    pub index: i32,
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
    /// Peer's client protocol version: None/1 = v1, 2 = v2.
    pub peer_version: Option<i32>,
    /// Session key agreement type: "x3dh" or "pqxdh".
    pub session_type: Option<String>,
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

// ─── Room Member Info ───────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RoomMemberInfo {
    pub id: i64,
    pub room_id: String,
    pub pubkey: String,
    pub name: Option<String>,
    pub is_admin: bool,
    pub status: MemberStatus,
    pub created_at: i64,
}

// ─── Data Change Notifications ──────────────────────────────────

#[derive(Clone, Debug)]
pub enum DataChange {
    RoomUpdated {
        room_id: String,
    },
    RoomDeleted {
        room_id: String,
    },
    RoomListChanged,
    MessageAdded {
        room_id: String,
        msgid: String,
    },
    MessageUpdated {
        room_id: String,
        msgid: String,
    },
    ContactUpdated {
        pubkey: String,
    },
    ContactListChanged,
    IdentityListChanged,
    ConnectionStatusChanged {
        status: ConnectionStatus,
        message: Option<String>,
    },
}

/// Listener for data change notifications (implemented by UI layer).
pub trait DataListener: Send + Sync {
    fn on_data_change(&self, change: DataChange);
}

// ─── Event Types ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum MessageKind {
    Text,
    Files,
    Cashu,
    LightningInvoice,
    FriendRequest,
    FriendApprove,
    FriendReject,
    ProfileSync,
    RelaySyncInvite,
    SignalGroupInvite,
    SignalGroupMemberRemoved,
    SignalGroupSelfLeave,
    SignalGroupDissolve,
    SignalGroupNameChanged,
    SignalGroupNicknameChanged,
    MlsGroupInvite,
    AgentActions,
    AgentOptions,
    AgentConfirm,
    AgentReply,
    TaskRequest,
    TaskResponse,
    SkillQuery,
    SkillDeclare,
    EventNotify,
    StreamChunk,
    Location,
    Contact,
    Sticker,
    Reaction,
    MessageDelete,
    MessageEdit,
    ReadReceipt,
    Typing,
    Poll,
    PollVote,
    CallSignal,
    GroupPinMessage,
    GroupAnnouncement,
}

impl From<libkeychat::KCMessageKind> for MessageKind {
    fn from(k: libkeychat::KCMessageKind) -> Self {
        match k {
            libkeychat::KCMessageKind::Text => MessageKind::Text,
            libkeychat::KCMessageKind::Files => MessageKind::Files,
            libkeychat::KCMessageKind::Cashu => MessageKind::Cashu,
            libkeychat::KCMessageKind::LightningInvoice => MessageKind::LightningInvoice,
            libkeychat::KCMessageKind::FriendRequest => MessageKind::FriendRequest,
            libkeychat::KCMessageKind::FriendApprove => MessageKind::FriendApprove,
            libkeychat::KCMessageKind::FriendReject => MessageKind::FriendReject,
            libkeychat::KCMessageKind::SignalGroupInvite => MessageKind::SignalGroupInvite,
            libkeychat::KCMessageKind::SignalGroupMemberRemoved => {
                MessageKind::SignalGroupMemberRemoved
            }
            libkeychat::KCMessageKind::SignalGroupSelfLeave => MessageKind::SignalGroupSelfLeave,
            libkeychat::KCMessageKind::SignalGroupDissolve => MessageKind::SignalGroupDissolve,
            libkeychat::KCMessageKind::SignalGroupNameChanged => {
                MessageKind::SignalGroupNameChanged
            }
            libkeychat::KCMessageKind::MlsGroupInvite => MessageKind::MlsGroupInvite,
            libkeychat::KCMessageKind::AgentReply => MessageKind::AgentReply,
            _ => MessageKind::Text,
        }
    }
}

#[derive(Clone, Debug)]
pub enum GroupChangeKind {
    MemberRemoved,
    SelfLeave,
    NameChanged,
}

#[derive(Clone, Debug)]
pub enum ClientEvent {
    FriendRequestReceived {
        request_id: String,
        sender_pubkey: String,
        sender_name: String,
        message: Option<String>,
        created_at: u64,
    },
    FriendRequestAccepted {
        peer_pubkey: String,
        peer_name: String,
    },
    FriendRequestRejected {
        peer_pubkey: String,
    },
    MessageReceived {
        room_id: String,
        sender_pubkey: String,
        kind: MessageKind,
        content: Option<String>,
        payload: Option<String>,
        event_id: String,
        fallback: Option<String>,
        reply_to_event_id: Option<String>,
        group_id: Option<String>,
        thread_id: Option<String>,
        nostr_event_json: Option<String>,
        relay_url: Option<String>,
    },
    GroupInviteReceived {
        room_id: String,
        group_type: String,
        group_name: String,
        inviter_pubkey: String,
    },
    GroupMemberChanged {
        room_id: String,
        kind: GroupChangeKind,
        member_pubkey: Option<String>,
        new_value: Option<String>,
    },
    GroupDissolved {
        room_id: String,
    },
    EventLoopError {
        description: String,
    },
    RelayOk {
        event_id: String,
        relay_url: String,
        success: bool,
        message: String,
    },
}

/// Listener for protocol events (friend requests, messages, groups).
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}

// ─── Record Types (used by all clients) ─────────────────────────

#[derive(Clone, Debug)]
pub struct CreateIdentityResult {
    pub pubkey_hex: String,
    pub mnemonic: String,
}

#[derive(Clone, Debug)]
pub struct ContactInfo {
    pub nostr_pubkey_hex: String,
    pub signal_id_hex: String,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct PendingFriendRequest {
    pub request_id: String,
    pub peer_nostr_pubkey: String,
}

#[derive(Clone, Debug)]
pub struct SentMessage {
    pub event_id: String,
    pub payload_json: Option<String>,
    pub nostr_event_json: Option<String>,
    pub connected_relays: Vec<String>,
    pub new_receiving_addresses: Vec<String>,
    pub dropped_receiving_addresses: Vec<String>,
    pub new_sending_address: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReplyToPayload {
    pub target_event_id: String,
    pub content: Option<String>,
}

#[derive(Clone, Debug)]
pub enum FileCategory {
    Image,
    Video,
    Voice,
    Audio,
    Document,
    Text,
    Archive,
    Other,
}

impl FileCategory {
    /// Convert to libkeychat's FileCategory.
    pub fn to_lib(&self) -> libkeychat::FileCategory {
        match self {
            FileCategory::Image => libkeychat::FileCategory::Image,
            FileCategory::Video => libkeychat::FileCategory::Video,
            FileCategory::Voice => libkeychat::FileCategory::Voice,
            FileCategory::Audio => libkeychat::FileCategory::Audio,
            FileCategory::Document => libkeychat::FileCategory::Document,
            FileCategory::Text => libkeychat::FileCategory::Text,
            FileCategory::Archive => libkeychat::FileCategory::Archive,
            FileCategory::Other => libkeychat::FileCategory::Other,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FilePayload {
    pub category: FileCategory,
    pub url: String,
    pub mime_type: Option<String>,
    pub suffix: Option<String>,
    pub size: u64,
    pub key: String,
    pub iv: String,
    pub hash: String,
    pub source_name: Option<String>,
    pub audio_duration: Option<u32>,
    pub amplitude_samples: Option<Vec<f64>>,
}

#[derive(Clone, Debug)]
pub struct GroupMemberInput {
    pub nostr_pubkey: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct SignalGroupInfo {
    pub group_id: String,
    pub name: String,
    pub member_count: u32,
}

#[derive(Clone, Debug)]
pub struct GroupMemberInfo {
    pub nostr_pubkey: String,
    pub name: String,
    pub is_admin: bool,
    pub is_me: bool,
}

#[derive(Clone, Debug)]
pub struct GroupSentMessage {
    pub msgid: String,
    pub group_id: String,
    pub event_ids: Vec<String>,
    pub payload_json: Option<String>,
    pub nostr_event_json: Option<String>,
    pub relay_status_json: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PublishResultInfo {
    pub event_id: String,
    pub success_relays: Vec<String>,
    pub failed_relays: Vec<FailedRelayInfo>,
}

#[derive(Clone, Debug)]
pub struct FailedRelayInfo {
    pub url: String,
    pub error: String,
}

#[derive(Clone, Debug)]
pub struct RelayStatusInfo {
    pub url: String,
    pub status: String,
}

// ─── MLS Group Types ───────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MlsGroupCreatedInfo {
    pub room_id: String,
    pub group_id: String,
    pub name: String,
    pub member_count: u32,
}

#[derive(Clone, Debug)]
pub struct MlsSentMessage {
    pub msgid: String,
    pub group_id: String,
    pub event_id: Option<String>,
}
