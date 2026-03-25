// ─── Records ─────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct CreateIdentityResult {
    pub pubkey_hex: String,
    pub mnemonic: String,
}

#[derive(uniffi::Record)]
pub struct ContactInfo {
    pub nostr_pubkey_hex: String,
    pub signal_id_hex: String,
    pub display_name: String,
}

#[derive(uniffi::Record)]
pub struct PendingFriendRequest {
    pub request_id: String,
    pub peer_nostr_pubkey: String,
}

#[derive(uniffi::Record)]
pub struct ReceivedFriendRequest {
    pub request_id: String,
    pub sender_pubkey_hex: String,
    pub sender_name: String,
    pub sender_device_id: String,
    pub message: Option<String>,
}

#[derive(uniffi::Record)]
pub struct SentMessage {
    pub event_id: String,
    pub payload_json: Option<String>,
    pub nostr_event_json: Option<String>,
    /// Relays that were connected at send time. Swift uses this for timeout tracking.
    /// Per-relay OK results come async via ClientEvent::RelayOk.
    pub connected_relays: Vec<String>,
    pub new_receiving_addresses: Vec<String>,
    pub dropped_receiving_addresses: Vec<String>,
    pub new_sending_address: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ReplyToPayload {
    pub target_event_id: String,
    pub content: Option<String>,
}

#[derive(uniffi::Record)]
pub struct LocalFile {
    pub path: String,
    pub category: FileCategory,
    pub mime_type: Option<String>,
    pub source_name: Option<String>,
    pub audio_duration: Option<u32>,
    pub amplitude_samples: Option<Vec<f64>>,
}

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
pub struct ProfilePayload {
    pub name: String,
    pub pubkey: String,
    pub version: i64,
    pub avatar: Option<String>,
    pub lightning: Option<String>,
    pub bio: Option<String>,
}

// ─── Signal Group Records ────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct GroupMemberInput {
    pub nostr_pubkey: String,
    pub name: String,
}

#[derive(uniffi::Record)]
pub struct SignalGroupInfo {
    pub group_id: String,
    pub name: String,
    pub member_count: u32,
}

#[derive(uniffi::Record)]
pub struct GroupSentMessage {
    pub group_id: String,
    pub event_ids: Vec<String>,
}

// ─── Enums ───────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
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

#[derive(uniffi::Enum)]
pub enum MessageKind {
    // Common
    Text,
    Files,
    Cashu,
    LightningInvoice,
    // Signal 1:1
    FriendRequest,
    FriendApprove,
    FriendReject,
    ProfileSync,
    RelaySyncInvite,
    // Signal Group
    SignalGroupInvite,
    SignalGroupMemberRemoved,
    SignalGroupSelfLeave,
    SignalGroupDissolve,
    SignalGroupNameChanged,
    SignalGroupNicknameChanged,
    // MLS Group
    MlsGroupInvite,
    // Agent (future)
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
    // Extended (future)
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
            _ => MessageKind::Text, // Unknown kinds fallback to Text
        }
    }
}

#[derive(uniffi::Enum)]
pub enum GroupChangeKind {
    MemberRemoved,
    SelfLeave,
    NameChanged,
}

#[derive(uniffi::Enum)]
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
    /// Per-relay OK response for a sent event (NIP-01).
    /// Emitted by event loop when relay responds to our EVENT message.
    RelayOk {
        event_id: String,
        relay_url: String,
        success: bool,
        message: String,
    },
}

#[derive(uniffi::Record)]
pub struct PublishResultInfo {
    pub event_id: String,
    pub success_relays: Vec<String>,
    pub failed_relays: Vec<FailedRelayInfo>,
}

#[derive(uniffi::Record)]
pub struct FailedRelayInfo {
    pub url: String,
    pub error: String,
}

#[derive(uniffi::Record)]
pub struct RelayStatusInfo {
    pub url: String,
    pub status: String,
}

// ─── Callback Interface ──────────────────────────────────────────

#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}
