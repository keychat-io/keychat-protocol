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

#[derive(uniffi::Enum)]
pub enum ClientEvent {
    FriendRequestReceived {
        request_id: String,
        sender_pubkey: String,
        sender_name: String,
        message: Option<String>,
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
        kind: String,
        content: Option<String>,
        payload: Option<String>,
        event_id: String,
        fallback: Option<String>,
        reply_to_event_id: Option<String>,
        group_id: Option<String>,
        thread_id: Option<String>,
    },
    GroupInviteReceived {
        room_id: String,
        group_type: String,
        group_name: String,
        inviter_pubkey: String,
    },
    GroupMemberChanged {
        room_id: String,
        kind: String,
        member_pubkey: Option<String>,
        new_value: Option<String>,
    },
    GroupDissolved {
        room_id: String,
    },
    EventLoopError {
        description: String,
    },
}

// ─── Callback Interface ──────────────────────────────────────────

#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}
