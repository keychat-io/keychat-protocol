//! KCMessage v2 envelope and payload types.
//!
//! Implements the message format from the Keychat Protocol v2 spec (§4).
//! All structured messages use the KCMessage v2 envelope. The `kind` field
//! routes message types, and each kind has a corresponding typed payload field.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

// ─── KCMessageKind ───────────────────────────────────────────────────────────

/// All known KCMessage kinds, with an `Unknown(String)` variant for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KCMessageKind {
    // Core
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
    // MLS
    MlsGroupInvite,
    MlsGroupMemberAdded,
    MlsGroupMemberRemoved,
    MlsGroupSelfLeave,
    MlsGroupDissolve,
    MlsGroupNameChanged,
    MlsGroupKeyRotation,
    // Agent interactive
    AgentActions,
    AgentOptions,
    AgentConfirm,
    AgentReply,
    // Agent protocol
    TaskRequest,
    TaskResponse,
    SkillQuery,
    SkillDeclare,
    EventNotify,
    StreamChunk,
    // Additional
    Reaction,
    MessageDelete,
    MessageEdit,
    ReadReceipt,
    Typing,
    Location,
    Contact,
    Sticker,
    Poll,
    PollVote,
    CallSignal,
    GroupPinMessage,
    GroupAnnouncement,
    RedPacket,
    /// Forward-compatible catch-all for unknown kinds.
    Unknown(String),
}

impl KCMessageKind {
    /// Convert the kind to its canonical JSON string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Files => "files",
            Self::Cashu => "cashu",
            Self::LightningInvoice => "lightningInvoice",
            Self::FriendRequest => "friendRequest",
            Self::FriendApprove => "friendApprove",
            Self::FriendReject => "friendReject",
            Self::ProfileSync => "profileSync",
            Self::RelaySyncInvite => "relaySyncInvite",
            Self::SignalGroupInvite => "signalGroupInvite",
            Self::SignalGroupMemberRemoved => "signalGroupMemberRemoved",
            Self::SignalGroupSelfLeave => "signalGroupSelfLeave",
            Self::SignalGroupDissolve => "signalGroupDissolve",
            Self::SignalGroupNameChanged => "signalGroupNameChanged",
            Self::SignalGroupNicknameChanged => "signalGroupNicknameChanged",
            Self::MlsGroupInvite => "mlsGroupInvite",
            Self::MlsGroupMemberAdded => "mlsGroupMemberAdded",
            Self::MlsGroupMemberRemoved => "mlsGroupMemberRemoved",
            Self::MlsGroupSelfLeave => "mlsGroupSelfLeave",
            Self::MlsGroupDissolve => "mlsGroupDissolve",
            Self::MlsGroupNameChanged => "mlsGroupNameChanged",
            Self::MlsGroupKeyRotation => "mlsGroupKeyRotation",
            Self::AgentActions => "agentActions",
            Self::AgentOptions => "agentOptions",
            Self::AgentConfirm => "agentConfirm",
            Self::AgentReply => "agentReply",
            Self::TaskRequest => "taskRequest",
            Self::TaskResponse => "taskResponse",
            Self::SkillQuery => "skillQuery",
            Self::SkillDeclare => "skillDeclare",
            Self::EventNotify => "eventNotify",
            Self::StreamChunk => "streamChunk",
            Self::Reaction => "reaction",
            Self::MessageDelete => "messageDelete",
            Self::MessageEdit => "messageEdit",
            Self::ReadReceipt => "readReceipt",
            Self::Typing => "typing",
            Self::Location => "location",
            Self::Contact => "contact",
            Self::Sticker => "sticker",
            Self::Poll => "poll",
            Self::PollVote => "pollVote",
            Self::CallSignal => "callSignal",
            Self::GroupPinMessage => "groupPinMessage",
            Self::GroupAnnouncement => "groupAnnouncement",
            Self::RedPacket => "redPacket",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Parse a string into a KCMessageKind. Unknown strings become `Unknown(s)`.
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "text" => Self::Text,
            "files" => Self::Files,
            "cashu" => Self::Cashu,
            "lightningInvoice" => Self::LightningInvoice,
            "friendRequest" => Self::FriendRequest,
            "friendApprove" => Self::FriendApprove,
            "friendReject" => Self::FriendReject,
            "profileSync" => Self::ProfileSync,
            "relaySyncInvite" => Self::RelaySyncInvite,
            "signalGroupInvite" => Self::SignalGroupInvite,
            "signalGroupMemberRemoved" => Self::SignalGroupMemberRemoved,
            "signalGroupSelfLeave" => Self::SignalGroupSelfLeave,
            "signalGroupDissolve" => Self::SignalGroupDissolve,
            "signalGroupNameChanged" => Self::SignalGroupNameChanged,
            "signalGroupNicknameChanged" => Self::SignalGroupNicknameChanged,
            "mlsGroupInvite" => Self::MlsGroupInvite,
            "mlsGroupMemberAdded" => Self::MlsGroupMemberAdded,
            "mlsGroupMemberRemoved" => Self::MlsGroupMemberRemoved,
            "mlsGroupSelfLeave" => Self::MlsGroupSelfLeave,
            "mlsGroupDissolve" => Self::MlsGroupDissolve,
            "mlsGroupNameChanged" => Self::MlsGroupNameChanged,
            "mlsGroupKeyRotation" => Self::MlsGroupKeyRotation,
            "agentActions" => Self::AgentActions,
            "agentOptions" => Self::AgentOptions,
            "agentConfirm" => Self::AgentConfirm,
            "agentReply" => Self::AgentReply,
            "taskRequest" => Self::TaskRequest,
            "taskResponse" => Self::TaskResponse,
            "skillQuery" => Self::SkillQuery,
            "skillDeclare" => Self::SkillDeclare,
            "eventNotify" => Self::EventNotify,
            "streamChunk" => Self::StreamChunk,
            "reaction" => Self::Reaction,
            "messageDelete" => Self::MessageDelete,
            "messageEdit" => Self::MessageEdit,
            "readReceipt" => Self::ReadReceipt,
            "typing" => Self::Typing,
            "location" => Self::Location,
            "contact" => Self::Contact,
            "sticker" => Self::Sticker,
            "poll" => Self::Poll,
            "pollVote" => Self::PollVote,
            "callSignal" => Self::CallSignal,
            "groupPinMessage" => Self::GroupPinMessage,
            "groupAnnouncement" => Self::GroupAnnouncement,
            "redPacket" => Self::RedPacket,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl Serialize for KCMessageKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KCMessageKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str_lossy(&s))
    }
}

// ─── Payload types ───────────────────────────────────────────────────────────

/// Text message payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KCTextPayload {
    pub content: String,
    /// `"plain"` (default) or `"markdown"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// File category enum (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
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

/// A single file entry within a files payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCFilePayload {
    pub category: FileCategory,
    pub url: String,
    /// MIME type (e.g. `"image/jpeg"`).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// AES-256 key (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// IV (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    /// SHA-256 hash of encrypted file (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Duration in seconds (voice/audio).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_duration: Option<f64>,
    /// Waveform amplitude samples.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amplitude_samples: Option<Vec<f64>>,
    /// Ecash token for paid downloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecash_token: Option<String>,
}

/// Files payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KCFilesPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub items: Vec<KCFilePayload>,
}

/// Friend request payload — PQXDH prekey bundle (§4.5, §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCFriendRequestPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub name: String,
    pub nostr_identity_key: String,
    pub signal_identity_key: String,
    pub first_inbox: String,
    pub device_id: String,
    pub signal_signed_prekey_id: u32,
    pub signal_signed_prekey: String,
    pub signal_signed_prekey_signature: String,
    pub signal_one_time_prekey_id: u32,
    pub signal_one_time_prekey: String,
    pub signal_kyber_prekey_id: u32,
    pub signal_kyber_prekey: String,
    pub signal_kyber_prekey_signature: String,
    pub global_sign: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning: Option<String>,
}

/// Friend approve payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCFriendApprovePayload {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// If `true`, the approver is a public agent and requests dual p-tag routing (§3.6).
    /// The sender should include both the ratchet-derived address and the agent's npub
    /// in subsequent Mode 1 events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_agent: Option<bool>,
}

/// Friend reject payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCFriendRejectPayload {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Cashu ecash transfer payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KCCashuPayload {
    pub mint: String,
    pub token: String,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Lightning invoice payload (§4.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KCLightningPayload {
    pub invoice: String,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Red packet payload (group-chat multi-token). Uses Cashu mint's double-spend
/// protection for "first-come-first-served" semantics — no protocol arbitration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCRedPacketPayload {
    pub mint: String,
    /// N independent Cashu tokens, one per share.
    pub tokens: Vec<String>,
    /// Total amount across all shares (sats).
    pub total_amount: u64,
    /// Number of shares.
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

// ─── Envelope metadata types ─────────────────────────────────────────────────

/// Reply reference (§4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReplyTo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_id: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

/// Identity binding on first PrekeyMessage (§4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignalPrekeyAuth {
    pub nostr_id: String,
    pub signal_id: String,
    pub time: u64,
    pub name: String,
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning: Option<String>,
}

/// Forwarded message metadata (§4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForwardFrom {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<u64>,
}

// ─── KCMessage envelope ─────────────────────────────────────────────────────

/// The KCMessage v2 envelope — the top-level message container.
///
/// Each message has a `kind` that determines which payload field is populated.
/// Unknown kinds and extra fields are preserved in `extra` for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KCMessage {
    /// Protocol version — always `2`.
    pub v: u32,

    /// Message UUID v4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Message type identifier.
    pub kind: KCMessageKind,

    // ── Typed payload fields ──
    // The active one corresponds to `kind`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<KCTextPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<KCFilesPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cashu: Option<KCCashuPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning: Option<KCLightningPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub red_packet: Option<KCRedPacketPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub friend_request: Option<KCFriendRequestPayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub friend_approve: Option<KCFriendApprovePayload>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub friend_reject: Option<KCFriendRejectPayload>,

    // ── Envelope metadata ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<ReplyTo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_prekey_auth: Option<SignalPrekeyAuth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_from: Option<ForwardFrom>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub burn_after_reading: Option<bool>,

    /// Extra/unknown fields for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl KCMessage {
    /// Create a new text message.
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            v: 2,
            id: Some(uuid_v4()),
            kind: KCMessageKind::Text,
            text: Some(KCTextPayload {
                content: content.into(),
                format: None,
            }),
            ..Self::empty()
        }
    }

    /// Create a new friend request message.
    pub fn friend_request(id: String, payload: KCFriendRequestPayload) -> Self {
        Self {
            v: 2,
            id: Some(id),
            kind: KCMessageKind::FriendRequest,
            friend_request: Some(payload),
            ..Self::empty()
        }
    }

    /// Create a new friend approve message.
    pub fn friend_approve(request_id: String, message: Option<String>) -> Self {
        Self {
            v: 2,
            id: Some(uuid_v4()),
            kind: KCMessageKind::FriendApprove,
            friend_approve: Some(KCFriendApprovePayload {
                request_id,
                message,
                public_agent: None,
            }),
            ..Self::empty()
        }
    }

    /// Create a friend approve message for a public agent (§3.6).
    /// Sets `publicAgent: true` to signal dual p-tag routing.
    pub fn friend_approve_public_agent(request_id: String, message: Option<String>) -> Self {
        Self {
            v: 2,
            id: Some(uuid_v4()),
            kind: KCMessageKind::FriendApprove,
            friend_approve: Some(KCFriendApprovePayload {
                request_id,
                message,
                public_agent: Some(true),
            }),
            ..Self::empty()
        }
    }

    /// Create a new friend reject message.
    pub fn friend_reject(request_id: String, message: Option<String>) -> Self {
        Self {
            v: 2,
            id: Some(uuid_v4()),
            kind: KCMessageKind::FriendReject,
            friend_reject: Some(KCFriendRejectPayload {
                request_id,
                message,
            }),
            ..Self::empty()
        }
    }

    /// Try to parse a JSON string as a KCMessage v2.
    /// Returns `None` if parsing fails or `v != 2`.
    pub fn try_parse(s: &str) -> Option<Self> {
        let msg: Self = serde_json::from_str(s).ok()?;
        if msg.v == 2 {
            Some(msg)
        } else {
            None
        }
    }

    /// Try to parse as v2; if that fails, fall back to a minimal v1
    /// KeychatMessage parser so we can inter-operate with legacy Flutter
    /// peers that emit `{"c":"signal","type":<n>,"msg":..,"name":..,"data":..}`
    /// after Signal-decrypting a DM or friend-approve.
    ///
    /// Only the v1 message types needed for 1:1 compat are recognised (DM,
    /// FriendApprove, FriendReject). Unknown v1 types return `None` so the
    /// caller can route them through app-core's richer `v1_to_v2`.
    pub fn try_parse_any(s: &str) -> Option<Self> {
        if let Some(v2) = Self::try_parse(s) {
            return Some(v2);
        }
        let v: serde_json::Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => return Some(Self::text(s.to_string())),
        };
        let msg_type = match v.get("type").and_then(|t| t.as_u64()) {
            Some(n) => n as u32,
            None => return Some(Self::text(s.to_string())),
        };
        match msg_type {
            // v1 DM
            100 => {
                let text = v.get("msg").and_then(|m| m.as_str()).unwrap_or("");
                Some(Self::text(text.to_string()))
            }
            // v1 ADD_CONTACT_FROM_ALICE (friend request). `name` carries the
            // QRUserModel as a serialized JSON string with camelCase fields.
            101 => {
                let name_field = v.get("name").and_then(|n| n.as_str())?;
                let qr: serde_json::Value = serde_json::from_str(name_field).ok()?;
                let greeting = v
                    .get("msg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                let payload = KCFriendRequestPayload {
                    message: if greeting.is_empty() {
                        None
                    } else {
                        Some(greeting)
                    },
                    name: qr
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    nostr_identity_key: qr
                        .get("pubkey")
                        .and_then(|x| x.as_str())?
                        .to_string(),
                    signal_identity_key: qr
                        .get("curve25519PkHex")
                        .and_then(|x| x.as_str())?
                        .to_string(),
                    first_inbox: qr
                        .get("onetimekey")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    device_id: "1".to_string(),
                    signal_signed_prekey_id: qr
                        .get("signedId")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0) as u32,
                    signal_signed_prekey: qr
                        .get("signedPublic")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    signal_signed_prekey_signature: qr
                        .get("signedSignature")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    signal_one_time_prekey_id: qr
                        .get("prekeyId")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0) as u32,
                    signal_one_time_prekey: qr
                        .get("prekeyPubkey")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    signal_kyber_prekey_id: 0,
                    signal_kyber_prekey: String::new(),
                    signal_kyber_prekey_signature: String::new(),
                    global_sign: qr
                        .get("globalSign")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    time: qr.get("time").and_then(|x| x.as_u64()),
                    version: 1,
                    relay: qr
                        .get("relay")
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    avatar: qr
                        .get("avatar")
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    lightning: qr
                        .get("lightning")
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                };
                let mut msg = Self::empty();
                msg.v = 2;
                msg.kind = KCMessageKind::FriendRequest;
                msg.friend_request = Some(payload);
                Some(msg)
            }
            // v1 ADD_CONTACT_FROM_BOB (friend approve). `data` carries the v2
            // SignalPrekeyAuth as a serialized JSON string so we can preserve
            // identity-binding context across the v1 wire format.
            102 => {
                let mut msg = Self::friend_approve(String::new(), None);
                if let Some(data_str) = v.get("data").and_then(|d| d.as_str()) {
                    if let Ok(auth) =
                        serde_json::from_str::<crate::message::SignalPrekeyAuth>(data_str)
                    {
                        msg.signal_prekey_auth = Some(auth);
                    }
                }
                Some(msg)
            }
            // v1 REJECT (friend reject)
            104 => Some(Self::friend_reject(String::new(), None)),
            _ => Some(Self::text(s.to_string())),
        }
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string(self).map_err(crate::KeychatError::from)
    }

    /// An empty message shell (all optional fields None).
    /// Note: `kind` defaults to `Text` as a placeholder — callers should set the
    /// actual kind before use.
    pub fn empty() -> Self {
        Self {
            v: 2,
            id: None,
            kind: KCMessageKind::Text,
            text: None,
            files: None,
            cashu: None,
            lightning: None,
            red_packet: None,
            friend_request: None,
            friend_approve: None,
            friend_reject: None,
            group_id: None,
            reply_to: None,
            signal_prekey_auth: None,
            fallback: None,
            thread_id: None,
            forward_from: None,
            burn_after_reading: None,
            extra: HashMap::new(),
        }
    }
}

/// Generate a UUID v4 string.
pub(crate) fn uuid_v4() -> String {
    use ::rand::Rng;
    let mut rng = ::rand::rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        // Last 6 bytes as a single u64 (only lower 48 bits used)
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_message_roundtrip() {
        let msg = KCMessage::text("Hello, world!");
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.v, 2);
        assert_eq!(parsed.kind, KCMessageKind::Text);
        assert_eq!(parsed.text.as_ref().unwrap().content, "Hello, world!");
    }

    #[test]
    fn kind_serializes_as_string() {
        let msg = KCMessage::text("test");
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""kind":"text""#));

        // friendRequest
        let msg2 = KCMessage {
            kind: KCMessageKind::FriendRequest,
            ..KCMessage::empty()
        };
        let json2 = msg2.to_json().unwrap();
        assert!(json2.contains(r#""kind":"friendRequest""#));
    }

    #[test]
    fn camel_case_json_keys() {
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::FriendRequest,
            friend_request: Some(KCFriendRequestPayload {
                message: None,
                name: "Alice".into(),
                nostr_identity_key: "abc123".into(),
                signal_identity_key: "05def456".into(),
                first_inbox: "ephemeral".into(),
                device_id: "dev-1".into(),
                signal_signed_prekey_id: 1,
                signal_signed_prekey: "aaa".into(),
                signal_signed_prekey_signature: "bbb".into(),
                signal_one_time_prekey_id: 1,
                signal_one_time_prekey: "ccc".into(),
                signal_kyber_prekey_id: 1,
                signal_kyber_prekey: "ddd".into(),
                signal_kyber_prekey_signature: "eee".into(),
                global_sign: "fff".into(),
                time: Some(1700000000),
                version: 2,
                relay: None,
                avatar: None,
                lightning: None,
            }),
            ..KCMessage::empty()
        };
        let json = msg.to_json().unwrap();
        // Verify camelCase field names
        assert!(json.contains("nostrIdentityKey"));
        assert!(json.contains("signalIdentityKey"));
        assert!(json.contains("firstInbox"));
        assert!(json.contains("signalSignedPrekeyId"));
        assert!(json.contains("signalSignedPrekey\":"));
        assert!(json.contains("signalSignedPrekeySignature"));
        assert!(json.contains("signalOneTimePrekeyId"));
        assert!(json.contains("signalOneTimePrekey\":"));
        assert!(json.contains("signalKyberPrekeyId"));
        assert!(json.contains("signalKyberPrekey\":"));
        assert!(json.contains("signalKyberPrekeySignature"));
        assert!(json.contains("globalSign"));
        assert!(json.contains("friendRequest"));
        // Verify it does NOT contain snake_case
        assert!(!json.contains("nostr_identity_key"));
        assert!(!json.contains("signal_identity_key"));
        assert!(!json.contains("friend_request"));
    }

    #[test]
    fn unknown_kind_forward_compat() {
        let json = r#"{
            "v": 2,
            "kind": "futureKind",
            "futureKind": {"data": 42},
            "fallback": "You need a newer Keychat version"
        }"#;
        let msg = KCMessage::try_parse(json).unwrap();
        assert_eq!(msg.kind, KCMessageKind::Unknown("futureKind".into()));
        assert_eq!(
            msg.fallback.as_deref(),
            Some("You need a newer Keychat version")
        );
        // The unknown payload is preserved in extra
        assert!(msg.extra.contains_key("futureKind"));
    }

    #[test]
    fn version_1_returns_none() {
        let json = r#"{"v": 1, "kind": "text"}"#;
        assert!(KCMessage::try_parse(json).is_none());
    }

    #[test]
    fn invalid_json_returns_none() {
        assert!(KCMessage::try_parse("not json at all").is_none());
    }

    #[test]
    fn friend_approve_roundtrip() {
        let msg = KCMessage::friend_approve("fr-uuid-001".into(), Some("Nice to meet you!".into()));
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::FriendApprove);
        let payload = parsed.friend_approve.unwrap();
        assert_eq!(payload.request_id, "fr-uuid-001");
        assert_eq!(payload.message.as_deref(), Some("Nice to meet you!"));
    }

    #[test]
    fn friend_reject_roundtrip() {
        let msg = KCMessage::friend_reject("fr-uuid-002".into(), None);
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::FriendReject);
        let payload = parsed.friend_reject.unwrap();
        assert_eq!(payload.request_id, "fr-uuid-002");
        assert!(payload.message.is_none());
    }

    #[test]
    fn files_message_roundtrip() {
        let msg = KCMessage {
            v: 2,
            id: Some("file-msg-1".into()),
            kind: KCMessageKind::Files,
            files: Some(KCFilesPayload {
                message: Some("Today's photos".into()),
                items: vec![KCFilePayload {
                    category: FileCategory::Image,
                    url: "https://example.com/encrypted/abc123".into(),
                    type_: Some("image/jpeg".into()),
                    suffix: Some("jpg".into()),
                    size: Some(245760),
                    key: Some("aes-key-hex".into()),
                    iv: Some("iv-hex".into()),
                    hash: Some("sha256-hex".into()),
                    source_name: None,
                    audio_duration: None,
                    amplitude_samples: None,
                    ecash_token: None,
                }],
            }),
            ..KCMessage::empty()
        };
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::Files);
        let files = parsed.files.unwrap();
        assert_eq!(files.items.len(), 1);
        assert_eq!(files.items[0].category, FileCategory::Image);
    }

    #[test]
    fn cashu_message_roundtrip() {
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::Cashu,
            cashu: Some(KCCashuPayload {
                mint: "https://mint.example.com".into(),
                token: "cashuAabc123".into(),
                amount: 100,
                unit: Some("sat".into()),
                memo: None,
                message: Some("Coffee money".into()),
            }),
            ..KCMessage::empty()
        };
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::Cashu);
        let cashu = parsed.cashu.unwrap();
        assert_eq!(cashu.amount, 100);
    }

    #[test]
    fn lightning_message_roundtrip() {
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::LightningInvoice,
            lightning: Some(KCLightningPayload {
                invoice: "lnbc1...".into(),
                amount: 1000,
                mint: None,
                hash: None,
                message: None,
            }),
            ..KCMessage::empty()
        };
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.kind, KCMessageKind::LightningInvoice);
    }

    #[test]
    fn envelope_metadata_roundtrip() {
        let msg = KCMessage {
            v: 2,
            id: Some("msg-1".into()),
            kind: KCMessageKind::Text,
            text: Some(KCTextPayload {
                content: "Reply!".into(),
                format: Some("markdown".into()),
            }),
            group_id: Some("group-pub-key".into()),
            reply_to: Some(ReplyTo {
                target_id: Some("original-id".into()),
                target_event_id: None,
                content: "Original text".into(),
                user_id: Some("user-pub".into()),
                user_name: Some("Alice".into()),
            }),
            signal_prekey_auth: Some(SignalPrekeyAuth {
                nostr_id: "nostr-pub".into(),
                signal_id: "signal-pub".into(),
                time: 1700000000,
                name: "Bob".into(),
                sig: "schnorr-sig".into(),
                avatar: None,
                lightning: None,
            }),
            fallback: Some("Reply!".into()),
            thread_id: Some("thread-root".into()),
            forward_from: Some(ForwardFrom {
                sender_name: Some("Charlie".into()),
                sender_id: None,
                original_time: Some(1699999000),
            }),
            burn_after_reading: Some(true),
            ..KCMessage::empty()
        };
        let json = msg.to_json().unwrap();
        let parsed = KCMessage::try_parse(&json).unwrap();
        assert_eq!(parsed.group_id.as_deref(), Some("group-pub-key"));
        assert!(parsed.reply_to.is_some());
        assert!(parsed.signal_prekey_auth.is_some());
        assert_eq!(parsed.thread_id.as_deref(), Some("thread-root"));
        assert!(parsed.forward_from.is_some());
        assert_eq!(parsed.burn_after_reading, Some(true));

        // Verify camelCase for metadata fields
        assert!(json.contains("groupId"));
        assert!(json.contains("replyTo"));
        assert!(json.contains("signalPrekeyAuth"));
        assert!(json.contains("threadId"));
        assert!(json.contains("forwardFrom"));
        assert!(json.contains("burnAfterReading"));
    }

    #[test]
    fn v_always_2_on_serialize() {
        let mut msg = KCMessage::text("test");
        msg.v = 99; // force wrong version
        let json = msg.to_json().unwrap();
        // Even though v was set to 99, it serializes as-is (struct is data, not enforced)
        // But try_parse will reject it
        assert!(json.contains(r#""v":99"#));
        assert!(KCMessage::try_parse(&json).is_none());
    }

    #[test]
    fn all_known_kinds_roundtrip() {
        let kinds = vec![
            KCMessageKind::Text,
            KCMessageKind::Files,
            KCMessageKind::Cashu,
            KCMessageKind::LightningInvoice,
            KCMessageKind::FriendRequest,
            KCMessageKind::FriendApprove,
            KCMessageKind::FriendReject,
            KCMessageKind::Reaction,
            KCMessageKind::MessageDelete,
            KCMessageKind::MessageEdit,
            KCMessageKind::SignalGroupInvite,
            KCMessageKind::MlsGroupInvite,
            KCMessageKind::AgentActions,
            KCMessageKind::TaskRequest,
            KCMessageKind::Typing,
        ];
        for kind in kinds {
            let s = serde_json::to_string(&kind).unwrap();
            let parsed: KCMessageKind = serde_json::from_str(&s).unwrap();
            assert_eq!(kind, parsed);
        }
    }
}
