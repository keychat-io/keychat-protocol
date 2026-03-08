use serde::{Deserialize, Serialize};

use crate::error::Result;

pub const TYPE_DM: i32 = 100;
pub const TYPE_ADD_CONTACT: i32 = 101;
pub const TYPE_DELETE_HISTORY: i32 = 103;
pub const TYPE_REJECT_CONTACT: i32 = 104;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeychatMessage {
    pub c: String,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Keychat app's auto-reply when accepting a friend request.
/// Contains the responder's identity info instead of a standard KeychatMessage.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptContactReply {
    #[serde(rename = "nostrId")]
    pub nostr_id: String,
    #[serde(rename = "signalId")]
    pub signal_id: String,
    pub name: String,
    pub message: String,
    #[serde(default)]
    pub time: u64,
    #[serde(default)]
    pub sig: String,
    #[serde(default)]
    pub lightning: String,
    #[serde(default)]
    pub avatar: String,
}

impl KeychatMessage {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(value: &str) -> Result<Self> {
        Ok(serde_json::from_str(value)?)
    }

    /// Try to parse as KeychatMessage first, then as AcceptContactReply.
    /// Converts AcceptContactReply into a synthetic KeychatMessage for uniform handling.
    pub fn from_json_flexible(value: &str) -> Result<Self> {
        if let Ok(msg) = serde_json::from_str::<KeychatMessage>(value) {
            return Ok(msg);
        }
        if let Ok(accept) = serde_json::from_str::<AcceptContactReply>(value) {
            return Ok(KeychatMessage {
                c: "signal".to_owned(),
                r#type: TYPE_DM,
                msg: accept.message,
                name: Some(accept.name),
            });
        }
        // Fall back: treat as plain text message
        Ok(KeychatMessage {
            c: "signal".to_owned(),
            r#type: TYPE_DM,
            msg: value.to_owned(),
            name: None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QRUserModel {
    pub name: String,
    pub pubkey: String,
    #[serde(rename = "curve25519PkHex")]
    pub curve25519_pk_hex: String,
    pub onetimekey: String,
    #[serde(rename = "signedId")]
    pub signed_id: u32,
    #[serde(rename = "signedPublic")]
    pub signed_public: String,
    #[serde(rename = "signedSignature")]
    pub signed_signature: String,
    #[serde(rename = "prekeyId")]
    pub prekey_id: u32,
    #[serde(rename = "prekeyPubkey")]
    pub prekey_pubkey: String,
    pub time: u64,
    #[serde(rename = "globalSign")]
    pub global_sign: String,
    #[serde(default)]
    pub relay: String,
    #[serde(default)]
    pub lightning: String,
    #[serde(default)]
    pub avatar: String,
}
