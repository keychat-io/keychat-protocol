use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageResult {
    pub key_package: String,
    pub mls_protocol_version: String,
    pub ciphersuite: String,
    pub extensions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub ciphertext: Vec<u8>,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedGroupMessage {
    pub plaintext: String,
    pub sender_nostr_id: String,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMembersResult {
    pub commit_message: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMemberResult {
    pub commit_message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitTypeResult {
    Add,
    Update,
    Remove,
    GroupContextExtensions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    pub sender: String,
    pub commit_type: CommitTypeResult,
    pub operated_members: Option<Vec<String>>,
}

/// Unified result from processing any inbound MLS message.
/// Replaces the need to try decrypt then fallback to process_commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessedMlsMessage {
    /// An application message (chat text).
    Application {
        plaintext: String,
        sender_nostr_id: String,
        listen_key: String,
    },
    /// A commit was processed and merged (epoch advanced).
    Commit {
        sender: String,
        commit_type: CommitTypeResult,
        operated_members: Option<Vec<String>>,
        listen_key: String,
    },
}
