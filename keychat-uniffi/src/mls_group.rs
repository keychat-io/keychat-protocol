//! MLS Group — thin UniFFI delegation to keychat-app-core MLS methods.

use crate::client::{convert_file_payload, convert_reply_to, KeychatClient};
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Create a new MLS group with the given members.
    /// `members` contains each member's nostr pubkey and their serialized KeyPackage bytes.
    pub async fn create_mls_group(
        &self,
        name: String,
        members: Vec<MlsKeyPackageInput>,
    ) -> Result<MlsGroupInfo, KeychatUniError> {
        let core_members = members
            .into_iter()
            .map(|m| (m.nostr_pubkey, m.key_package_bytes))
            .collect();
        let result = self.app.create_mls_group(name, core_members).await?;
        Ok(MlsGroupInfo {
            group_id: result.group_id,
            name: result.name,
            member_count: result.member_count,
            mls_temp_inbox: result.mls_temp_inbox,
        })
    }

    /// Join an MLS group via a received Welcome message.
    pub async fn join_mls_group(
        &self,
        welcome_bytes: Vec<u8>,
        name: String,
        admin_pubkeys: Vec<String>,
    ) -> Result<MlsGroupInfo, KeychatUniError> {
        let result = self
            .app
            .join_mls_group(welcome_bytes, name, admin_pubkeys)
            .await?;
        Ok(MlsGroupInfo {
            group_id: result.group_id,
            name: result.name,
            member_count: result.member_count,
            mls_temp_inbox: result.mls_temp_inbox,
        })
    }

    /// Get the member list for an MLS group.
    pub async fn get_mls_group_members(
        &self,
        group_id: String,
    ) -> Result<Vec<MlsGroupMemberInfo>, KeychatUniError> {
        let result = self.app.get_mls_group_members(group_id).await?;
        Ok(result
            .into_iter()
            .map(|m| MlsGroupMemberInfo {
                nostr_pubkey: m.nostr_pubkey,
                is_admin: m.is_admin,
                is_me: m.is_me,
            })
            .collect())
    }

    /// Send a text message to an MLS group.
    pub async fn send_mls_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<MlsGroupSentMessage, KeychatUniError> {
        let core_reply = reply_to.map(convert_reply_to);
        let result = self.app.send_mls_text(group_id, text, core_reply).await?;
        Ok(convert_mls_sent_message(result))
    }

    /// Send file(s) to an MLS group.
    pub async fn send_mls_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<MlsGroupSentMessage, KeychatUniError> {
        let core_files = files.into_iter().map(convert_file_payload).collect();
        let core_reply = reply_to.map(convert_reply_to);
        let result = self
            .app
            .send_mls_file(group_id, core_files, message, core_reply)
            .await?;
        Ok(convert_mls_sent_message(result))
    }

    /// Remove a member from an MLS group (admin only).
    pub async fn remove_mls_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> Result<(), KeychatUniError> {
        self.app
            .remove_mls_member(group_id, member_nostr_pubkey)
            .await?;
        Ok(())
    }

    /// MLS self-update (key rotation). Broadcasts Commit, advances epoch.
    pub async fn mls_self_update(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.mls_self_update(group_id).await?;
        Ok(())
    }

    /// Leave an MLS group.
    pub async fn leave_mls_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.leave_mls_group(group_id).await?;
        Ok(())
    }

    /// Dissolve an MLS group (admin only).
    pub async fn dissolve_mls_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.dissolve_mls_group(group_id).await?;
        Ok(())
    }

    /// Rename an MLS group (admin only).
    pub async fn rename_mls_group(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), KeychatUniError> {
        self.app.rename_mls_group(group_id, new_name).await?;
        Ok(())
    }

    /// Get the current MLS temp inbox address for a group.
    pub async fn get_mls_temp_inbox(&self, group_id: String) -> Result<String, KeychatUniError> {
        let result = self.app.get_mls_temp_inbox(&group_id).await?;
        Ok(result)
    }

    /// List all tracked MLS group IDs.
    pub async fn list_mls_group_ids(&self) -> Result<Vec<String>, KeychatUniError> {
        let result = self.app.list_mls_group_ids().await?;
        Ok(result)
    }

    /// Generate a KeyPackage for this identity (serialized TLS bytes).
    /// Other users need this to invite us to an MLS group.
    pub async fn generate_mls_key_package(&self) -> Result<Vec<u8>, KeychatUniError> {
        let result = self.app.generate_mls_key_package().await?;
        Ok(result)
    }
}

fn convert_mls_sent_message(m: keychat_app_core::MlsGroupSentMessage) -> MlsGroupSentMessage {
    MlsGroupSentMessage {
        msgid: m.msgid,
        group_id: m.group_id,
        event_id: m.event_id,
        payload_json: m.payload_json,
        relay_status_json: m.relay_status_json,
    }
}
