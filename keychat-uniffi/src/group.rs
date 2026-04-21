//! Signal Group — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::{convert_file_payload, convert_reply_to, KeychatClient};
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Create a new Signal group.
    pub async fn create_signal_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> Result<SignalGroupInfo, KeychatUniError> {
        let core_members = members
            .into_iter()
            .map(|m| keychat_app_core::GroupMemberInput {
                nostr_pubkey: m.nostr_pubkey,
                name: m.name,
            })
            .collect();
        let result = self.app.create_signal_group(name, core_members).await?;
        Ok(SignalGroupInfo {
            group_id: result.group_id,
            name: result.name,
            member_count: result.member_count,
        })
    }

    /// Get the member list for a Signal group.
    pub async fn get_signal_group_members(
        &self,
        group_id: String,
    ) -> Result<Vec<GroupMemberInfo>, KeychatUniError> {
        let result = self.app.get_signal_group_members(group_id).await?;
        Ok(result
            .into_iter()
            .map(|m| GroupMemberInfo {
                nostr_pubkey: m.nostr_pubkey,
                name: m.name,
                is_admin: m.is_admin,
                is_me: m.is_me,
            })
            .collect())
    }

    /// Send a text message to a Signal group.
    pub async fn send_group_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<GroupSentMessage, KeychatUniError> {
        let core_reply = reply_to.map(|r| keychat_app_core::ReplyToPayload {
            target_event_id: r.target_event_id,
            content: r.content,
        });
        let result = self.app.send_group_text(group_id, text, core_reply).await?;
        Ok(convert_group_sent_message(result))
    }

    /// Send file(s) to a Signal group.
    pub async fn send_group_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<GroupSentMessage, KeychatUniError> {
        let core_files = files.into_iter().map(convert_file_payload).collect();
        let core_reply = reply_to.map(|r| keychat_app_core::ReplyToPayload {
            target_event_id: r.target_event_id,
            content: r.content,
        });
        let result = self
            .app
            .send_group_file(group_id, core_files, message, core_reply)
            .await?;
        Ok(convert_group_sent_message(result))
    }

    /// Send a red packet to a Signal group.
    pub async fn send_group_red_packet(
        &self,
        group_id: String,
        mint: String,
        tokens: Vec<String>,
        total_amount: u64,
        count: u32,
        memo: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<GroupSentMessage, KeychatUniError> {
        let core_reply = reply_to.map(|r| keychat_app_core::ReplyToPayload {
            target_event_id: r.target_event_id,
            content: r.content,
        });
        let result = self
            .app
            .send_group_red_packet(group_id, mint, tokens, total_amount, count, memo, core_reply)
            .await?;
        Ok(convert_group_sent_message(result))
    }

    /// Leave a Signal group. Notifies all members.
    pub async fn leave_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.leave_signal_group(group_id).await?;
        Ok(())
    }

    /// Dissolve a Signal group (admin only). Notifies all members.
    pub async fn dissolve_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.dissolve_signal_group(group_id).await?;
        Ok(())
    }

    /// Remove a member from a Signal group (admin only).
    pub async fn remove_group_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> Result<(), KeychatUniError> {
        self.app
            .remove_group_member(group_id, member_nostr_pubkey)
            .await?;
        Ok(())
    }

    /// Rename a Signal group (admin only).
    pub async fn rename_signal_group(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), KeychatUniError> {
        self.app.rename_signal_group(group_id, new_name).await?;
        Ok(())
    }
}

fn convert_group_sent_message(m: keychat_app_core::GroupSentMessage) -> GroupSentMessage {
    GroupSentMessage {
        msgid: m.msgid,
        group_id: m.group_id,
        event_ids: m.event_ids,
        payload_json: m.payload_json,
        nostr_event_json: m.nostr_event_json,
        relay_status_json: m.relay_status_json,
    }
}
