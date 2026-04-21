//! MLS Group — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::{convert_file_payload, convert_reply_to, KeychatClient};
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Generate a fresh MLS KeyPackage and publish it as a kind:10443 Nostr event.
    ///
    /// Must be called after `connect()` so there is an active relay connection.
    /// Other participants will fetch this event when inviting us to MLS groups.
    pub async fn publish_mls_key_package(&self) -> Result<(), KeychatUniError> {
        self.app
            .publish_mls_key_package()
            .await
            .map_err(Into::into)
    }

    /// Create a new MLS group with the given name and invited members.
    ///
    /// Fetches each invitee's KeyPackage (kind:10443), adds them via MLS
    /// add_members, broadcasts the commit, and sends Welcome via Signal DM.
    /// Returns room_id/group_id/name/member_count on success. Members whose
    /// KeyPackage cannot be fetched are marked InviteFailed but the group
    /// is still created.
    pub async fn create_mls_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> Result<MlsGroupCreatedInfo, KeychatUniError> {
        let core_members = members
            .into_iter()
            .map(|m| keychat_app_core::GroupMemberInput {
                nostr_pubkey: m.nostr_pubkey,
                name: m.name,
            })
            .collect();
        let info = self.app.create_mls_group(name, core_members).await?;
        Ok(MlsGroupCreatedInfo {
            room_id: info.room_id,
            group_id: info.group_id,
            name: info.name,
            member_count: info.member_count,
        })
    }

    /// Send a text message to an MLS group.
    pub async fn send_mls_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<MlsSentMessage, KeychatUniError> {
        let core_reply = reply_to.map(convert_reply_to);
        let m = self.app.send_mls_text(group_id, text, core_reply).await?;
        Ok(MlsSentMessage {
            msgid: m.msgid,
            group_id: m.group_id,
            event_id: m.event_id,
        })
    }

    /// Send files (with optional caption) to an MLS group.
    pub async fn send_mls_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<MlsSentMessage, KeychatUniError> {
        let core_files = files.into_iter().map(convert_file_payload).collect();
        let core_reply = reply_to.map(convert_reply_to);
        let m = self
            .app
            .send_mls_file(group_id, core_files, message, core_reply)
            .await?;
        Ok(MlsSentMessage {
            msgid: m.msgid,
            group_id: m.group_id,
            event_id: m.event_id,
        })
    }

    /// Update the display name of an MLS group.
    ///
    /// Produces a GroupContextExtensions commit, broadcasts it to the group's
    /// temp_inbox, updates the local room record, and rotates the inbox mapping
    /// to reflect the new epoch.
    pub async fn update_mls_group_name(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), KeychatUniError> {
        self.app
            .update_mls_group_name(group_id, new_name)
            .await
            .map_err(Into::into)
    }

    /// Leave an MLS group: self-remove via Commit, unsubscribe, archive locally.
    pub async fn leave_mls_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app.leave_mls_group(group_id).await.map_err(Into::into)
    }

    /// Add members to an MLS group. Fetches KeyPackages, adds + commits, sends Welcomes.
    pub async fn add_mls_members(
        &self,
        group_id: String,
        members: Vec<GroupMemberInput>,
    ) -> Result<(), KeychatUniError> {
        let core_members = members
            .into_iter()
            .map(|m| keychat_app_core::GroupMemberInput {
                nostr_pubkey: m.nostr_pubkey,
                name: m.name,
            })
            .collect();
        self.app
            .add_mls_members(group_id, core_members)
            .await
            .map_err(Into::into)
    }

    /// Remove members from an MLS group (admin only) via a remove commit.
    pub async fn remove_mls_members(
        &self,
        group_id: String,
        member_pubkeys: Vec<String>,
    ) -> Result<(), KeychatUniError> {
        self.app
            .remove_mls_members(group_id, member_pubkeys)
            .await
            .map_err(Into::into)
    }

    /// Retry inviting members whose previous invite failed (InviteFailed status).
    ///
    /// Returns the number of members successfully invited on this attempt.
    pub async fn retry_mls_invite(
        &self,
        group_id: String,
        member_pubkeys: Vec<String>,
    ) -> Result<u32, KeychatUniError> {
        self.app
            .retry_mls_invite(group_id, member_pubkeys)
            .await
            .map(|n| n as u32)
            .map_err(Into::into)
    }

    /// Rotate our own leaf-node keys in the given MLS group (forward secrecy).
    ///
    /// Produces a self_update Commit, broadcasts it to the group's temp_inbox,
    /// and rotates the inbox subscription to reflect the new epoch.
    ///
    /// Call this periodically (e.g., once a day) for each group the user is in.
    pub async fn mls_self_update(&self, group_id: String) -> Result<(), KeychatUniError> {
        self.app
            .mls_self_update(group_id)
            .await
            .map_err(Into::into)
    }

    /// Rotate leaf-node keys for every active MLS group in a single call.
    ///
    /// Calls `mls_self_update` for each group the client knows about.
    /// Failures for individual groups are logged but do not stop processing.
    ///
    /// Returns the number of groups successfully updated.
    pub async fn mls_self_update_all_groups(&self) -> Result<u32, KeychatUniError> {
        self.app
            .mls_self_update_all_groups()
            .await
            .map(|n| n as u32)
            .map_err(Into::into)
    }

    /// Restore the mls_inbox_map from all active MLS groups and subscribe to
    /// each group's temp_inbox. Call once per session after `connect()`.
    ///
    /// Returns the list of temp_inbox hex pubkeys that were registered.
    pub async fn restore_mls_inbox_map(&self) -> Result<Vec<String>, KeychatUniError> {
        self.app.restore_mls_inbox_map().await.map_err(Into::into)
    }
}
