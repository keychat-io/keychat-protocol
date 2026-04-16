//! MLS Group — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::KeychatClient;
use crate::error::KeychatUniError;

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
}
